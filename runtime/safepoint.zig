const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("runtime");

// OS Constants for Windows
const PAGE_READONLY = 0x02;
const PAGE_NOACCESS = 0x01;
const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
const EXCEPTION_CONTINUE_SEARCH = 0;
const EXCEPTION_CONTINUE_EXECUTION = -1;

extern "kernel32" fn VirtualAlloc(lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(.c) ?*anyopaque;
extern "kernel32" fn VirtualProtect(lpAddress: *anyopaque, dwSize: usize, flNewProtect: u32, lpflOldProtect: *u32) callconv(.c) i32;
extern "kernel32" fn AddVectoredExceptionHandler(First: u32, Handler: *const fn (*anyopaque) callconv(.c) i32) callconv(.c) ?*anyopaque;

// ── Global safepoint page ──────────────────────────────────────────────────
// Mutator threads perform a dummy read from this page.
pub var safepoint_page: *volatile u8 = undefined;
var veh_handle: ?*anyopaque = null;

// ── Thread parking state ───────────────────────────────────────────────────
var parked_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
pub var expected_count: u32 = 0;
var safepoint_active: bool = false;

var gc_wait_lock: std.Io.Mutex = .init;
var gc_wait_cond: std.Io.Condition = .init;
var gc_coordinator_cond: std.Io.Condition = .init;

/// Called exactly once during VM startup.
pub fn initSafepointSubsystem() void {
    if (builtin.os.tag == .windows) {
        const ptr = VirtualAlloc(null, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
        if (ptr == null) @panic("Failed to allocate safepoint page");
        safepoint_page = @as(*volatile u8, @ptrCast(ptr));

        veh_handle = AddVectoredExceptionHandler(1, vehHandler);
        if (veh_handle == null) @panic("Failed to install safepoint exception handler");
    } else {
        @panic("Asymmetric Dekker Safepoints only implemented for Windows so far");
    }
}

/// Register the total number of mutator threads the GC will wait for.
pub fn setThreadCount(n: u32) void {
    expected_count = n;
    parked_count.store(0, .release);
}

/// Called by GC coordinator to initiate Stop-The-World.
pub fn requestSafepoint() void {
    gc_wait_lock.lockUncancelable(runtime.global_io);
    safepoint_active = true;
    gc_wait_lock.unlock(runtime.global_io);

    if (builtin.os.tag == .windows) {
        var old_protect: u32 = 0;
        const res = VirtualProtect(safepoint_page, 4096, PAGE_NOACCESS, &old_protect);
        if (res == 0) @panic("Failed to protect safepoint page");
    }

    // Wait for all mutator threads to trap and park
    gc_wait_lock.lockUncancelable(runtime.global_io);
    defer gc_wait_lock.unlock(runtime.global_io);
    while (parked_count.load(.acquire) < expected_count) {
        gc_coordinator_cond.waitUncancelable(runtime.global_io, &gc_wait_lock);
    }
}

/// Called by GC coordinator after STW is complete.
pub fn releaseSafepoint() void {
    if (builtin.os.tag == .windows) {
        var old_protect: u32 = 0;
        const res = VirtualProtect(safepoint_page, 4096, PAGE_READONLY, &old_protect);
        if (res == 0) @panic("Failed to unprotect safepoint page");
    }
    
    gc_wait_lock.lockUncancelable(runtime.global_io);
    safepoint_active = false;
    gc_wait_lock.unlock(runtime.global_io);
    
    // Wake up all parked threads so they retry the instruction
    gc_wait_cond.broadcast(runtime.global_io);
}

// Exception Pointers mapping for Windows x64
const EXCEPTION_RECORD = extern struct {
    ExceptionCode: u32,
    ExceptionFlags: u32,
    ExceptionRecord: ?*EXCEPTION_RECORD,
    ExceptionAddress: ?*anyopaque,
    NumberParameters: u32,
    ExceptionInformation: [15]usize,
};

const EXCEPTION_POINTERS = extern struct {
    ExceptionRecord: *EXCEPTION_RECORD,
    ContextRecord: *anyopaque,
};

fn vehHandler(ExceptionInfo: *anyopaque) callconv(.c) i32 {
    const ep = @as(*EXCEPTION_POINTERS, @ptrCast(@alignCast(ExceptionInfo)));
    const er = ep.ExceptionRecord;

    if (er.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        if (er.NumberParameters >= 2) {
            const fault_addr = er.ExceptionInformation[1];
            const sp_addr = @intFromPtr(safepoint_page);
            
            if (fault_addr >= sp_addr and fault_addr < sp_addr + 4096) {
                // Safepoint Trap Caught! The hardware raised an exception on the dummy read.
                safepointSlow();
                // Return EXCEPTION_CONTINUE_EXECUTION so the CPU retries the instruction
                // Now that it's PAGE_READONLY, it will succeed instantly.
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

pub fn safepointSlow() void {
    gc_wait_lock.lockUncancelable(runtime.global_io);
    defer gc_wait_lock.unlock(runtime.global_io);
    
    const count = parked_count.fetchAdd(1, .acquire) + 1;
    if (count == expected_count) {
        gc_coordinator_cond.signal(runtime.global_io);
    }
    
    // We are now parked, wait for GC to unprotect the page
    while (safepoint_active) {
        gc_wait_cond.waitUncancelable(runtime.global_io, &gc_wait_lock);
    }
}
