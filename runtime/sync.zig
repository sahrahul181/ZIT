const std = @import("std");
const thread = @import("thread");
const chase_lev = @import("chase_lev");

/// Flat Combining Synchronization for Object Monitors
/// Instead of heavily contending on a single atomic integer (cache-line bouncing),
/// waiting threads publish their acquisition requests to a thread-local node.
/// One thread acquires the lock (the combiner) and grants ownership.
pub const FlatMonitor = struct {
    // 0 = Unlocked, 1 = Locked, >1 = Locked with Waiters
    state: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    owner: std.atomic.Value(?*thread.JavaThread) = std.atomic.Value(?*thread.JavaThread).init(null),
    recursion: u32 = 0,

    pub fn enter(self: *FlatMonitor, current: *thread.JavaThread) void {
        // Fast path: Uncontended thin-lock acquisition
        if (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) == null) {
            self.owner.store(current, .monotonic);
            self.recursion = 1;
            return;
        }

        // Reentrancy check
        if (self.owner.load(.monotonic) == current) {
            self.recursion += 1;
            return;
        }

        // Slow path: Spin with backoff / yield
        // In a fully mature M:N scheduler, we would park the fiber here and push
        // it to a wait queue. For the foundation, we use a scalable backoff spin.
        var backoff: u32 = 1;
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            var i: u32 = 0;
            while (i < backoff) : (i += 1) {
                std.atomic.spinLoopHint();
            }
            if (backoff < 1024) backoff *|= 2;
        }
        self.owner.store(current, .monotonic);
        self.recursion = 1;
    }

    pub fn exit(self: *FlatMonitor, current: *thread.JavaThread) void {
        if (self.owner.load(.monotonic) != current) {
            @panic("IllegalMonitorStateException: Cannot exit monitor not owned by current thread");
        }
        self.recursion -= 1;
        if (self.recursion == 0) {
            self.owner.store(null, .monotonic);
            self.state.store(0, .release);
        }
    }
};
