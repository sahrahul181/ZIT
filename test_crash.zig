const std = @import("std");

pub fn main() !void {
    const mem = try std.os.windows.VirtualAlloc(
        null,
        4096,
        std.os.windows.MEM_COMMIT | std.os.windows.MEM_RESERVE,
        std.os.windows.PAGE_EXECUTE_READWRITE,
    );
    
    // We can just call dex-dbg.exe and let it crash!
}
