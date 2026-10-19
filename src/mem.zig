const std = @import("std");
const windows = std.os.windows;
const PROT = std.posix.PROT;
const target = @import("builtin").os.tag;
const kernel32 = @import("kernel32.zig");
const procmap = switch (target) {
    .windows => void,
    else => @import("procmap.zig"),
};

pub const Protection = packed struct {
    execute: bool = false,
    write: bool = false,
    read: bool = false,

    pub const everything: Protection = .{ .read = true, .write = true, .execute = true };

    fn posixFlags(p: Protection) PROT {
        return .{ .READ = p.read, .WRITE = p.write, .EXEC = p.execute };
    }

    fn winapiFlags(p: Protection) windows.PAGE {
        return windows.PAGE.fromProtection(.{ .read = p.read, .write = p.write, .execute = p.execute }) orelse unreachable;
    }

    fn fromWinapi(f: windows.PAGE) Protection {
        return .{
            .read = f.READONLY or f.READWRITE or f.WRITECOPY or f.EXECUTE_READ or f.EXECUTE_READWRITE or f.EXECUTE_WRITECOPY,
            .write = f.READWRITE or f.WRITECOPY or f.EXECUTE_READWRITE or f.EXECUTE_WRITECOPY,
            .execute = f.EXECUTE or f.EXECUTE_READ or f.EXECUTE_READWRITE or f.EXECUTE_WRITECOPY,
        };
    }

    fn fromPosix(f: PROT) Protection {
        return .{
            .read = f.READ,
            .write = f.WRITE,
            .execute = f.EXEC,
        };
    }

    test {
        const a: Protection = .everything;
        try std.testing.expectEqual(PROT{ .WRITE = true, .READ = true, .EXEC = true }, a.posixFlags());

        const b: Protection = .{ .read = true };
        try std.testing.expectEqual(PROT{ .READ = true }, b.posixFlags());

        const c: Protection = .{ .write = true };
        try std.testing.expectEqual(PROT{ .WRITE = true }, c.posixFlags());

        const d: Protection = .{ .execute = true };
        try std.testing.expectEqual(PROT{ .EXEC = true }, d.posixFlags());

        const e: Protection = .{};
        try std.testing.expectEqual(PROT{}, e.posixFlags());
    }
};

pub const MapError = switch (target) {
    .windows => error{ AccessDenied, OutOfMemory, Unexpected },
    else => std.posix.MMapError,
};

pub const ProtectError = switch (target) {
    .windows => error{ AccessDenied, Unexpected },
    .linux => std.process.ProtectMemoryError || procmap.ProcmapQuery.QueryError,
    else => unreachable,
};

pub fn map(addr: ?*anyopaque, size: usize, prot: Protection) MapError![]align(std.heap.page_size_min) u8 {
    return switch (target) {
        .windows => blk: {
            var base = addr;
            var length = size;
            switch (windows.ntdll.NtAllocateVirtualMemory(windows.current_process, @ptrCast(&base), 0, &length, .{ .COMMIT = true, .RESERVE = true }, prot.winapiFlags())) {
                .SUCCESS => break :blk @as([*]align(std.heap.page_size_min) u8, @ptrCast(@alignCast(base.?)))[0..size],
                .ACCESS_DENIED => return error.AccessDenied,
                .NO_MEMORY, .CONFLICTING_ADDRESSES, .COMMITMENT_LIMIT => return error.OutOfMemory,
                else => |status| return windows.unexpectedStatus(status),
            }
        },
        .linux => std.posix.mmap(@ptrCast(@alignCast(addr)), size, prot.posixFlags(), .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0),
        else => unreachable,
    };
}

pub fn unmap(mem: []align(std.heap.page_size_min) u8) void {
    return switch (target) {
        .windows => {
            var base: windows.PVOID = mem.ptr;
            var size: usize = 0;
            const status = windows.ntdll.NtFreeVirtualMemory(windows.current_process, &base, &size, .{ .RELEASE = true });
            std.debug.assert(status == .SUCCESS);
        },
        .linux => std.posix.munmap(mem),
        else => unreachable,
    };
}

pub fn protect(mem: []align(std.heap.page_size_min) u8, prot: Protection) ProtectError!Protection {
    switch (target) {
        .windows => {
            var base: ?windows.PVOID = mem.ptr;
            var size = mem.len;
            var prev: windows.PAGE = undefined;
            switch (windows.ntdll.NtProtectVirtualMemory(windows.current_process, &base, &size, prot.winapiFlags(), &prev)) {
                .SUCCESS => {},
                .INVALID_ADDRESS, .ACCESS_DENIED => return error.AccessDenied,
                else => |status| return windows.unexpectedStatus(status),
            }

            return .fromWinapi(prev);
        },
        .linux => {
            var q: procmap.ProcmapQuery = .{ .query_addr = @intFromPtr(mem.ptr), .query_flags = .{} };
            try q.query();

            try std.process.protectMemory(mem, .{ .read = prot.read, .write = prot.write, .execute = prot.execute });
            return q.vma_flags.prot();
        },
        else => unreachable,
    }
}

var mmap_min_addr: std.atomic.Value(usize) = .init(std.math.maxInt(usize));
var allocation_granularity: std.atomic.Value(usize) = .init(0);

pub const InitError = switch (target) {
    .windows => error{},
    .linux => std.posix.OpenError || std.posix.ReadError || std.fmt.ParseIntError,
    else => unreachable,
};

pub fn init() InitError!void {
    if (mmap_min_addr.load(.acquire) != std.math.maxInt(usize)) return;

    switch (target) {
        .windows => {
            var system_info: kernel32.SYSTEM_INFO = undefined;
            kernel32.GetSystemInfo(&system_info);
            allocation_granularity.store(system_info.dwAllocationGranularity, .monotonic);
            mmap_min_addr.store(@intFromPtr(system_info.lpMinimumApplicationAddress), .release);
        },
        .linux => {
            const min_addr_path = "/proc/sys/vm/mmap_min_addr";
            var buf: [32]u8 = undefined;
            const fd = try std.posix.openat(std.posix.AT.FDCWD, min_addr_path, .{ .CLOEXEC = true }, 0);
            defer std.Io.Threaded.closeFd(fd);

            const size = try std.posix.read(fd, &buf);
            const address = try std.fmt.parseInt(usize, std.mem.trim(u8, buf[0..size], "\r\n"), 10);
            mmap_min_addr.store(address, .release);
        },
        else => unreachable,
    }
}

pub const Range = struct {
    /// inclusive
    from: usize,
    /// inclusive
    to: usize,

    pub fn contains(r: Range, addr: usize) bool {
        return addr >= r.from and addr <= r.to;
    }

    pub fn intersects(a: Range, b: Range) bool {
        return a.from <= b.to and b.from <= a.to;
    }

    /// Construct the range [origin - x; origin + x]
    pub fn symmetric(origin: usize, x: u32) Range {
        return .{
            .from = origin - x,
            .to = origin + x,
        };
    }

    /// Calculate max and min possible addresses for the trampoline relative to the target address
    pub fn rip(addr: usize) Range {
        const min_addr = mmap_min_addr.load(.acquire);
        const to = b: {
            if (addr > std.math.maxInt(usize) - std.math.maxInt(i32)) break :b std.math.maxInt(usize);
            break :b addr + std.math.maxInt(i32);
        };

        if (addr < std.math.maxInt(i32) + 1) {
            return .{
                .from = min_addr,
                .to = to,
            };
        }

        const from: usize = addr - std.math.maxInt(u32) / 2;
        return .{
            .from = if (from < min_addr) min_addr else from,
            .to = to,
        };
    }

    test {
        {
            const a: Range = .{ .from = 0, .to = 10 };
            const b: Range = .{ .from = 5, .to = 15 };
            try std.testing.expect(a.intersects(b));
            try std.testing.expect(b.intersects(a));
        }

        {
            const a: Range = .{ .from = 5, .to = 10 };
            const b: Range = .{ .from = 4, .to = 6 };
            try std.testing.expect(b.intersects(a));
        }
    }
};

pub const QueryError = switch (target) {
    .windows => error{Unexpected},
    .linux => procmap.ProcmapQuery.QueryError,
    else => unreachable,
};

fn vmaGapSize(addr: usize) QueryError!usize {
    var q: procmap.ProcmapQuery = .{
        .query_addr = addr,
        .query_flags = .{ .covering_or_next_vma = true },
    };
    try q.query();

    // no further VMAs are mapped
    if (q.query_addr >= q.vma_end) {
        return std.math.maxInt(usize) - addr;
    }

    return q.vma_start - addr;
}

/// Returns the starting address of a page that starts within the range
fn findUnmappedAreaWithinLinux(bounds: Range, gap_size: usize) QueryError!?usize {
    const page_size = std.heap.pageSize();
    var q: procmap.ProcmapQuery = .{
        .query_addr = bounds.from,
        .query_flags = .{ .covering_or_next_vma = true },
    };

    try q.query();
    while (q.vma_end <= bounds.to) {
        // no further VMAs are mapped
        if (q.query_addr >= q.vma_end) {
            return q.vma_end;
        }

        // we found a gap between VMAs
        if (q.vma_start > q.query_addr and try vmaGapSize(std.mem.alignBackward(usize, q.query_addr, page_size)) >= gap_size) {
            return std.mem.alignBackward(usize, q.query_addr, page_size);
        }

        q.query_addr = q.vma_end;
        try q.query();
    }

    return null;
}

/// Returns an address contained within a page that starts within the provided range
fn findUnmappedAreaWithinWindows(bounds: Range, gap_size: usize) QueryError!?usize {
    const granularity = allocation_granularity.load(.monotonic);
    var probe_address = std.mem.alignForward(usize, bounds.from, granularity);
    while (probe_address < bounds.to) {
        var memory_info: kernel32.MEMORY_BASIC_INFORMATION = undefined;
        const info_size = kernel32.VirtualQuery(@ptrFromInt(probe_address), &memory_info, @sizeOf(@TypeOf(memory_info)));

        if (info_size == 0) {
            return error.Unexpected;
        }

        if (memory_info.State == kernel32.MEM_FREE and memory_info.RegionSize >= gap_size) {
            return probe_address;
        }

        probe_address = @intFromPtr(memory_info.BaseAddress) + memory_info.RegionSize;
        probe_address += granularity - 1;
        probe_address = std.mem.alignBackward(usize, probe_address, granularity);
    }

    return null;
}

/// bounds: min & max address where we're looking for an unallocated vma
/// size: minimum size of the vma required
pub fn findUnmappedAreaWithin(bounds: Range, size: usize) QueryError!?usize {
    return switch (target) {
        .windows => findUnmappedAreaWithinWindows(bounds, size),
        .linux => findUnmappedAreaWithinLinux(bounds, size),
        else => unreachable,
    };
}

pub fn delta(a: usize, b: usize) isize {
    return switch (a > b) {
        true => @intCast(a - b),
        false => @as(isize, @intCast(b - a)) * -1,
    };
}
