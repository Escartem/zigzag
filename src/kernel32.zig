const std = @import("std");
const windows = std.os.windows;

pub const MEM_FREE = 0x10000;

pub const SYSTEM_INFO = extern struct {
    processor_architecture: u16,
    reserved: u16,
    dwPageSize: u32,
    lpMinimumApplicationAddress: ?*anyopaque,
    lpMaximumApplicationAddress: ?*anyopaque,
    dwActiveProcessorMask: usize,
    dwNumberOfProcessors: u32,
    dwProcessorType: u32,
    dwAllocationGranularity: u32,
    wProcessorLevel: u16,
    wProcessorRevision: u16,
};

pub const MEMORY_BASIC_INFORMATION = extern struct {
    BaseAddress: ?*anyopaque,
    AllocationBase: ?*anyopaque,
    AllocationProtect: windows.PAGE,
    PartitionId: u16,
    RegionSize: usize,
    State: u32,
    Protect: windows.PAGE,
    Type: u32,
};

pub extern "kernel32" fn GetSystemInfo(lpSystemInfo: *SYSTEM_INFO) callconv(.winapi) void;

pub extern "kernel32" fn VirtualQuery(address: ?*const anyopaque, information: *MEMORY_BASIC_INFORMATION, length: usize) callconv(.winapi) usize;
