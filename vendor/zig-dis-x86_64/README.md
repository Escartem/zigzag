# zig-dis-x86_64
x86_64 disassembler library written in Zig

Vendored from [uniboi/zig-dis-x86_64](https://github.com/uniboi/zig-dis-x86_64) at commit `5c57c8b922d15d57c0addb42ca8f0eadb5776fe0`.
This copy requires Zig 0.17.0 and updates buffer I/O, formatting, type reflection, array initialization, and the existing tests for that version. The upstream MIT license is preserved in `LICENSE`.

## What is it?

You can use this library to disassemble and encode x86_64 machine code.

## Why is it?

I needed a simple disassembler for linker optimisations in `zig ld` for x86_64.

## Basic usage

Disassembling input byte buffer:

```zig
const std = @import("std");
const Disassembler = @import("dis_x86_64").Disassembler;

var disassembler = Disassembler.init(&.{
    0x40, 0xb7, 0x10,  // mov dil, 0x10
    0x48, 0x8b, 0xd8,  // mov rbx, rax
});

var text = std.Io.Writer.Allocating.init(gpa);
defer text.deinit();

while (try disassembler.next()) |inst| {
    try text.writer.print("{f}\n", .{inst});
}

try std.testing.expectEqualStrings(
    \\mov dil, 0x10
    \\mov rbx, rax
, text.written());
```

Encoding instructions back to machine code:

```zig
const std = @import("std");
const Instruction = @import("dis_x86_64").Instruction;

var code = std.Io.Writer.Allocating.init(gpa);
defer code.deinit();

const inst = try Instruction.new(.none, .mov, &.{
    .{ .reg = .rbx },
    .{ .imm = .{ .unsigned = 4 } },
});
try inst.encode(&code.writer, .{});

try std.testing.expectEqualSlices(u8, "\x48\xc7\xc3\x04\x00\x00\x00", code.written());
```
