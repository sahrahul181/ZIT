const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});
    const mod = b.addModule("ZIT", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "ZIT",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),

            .target = target,
            .optimize = optimize,

            .imports = &.{
                .{ .name = "ZIT", .module = mod },
            },
        }),
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    const inst_mod = b.addModule("instructions", .{ .root_source_file = b.path("inst/instructions.zig"), .optimize = optimize, .target = target });
    const inst_mod_test = b.addTest(.{ .root_module = inst_mod });
    test_step.dependOn(&b.addRunArtifact(inst_mod_test).step);

    const dex_mod = b.addModule("parser", .{ .root_source_file = b.path("dex/parser.zig"), .optimize = optimize, .target = target, .imports = &.{.{ .name = "instruction", .module = inst_mod }} });
    const dex_mod_test = b.addTest(.{ .root_module = dex_mod });
    test_step.dependOn(&b.addRunArtifact(dex_mod_test).step);

    const print_mod = b.addModule("printer", .{ .root_source_file = b.path("dex/print.zig"), .optimize = optimize, .target = target, .imports = &.{ .{ .name = "dex", .module = dex_mod }, .{ .name = "instruction", .module = inst_mod } } });
    const print_mod_test = b.addTest(.{ .root_module = print_mod });
    test_step.dependOn(&b.addRunArtifact(print_mod_test).step);

    const ir_mod = b.addModule("ir", .{ .root_source_file = b.path("jit/ir.zig"), .optimize = optimize, .target = target });
    const ir_mod_test = b.addTest(.{ .root_module = ir_mod });
    test_step.dependOn(&b.addRunArtifact(ir_mod_test).step);

    const cfg_mod = b.addModule("cfg", .{ .root_source_file = b.path("jit/cfg.zig"), .optimize = optimize, .target = target, .imports = &.{
        .{ .name = "instruction", .module = inst_mod },
        .{ .name = "ir", .module = ir_mod },
    } });
    const cfg_mod_test = b.addTest(.{ .root_module = cfg_mod });
    test_step.dependOn(&b.addRunArtifact(cfg_mod_test).step);

    const translate_mod = b.addModule("translate", .{ .root_source_file = b.path("jit/translate.zig"), .optimize = optimize, .target = target, .imports = &.{
        .{ .name = "instruction", .module = inst_mod },
        .{ .name = "ir", .module = ir_mod },
        .{ .name = "cfg", .module = cfg_mod },
    } });
    const translate_mod_test = b.addTest(.{ .root_module = translate_mod });
    test_step.dependOn(&b.addRunArtifact(translate_mod_test).step);

    // Integration test: parse the real d8-produced DEX and build a CFG from it.
    const cfg_it_mod = b.createModule(.{ .root_source_file = b.path("jit/cfg_integration_test.zig"), .optimize = optimize, .target = target, .imports = &.{
        .{ .name = "dex", .module = dex_mod },
        .{ .name = "cfg", .module = cfg_mod },
        .{ .name = "instruction", .module = inst_mod },
        .{ .name = "translate", .module = translate_mod },
        .{ .name = "ir", .module = ir_mod },
    } });
    const cfg_it_test = b.addTest(.{ .root_module = cfg_it_mod });
    test_step.dependOn(&b.addRunArtifact(cfg_it_test).step);

    const opt_mod = b.addModule("opt", .{
        .root_source_file = b.path("jit/opt.zig"),
        .optimize = optimize,
        .target = target,
        .imports = &.{
            .{ .name = "ir", .module = ir_mod },
            .{ .name = "cfg", .module = cfg_mod },
            .{ .name = "translate", .module = translate_mod },
            .{ .name = "instruction", .module = inst_mod },
        },
    });
    const opt_mod_test = b.addTest(.{ .root_module = opt_mod });
    test_step.dependOn(&b.addRunArtifact(opt_mod_test).step);

    const dessa_mod = b.addModule("dessa", .{
        .root_source_file = b.path("jit/dessa.zig"),
        .optimize = optimize,
        .target = target,
        .imports = &.{
            .{ .name = "ir", .module = ir_mod },
            .{ .name = "cfg", .module = cfg_mod },
            .{ .name = "instruction", .module = inst_mod },
            .{ .name = "translate", .module = translate_mod },
        },
    });
    const dessa_mod_test = b.addTest(.{ .root_module = dessa_mod });
    test_step.dependOn(&b.addRunArtifact(dessa_mod_test).step);

    const x86_mod = b.addModule("x86", .{
        .root_source_file = b.path("jit/x86.zig"),
        .optimize = optimize,
        .target = target,
        .imports = &.{
            .{ .name = "ir", .module = ir_mod },
        },
    });

    const lower_mod = b.addModule("lower", .{
        .root_source_file = b.path("jit/lower.zig"),
        .optimize = optimize,
        .target = target,
        .imports = &.{
            .{ .name = "ir", .module = ir_mod },
            .{ .name = "cfg", .module = cfg_mod },
            .{ .name = "x86", .module = x86_mod },
        },
    });
    const lower_mod_test = b.addTest(.{ .root_module = lower_mod });
    test_step.dependOn(&b.addRunArtifact(lower_mod_test).step);

    const regalloc_mod = b.addModule("regalloc", .{
        .root_source_file = b.path("jit/regalloc.zig"),
        .optimize = optimize,
        .target = target,
        .imports = &.{
            .{ .name = "ir", .module = ir_mod },
            .{ .name = "x86", .module = x86_mod },
            .{ .name = "cfg", .module = cfg_mod },
        },
    });
    const regalloc_mod_test = b.addTest(.{ .root_module = regalloc_mod });
    test_step.dependOn(&b.addRunArtifact(regalloc_mod_test).step);

    const runtime_mod = b.addModule("runtime", .{
        .root_source_file = b.path("runtime/runtime.zig"),
        .optimize = optimize,
        .target = target,
    });

    const emitter_mod = b.addModule("emitter", .{
        .root_source_file = b.path("jit/emitter.zig"),
        .optimize = optimize,
        .target = target,
        .imports = &.{
            .{ .name = "ir", .module = ir_mod },
            .{ .name = "x86", .module = x86_mod },
            .{ .name = "runtime", .module = runtime_mod },
        },
    });
    const emitter_mod_test = b.addTest(.{ .root_module = emitter_mod });
    test_step.dependOn(&b.addRunArtifact(emitter_mod_test).step);

    const exec_mem_mod = b.addModule("exec_mem", .{
        .root_source_file = b.path("jit/exec_mem.zig"),
        .optimize = optimize,
        .target = target,
        .imports = &.{
            .{ .name = "ir", .module = ir_mod },
            .{ .name = "cfg", .module = cfg_mod },
            .{ .name = "x86", .module = x86_mod },
            .{ .name = "lower", .module = lower_mod },
            .{ .name = "regalloc", .module = regalloc_mod },
            .{ .name = "emitter", .module = emitter_mod },
            .{ .name = "instruction", .module = inst_mod },
            .{ .name = "translate", .module = translate_mod },
            .{ .name = "runtime", .module = runtime_mod },
        },
    });
    const exec_mem_mod_test = b.addTest(.{ .root_module = exec_mem_mod });
    test_step.dependOn(&b.addRunArtifact(exec_mem_mod_test).step);


    const dex_dbg = b.addExecutable(.{
        .name = "dex-dbg",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/dex_dbg.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "parser", .module = dex_mod },
                .{ .name = "cfg", .module = cfg_mod },
                .{ .name = "instruction", .module = inst_mod },
                .{ .name = "printer", .module = print_mod },
                .{ .name = "translate", .module = translate_mod },
                .{ .name = "ir", .module = ir_mod },
                .{ .name = "opt", .module = opt_mod },
                .{ .name = "dessa", .module = dessa_mod },
                .{ .name = "x86", .module = x86_mod },
                .{ .name = "lower", .module = lower_mod },
                .{ .name = "regalloc", .module = regalloc_mod },
                .{ .name = "emitter", .module = emitter_mod },
                .{ .name = "exec_mem", .module = exec_mem_mod },
            },
        }),
    });
    dex_dbg.root_module.addIncludePath(b.path("nanopb"));
    dex_dbg.root_module.addCSourceFile(.{ .file = b.path("nanopb/pb_decode.c") });
    dex_dbg.root_module.addCSourceFile(.{ .file = b.path("nanopb/metadata_decoder.c") });
    dex_dbg.root_module.link_libc = true;
    b.installArtifact(dex_dbg);
}
