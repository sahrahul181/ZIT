/*
 * jit_guard.c  –  Portable setjmp/longjmp guard for JIT-to-interpreter
 *                 exception unwinding.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Custom jump buffer to avoid OS-specific setjmp/longjmp stack unwinding crashes.
// Layout:
// 0: rbx, 8: rbp, 16: rdi, 24: rsi, 32: r12, 40: r13, 48: r14, 56: r15, 64: rsp, 72: rip
typedef uint64_t my_jmp_buf[10];

#ifdef _WIN64
// Windows x64 ABI: RAX, RCX, RDX, R8, R9, R10, R11 are volatile.
// Non-volatile (must be saved): RBX, RBP, RDI, RSI, R12, R13, R14, R15, RSP.
__attribute__((noinline)) int my_setjmp(my_jmp_buf env) {
    int result = 0;
    __asm__ volatile (
        "mov %%rbx, 0(%1)\n\t"
        "mov %%rbp, 8(%1)\n\t"
        "mov %%rdi, 16(%1)\n\t"
        "mov %%rsi, 24(%1)\n\t"
        "mov %%r12, 32(%1)\n\t"
        "mov %%r13, 40(%1)\n\t"
        "mov %%r14, 48(%1)\n\t"
        "mov %%r15, 56(%1)\n\t"
        "lea 16(%%rbp), %%rax\n\t" // Caller's RSP is RBP + 16
        "mov %%rax, 64(%1)\n\t"
        "mov 8(%%rbp), %%rax\n\t"  // Caller's RIP is at 8(RBP)
        "mov %%rax, 72(%1)\n\t"
        "xor %%eax, %%eax\n\t"
        "mov %%eax, %0\n\t"
        : "=r"(result)
        : "r"(env)
        : "rax", "memory"
    );
    return result;
}

__attribute__((noinline)) void my_longjmp(my_jmp_buf env, int val) {
    __asm__ volatile (
        "mov 0(%0), %%rbx\n\t"
        "mov 8(%0), %%rbp\n\t"
        "mov 16(%0), %%rdi\n\t"
        "mov 24(%0), %%rsi\n\t"
        "mov 32(%0), %%r12\n\t"
        "mov 40(%0), %%r13\n\t"
        "mov 48(%0), %%r14\n\t"
        "mov 56(%0), %%r15\n\t"
        "mov 64(%0), %%rsp\n\t"
        "mov 72(%0), %%rax\n\t"
        "push %%rax\n\t"
        "mov %1, %%rax\n\t"
        "ret\n\t"
        : : "r"(env), "r"((uint64_t)val) : "memory"
    );
}
#else
// On other platforms, fallback to standard setjmp/longjmp
#include <setjmp.h>
#define my_setjmp(env) setjmp(env)
#define my_longjmp(env, val) longjmp(env, val)
#endif

typedef uint64_t (*JitFn4)(uint64_t, uint64_t, uint64_t, uint64_t);

/*
 * Thread-local pointer to the active jump buffer.
 */
#ifdef _WIN64
static __thread uint64_t *g_jmp_env = NULL;
#else
static __thread jmp_buf *g_jmp_env = NULL;
#endif

/*
 * Called by throwIndexOutOfBounds (in runtime.zig) when has_jmp_env is true.
 * Jumps back into jit_guarded_call.
 */
void jit_longjmp_if_guarded(void) {
#ifdef _WIN64
    uint64_t *env = g_jmp_env;
    if (env != NULL) {
        g_jmp_env = NULL;
        my_longjmp(env, 1);
    }
#else
    jmp_buf *env = g_jmp_env;
    if (env != NULL) {
        g_jmp_env = NULL;
        my_longjmp(*env, 1);
    }
#endif
}

static __thread int *g_exception_out = NULL;

/*
 * Called by interpreter.zig instead of callJitCode when a JavaThread is
 * active.  Wraps the JIT call in a setjmp guard.
 */
__attribute__((no_stack_protector))
uint64_t jit_guarded_call(
    void      *fn_ptr,
    uint64_t   a0,
    uint64_t   a1,
    uint64_t   a2,
    uint64_t   a3,
    int       *exception_out)
{
#ifdef _WIN64
    my_jmp_buf env;
    *exception_out = 0;
    g_exception_out = exception_out;

    if (my_setjmp(env) == 0) {
        g_jmp_env = (uint64_t*)&env;
        uint64_t result = ((JitFn4)fn_ptr)(a0, a1, a2, a3);
        g_jmp_env = NULL;
        g_exception_out = NULL;
        return result;
    } else {
        g_jmp_env = NULL;
        if (g_exception_out) {
            *g_exception_out = 1;
        }
        g_exception_out = NULL;
        return 0;
    }
#else
    jmp_buf env;
    *exception_out = 0;
    g_exception_out = exception_out;

    if (my_setjmp(env) == 0) {
        g_jmp_env = &env;
        uint64_t result = ((JitFn4)fn_ptr)(a0, a1, a2, a3);
        g_jmp_env = NULL;
        g_exception_out = NULL;
        return result;
    } else {
        g_jmp_env = NULL;
        if (g_exception_out) {
            *g_exception_out = 1;
        }
        g_exception_out = NULL;
        return 0;
    }
#endif
}
