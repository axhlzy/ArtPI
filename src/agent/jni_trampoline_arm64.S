//
// jni_trampoline_arm64.S - Universal AArch64 Trampoline for 233 JNI functions
//
#if defined(__aarch64__)

.text
.align 4

.global artpi_jni_get_trampoline
.hidden artpi_jni_get_trampoline
.type artpi_jni_get_trampoline, %function
artpi_jni_get_trampoline:
    adrp x1, artpi_jni_trampolines
    add  x1, x1, :lo12:artpi_jni_trampolines
    add  x0, x1, w0, uxtw #3
    ret

.global artpi_jni_trampolines
.hidden artpi_jni_trampolines
.type artpi_jni_trampolines, %function
artpi_jni_trampolines:
.set slot, 0
.rept 233
    mov x16, slot
    b   artpi_jni_common_entry
.set slot, slot + 1
.endr

.global artpi_jni_common_entry
.hidden artpi_jni_common_entry
.type artpi_jni_common_entry, %function
artpi_jni_common_entry:
    // Frame layout (192 bytes, 16-byte aligned):
    // [sp, #0]:   fp, lr
    // [sp, #16]:  x0, x1
    // [sp, #32]:  x2, x3
    // [sp, #48]:  x4, x5
    // [sp, #64]:  x6, x7
    // [sp, #80]:  slot_id (x16)
    // [sp, #88]:  caller_lr (x30)
    // [sp, #96]:  d0, d1
    // [sp, #112]: d2, d3
    // [sp, #128]: d4, d5
    // [sp, #144]: d6, d7
    // [sp, #160]: return_x0
    // [sp, #168]: return_d0
    // [sp, #176]: x19 (callee-saved)
    // [sp, #184]: x20 (callee-saved)
    sub sp, sp, #192
    stp x29, x30, [sp, #0]
    mov x29, sp

    stp x0, x1,   [sp, #16]
    stp x2, x3,   [sp, #32]
    stp x4, x5,   [sp, #48]
    stp x6, x7,   [sp, #64]
    str x16,      [sp, #80]
    str x30,      [sp, #88]

    stp d0, d1,   [sp, #96]
    stp d2, d3,   [sp, #112]
    stp d4, d5,   [sp, #128]
    stp d6, d7,   [sp, #144]

    stp x19, x20, [sp, #176]

    // 1. Call Pre-Hook: ArtpiJniOnEnter(slot_id, env, saved_regs, caller_lr)
    mov w0, w16
    ldr x1, [sp, #16]
    add x2, sp, #16
    ldr x3, [sp, #88]
    bl  ArtpiJniOnEnter

    // 2. Fetch real function pointer: ArtpiJniGetRealFunc(slot_id)
    ldr w0, [sp, #80]
    bl  ArtpiJniGetRealFunc
    mov x16, x0

    // 3. Restore all original arguments
    ldp d0, d1,   [sp, #96]
    ldp d2, d3,   [sp, #112]
    ldp d4, d5,   [sp, #128]
    ldp d6, d7,   [sp, #144]

    ldp x0, x1,   [sp, #16]
    ldp x2, x3,   [sp, #32]
    ldp x4, x5,   [sp, #48]
    ldp x6, x7,   [sp, #64]

    // 4. Safe null-check: if real func is null, skip call
    cbz x16, 1f

    // Call real JNI implementation
    blr x16

1:
    // 5. Save return values
    str x0, [sp, #160]
    str d0, [sp, #168]

    // 6. Call Post-Hook: ArtpiJniOnLeave(slot_id, env, retval, caller_lr)
    ldr w0, [sp, #80]
    ldr x1, [sp, #16]
    ldr x2, [sp, #160]
    ldr x3, [sp, #88]
    bl  ArtpiJniOnLeave

    // 7. Restore return values
    ldr x0, [sp, #160]
    ldr d0, [sp, #168]

    // 8. Restore callee-saved registers
    ldp x19, x20, [sp, #176]

    // 9. Restore fp, lr, and return
    ldp x29, x30, [sp, #0]
    add sp, sp, #192
    ret

// ============================================================================
// Universal Native Call Invoker: uint64_t artpi_call_native_variadic(fn, argc, argv)
// ============================================================================
.global artpi_call_native_variadic
.hidden artpi_call_native_variadic
.type artpi_call_native_variadic, %function
artpi_call_native_variadic:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    stp x19, x20, [sp, #16]

    mov x19, x0        // x19 = target function
    mov x20, x1        // x20 = argc
    mov x16, x2        // x16 = argv pointer

    cbz x20, .L_invoke_call

    cmp x20, #8
    b.ls .L_load_regs

    // Compute aligned stack space for args 8..argc-1
    sub x9, x20, #8
    lsl x10, x9, #3
    add x10, x10, #15
    and x10, x10, #-16
    sub sp, sp, x10

    mov x11, #0
.L_copy_stack:
    cmp x11, x9
    b.ge .L_load_regs
    add x12, x11, #8
    ldr x13, [x16, x12, lsl #3]
    str x13, [sp, x11, lsl #3]
    add x11, x11, #1
    b .L_copy_stack

.L_load_regs:
    ldr x0, [x16, #0]
    cmp x20, #1
    b.eq .L_invoke_call
    ldr x1, [x16, #8]
    cmp x20, #2
    b.eq .L_invoke_call
    ldr x2, [x16, #16]
    cmp x20, #3
    b.eq .L_invoke_call
    ldr x3, [x16, #24]
    cmp x20, #4
    b.eq .L_invoke_call
    ldr x4, [x16, #32]
    cmp x20, #5
    b.eq .L_invoke_call
    ldr x5, [x16, #40]
    cmp x20, #6
    b.eq .L_invoke_call
    ldr x6, [x16, #48]
    cmp x20, #7
    b.eq .L_invoke_call
    ldr x7, [x16, #56]

.L_invoke_call:
    blr x19
    mov sp, x29
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

#endif

