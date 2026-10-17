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

#endif
