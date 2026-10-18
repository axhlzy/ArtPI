//
// native_thunk_arm64.S - Generic JNI entry for JS-implemented (native) methods
//
// A per-method stub generated at runtime (see agent_java_registerclass.cpp)
// loads a unique slot id into x16 and branches here. We spill the full argument
// register file (x0..x7 + d0..d7) plus the caller's SP, call the C++ dispatcher,
// then reload the return value from the frame.
//
// Frame layout (224 bytes, 16-byte aligned):
//   [  0 ..  63]  x0 .. x7
//   [ 64 .. 127]  d0 .. d7
//   [128]         caller_sp  (original SP -> first stack-passed argument)
//   [136]         x29, x30
//   [152]         slot id
//

#if defined(__aarch64__)

.text
.align 4

.global artpi_native_thunk_entry
.hidden artpi_native_thunk_entry
.type artpi_native_thunk_entry, %function
artpi_native_thunk_entry:
    sub sp, sp, #224

    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]

    stp d0, d1, [sp, #64]
    stp d2, d3, [sp, #80]
    stp d4, d5, [sp, #96]
    stp d6, d7, [sp, #112]

    add x9, sp, #224
    str x9, [sp, #128]

    stp x29, x30, [sp, #136]
    str x16,     [sp, #152]

    // ArtpiNativeDispatch(int slot, ArtpiNativeFrame* frame)
    mov w0, w16
    mov x1, sp
    bl  ArtpiNativeDispatch

    // Return value is written back into the frame by the dispatcher.
    ldr x0, [sp, #0]
    ldr d0, [sp, #64]

    ldp x29, x30, [sp, #136]
    add sp, sp, #224
    ret

#endif
