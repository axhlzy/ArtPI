#define FUNCTION(name) \
.data; \
.align 4; \
.global name; \
name:

#define VAR(name) \
.global name; \
name:\
name##_addr:

#define LDVAR(reg, name) \
ldr reg, name##_addr;


FUNCTION(pine_direct_jump_trampoline)
LDVAR(x17, pine_direct_jump_trampoline_jump_entry)
br x17
VAR(pine_direct_jump_trampoline_jump_entry)
.long 0
.long 0

FUNCTION(pine_bridge_jump_trampoline)
LDVAR(x17, pine_bridge_jump_trampoline_target_method)
cmp x0, x17
bne jump_to_original
LDVAR(x17, pine_bridge_jump_trampoline_extras)
b acquire_lock

lock_failed:
wfe // Wait other thread to release the lock

acquire_lock:
ldaxr w16, [x17]
cbz w16, lock_failed // lock_flag == 0 (has other thread holding the lock), fail.
stlxr w16, wzr, [x17] // try set lock_flag to 0
cbnz w16, lock_failed // failed, try again.

// Now we hold the lock!
str x1, [x17, #4]
str x2, [x17, #12]
str x3, [x17, #20]
str d0, [x17, #28]
str d1, [x17, #36]
str d2, [x17, #44]
str d3, [x17, #52]
str d4, [x17, #60]
str d5, [x17, #68]
str d6, [x17, #76]
str d7, [x17, #84]
mov x1, x0 // first param = callee ArtMethod
mov x2, x17 // second param = extras (saved x1, x2, x3)
mov x3, sp // third param = sp
LDVAR(x0, pine_bridge_jump_trampoline_bridge_method)
LDVAR(x17, pine_bridge_jump_trampoline_bridge_entry)
br x17

jump_to_original:
LDVAR(x17, pine_bridge_jump_trampoline_call_origin_entry)
br x17
VAR(pine_bridge_jump_trampoline_target_method)
.long 0
.long 0
VAR(pine_bridge_jump_trampoline_extras)
.long 0
.long 0
VAR(pine_bridge_jump_trampoline_bridge_method)
.long 0
.long 0
VAR(pine_bridge_jump_trampoline_bridge_entry)
.long 0
.long 0
VAR(pine_bridge_jump_trampoline_call_origin_entry)
.long 0
.long 0

FUNCTION(pine_method_jump_trampoline)
LDVAR(x0, pine_method_jump_trampoline_dest_method)
LDVAR(x17, pine_method_jump_trampoline_dest_entry)
br x17
VAR(pine_method_jump_trampoline_dest_method)
.long 0
.long 0
VAR(pine_method_jump_trampoline_dest_entry)
.long 0
.long 0

FUNCTION(pine_call_origin_trampoline)
LDVAR(x0, pine_call_origin_trampoline_origin_method)
LDVAR(x17, pine_call_origin_trampoline_origin_code_entry)
br x17
VAR(pine_call_origin_trampoline_origin_method)
.long 0
.long 0
VAR(pine_call_origin_trampoline_origin_code_entry)
.long 0
.long 0

FUNCTION(pine_backup_trampoline)
LDVAR(x0, pine_backup_trampoline_origin_method)
VAR(pine_backup_trampoline_override_space)
.long 0 // 4 bytes (will be overwritten)
.long 0 // 4 bytes (will be overwritten)
.long 0 // 4 bytes (will be overwritten)
.long 0 // 4 bytes (will be overwritten)
nop // 4 bytes, may be overwritten for anti checks
nop // 4 bytes, may be overwritten for anti checks
LDVAR(x17, pine_backup_trampoline_remaining_code_entry)
br x17
VAR(pine_backup_trampoline_origin_method)
.long 0
.long 0
VAR(pine_backup_trampoline_remaining_code_entry)
.long 0
.long 0

FUNCTION(pine_native_bridge_trampoline)
    sub sp, sp, #320
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]

    add x9, sp, #320
    str x9, [sp, #248]

    stp d0, d1, [sp, #256]
    stp d2, d3, [sp, #272]
    stp d4, d5, [sp, #288]
    stp d6, d7, [sp, #304]

    ldr x0, [sp, #0]
    mov x1, sp
    LDVAR(x2, pine_native_bridge_trampoline_origin_entry)
    LDVAR(x17, pine_native_bridge_trampoline_callback)
    blr x17

    ldp d0, d1, [sp, #256]
    ldp d2, d3, [sp, #272]
    ldp d4, d5, [sp, #288]
    ldp d6, d7, [sp, #304]

    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]

    add sp, sp, #320
    ret

VAR(pine_native_bridge_trampoline_origin_entry)
.long 0
.long 0
VAR(pine_native_bridge_trampoline_callback)
.long 0
.long 0

FUNCTION(pine_trampolines_end)
// End tag used for calculate size only
