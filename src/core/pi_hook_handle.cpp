//
// pi_hook_handle.cpp - Implementation of HookHandle
//

#include "pi_hook_handle.h"
#include "art/art_method.h"
#include "utils/memory.h"
#include "utils/scoped_memory_access_protection.h"
#include "pine_native.h"
#include <cstring>

namespace PI {

HookHandle::Impl::~Impl() {
    clazz_ref.reset();
    global_clazz = nullptr;
}

HookHandle::HookHandle() : impl_(nullptr) {}

HookHandle::HookHandle(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}

HookHandle::~HookHandle() = default;

bool HookHandle::isValid() const {
    return impl_ && impl_->target != nullptr && impl_->backup != nullptr;
}

bool HookHandle::isHooked() const {
    return impl_ && impl_->is_hooked;
}

void* HookHandle::getBackup() const {
    return impl_ ? impl_->backup : nullptr;
}

ArtMethod* HookHandle::getArtMethod() const {
    return impl_ ? impl_->target : nullptr;
}

bool HookHandle::unhook() {
    if (!impl_ || !impl_->is_hooked || !impl_->target) {
        return false;
    }

    ArtMethod* target = impl_->target;

    // 1. If inline hook, restore original machine code bytes
    if (impl_->is_inline && impl_->target_code_addr && impl_->orig_bytes_size > 0) {
        pine::Memory::Unprotect(impl_->target_code_addr);
        {
            pine::ScopedMemoryAccessProtection protection(impl_->target_code_addr, impl_->orig_bytes_size);
            std::memcpy(impl_->target_code_addr, impl_->orig_bytes, impl_->orig_bytes_size);
        }
        pine::Memory::FlushCache(impl_->target_code_addr, impl_->orig_bytes_size);
        PI_LOGI("HookHandle::unhook: Restored %zu inline machine code bytes at %p",
                impl_->orig_bytes_size, impl_->target_code_addr);
    } else if (!impl_->is_inline && impl_->orig_entry_point) {
        // 2. If replacement hook, restore entry_point_from_compiled_code_
        target->SetEntryPointFromCompiledCode(impl_->orig_entry_point);
        PI_LOGI("HookHandle::unhook: Restored compiled code entrypoint to %p",
                impl_->orig_entry_point);
    }

    // 3. Restore access flags
    target->SetAccessFlags(impl_->orig_access_flags);

    // 4. Remove from Pine dispatcher registry
    Pine::unregisterMethodHook(target);

    // 5. Clean up clazz reference
    impl_->clazz_ref.reset();
    impl_->global_clazz = nullptr;

    impl_->is_hooked = false;
    PI_LOGI("HookHandle::unhook: Successfully unhooked ArtMethod %p", target);
    return true;
}

} // namespace PI
