//
// pi_hook_handle.h - Hook handle management for PI framework
//

#ifndef PI_HOOK_HANDLE_H
#define PI_HOOK_HANDLE_H

#include "pi_common.h"

namespace PI {

class Method;

/**
 * Handle returned by Method::hook().
 * Supports unhooking at any time via handle.unhook().
 * Uses shared state under the hood for safe copying.
 */
class HookHandle {
public:
    HookHandle();
    ~HookHandle();

    HookHandle(const HookHandle&) = default;
    HookHandle& operator=(const HookHandle&) = default;
    HookHandle(HookHandle&&) noexcept = default;
    HookHandle& operator=(HookHandle&&) noexcept = default;

    // Check if the hook was successfully established
    bool isValid() const;
    explicit operator bool() const { return isValid(); }

    // Check if the hook is currently active
    bool isHooked() const;

    // Remove the hook and restore original code / entry points
    bool unhook();

    // Get the backup trampoline entry point (for calling original)
    void* getBackup() const;

    // Get the target ArtMethod pointer
    ArtMethod* getArtMethod() const;

    struct Impl {
        ArtMethod* target = nullptr;
        void* backup = nullptr;
        bool is_hooked = false;
        bool is_inline = false;
        void* target_code_addr = nullptr;
        uint8_t orig_bytes[64] = {0};
        size_t orig_bytes_size = 0;
        void* orig_entry_point = nullptr;
        void* orig_interpreter_entry = nullptr;
        uint32_t orig_access_flags = 0;
        jclass global_clazz = nullptr;
        std::shared_ptr<_jobject> clazz_ref;

        ~Impl();
    };

    explicit HookHandle(std::shared_ptr<Impl> impl);

private:
    friend class Method;
    std::shared_ptr<Impl> impl_;
};

} // namespace PI

#endif // PI_HOOK_HANDLE_H
