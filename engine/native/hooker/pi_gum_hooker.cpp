//
// pi_gum_hooker.cpp - libgum 后端实现 (frida-gum 17.x API)
//

#include "pi_gum_hooker.h"
#include "pi_native_hook.h"
#include <android/log.h>
#include <cstring>
#include <memory>
#include <mutex>

#include "frida-gum.h"
#include "xdl.h"

#define GH_LOGI(...) __android_log_print(ANDROID_LOG_INFO, "PI_NativeHook", __VA_ARGS__)
#define GH_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "PI_NativeHook", __VA_ARGS__)

namespace PI { namespace Native {

namespace {
    std::mutex g_gum_mutex;
    bool g_gum_initialized = false;

    GumInterceptor* sharedInterceptor() {
        return gum_interceptor_obtain();
    }

    // ---------------------------------------------------------------------------
    // 后端无关 HookContext 的 gum 适配器
    // ---------------------------------------------------------------------------
    class GumHookContext final : public HookContext {
    public:
        explicit GumHookContext(GumInvocationContext* ctx) : ctx_(ctx) {}

        void* nthArgument(int index) const override {
            return gum_invocation_context_get_nth_argument(ctx_, (guint) index);
        }
        void replaceNthArgument(int index, void* value) override {
            gum_invocation_context_replace_nth_argument(ctx_, (guint) index, value);
        }
        void* returnValue() const override {
            return gum_invocation_context_get_return_value(ctx_);
        }
        void replaceReturnValue(void* value) override {
            gum_invocation_context_replace_return_value(ctx_, value);
        }
        void* returnAddress() const override {
            return gum_invocation_context_get_return_address(ctx_);
        }
        unsigned int threadId() const override {
            return gum_invocation_context_get_thread_id(ctx_);
        }
        unsigned int depth() const override {
            return gum_invocation_context_get_depth(ctx_);
        }
        void* listenerThreadData(size_t requiredSize) const override {
            return gum_invocation_context_get_listener_thread_data(ctx_, requiredSize);
        }
        void* listenerFunctionData() const override {
            return gum_invocation_context_get_listener_function_data(ctx_);
        }
        void* listenerInvocationData(size_t requiredSize) const override {
            return gum_invocation_context_get_listener_invocation_data(ctx_, requiredSize);
        }
        void* replacementData() const override {
            return gum_invocation_context_get_replacement_data(ctx_);
        }
        void* cpuContext() const override {
            return &ctx_->cpu_context;
        }
        void* raw() const override {
            return ctx_;
        }

    private:
        GumInvocationContext* ctx_;
    };

    // ---------------------------------------------------------------------------
    // 抽象后端会话 (lambda 回调 + gum listener 生命周期; gum data_destroy 托管)
    // ---------------------------------------------------------------------------
    struct BackendSession {
        NativeHookCallback on_enter;
        NativeHookCallback on_leave;
        GumInvocationListener* listener = nullptr;
    };

    void BE_ON_ENTER(GumInvocationContext* ctx, gpointer user_data) {
        auto* s = static_cast<BackendSession*>(user_data);
        if (s && s->on_enter) {
            GumHookContext adapter(ctx);
            s->on_enter(adapter);
        }
    }
    void BE_ON_LEAVE(GumInvocationContext* ctx, gpointer user_data) {
        auto* s = static_cast<BackendSession*>(user_data);
        if (s && s->on_leave) {
            GumHookContext adapter(ctx);
            s->on_leave(adapter);
        }
    }

    // ---------------------------------------------------------------------------
    // spec 门面会话 (GumInvocationContext* 直通)
    // ---------------------------------------------------------------------------
    struct RawSession {
        std::function<void(GumInvocationContext*)> on_enter;
        std::function<void(GumInvocationContext*)> on_leave;
        GumInvocationListener* listener = nullptr;
    };

    void RAW_ON_ENTER(GumInvocationContext* ctx, gpointer user_data) {
        auto* s = static_cast<RawSession*>(user_data);
        if (s && s->on_enter) s->on_enter(ctx);
    }
    void RAW_ON_LEAVE(GumInvocationContext* ctx, gpointer user_data) {
        auto* s = static_cast<RawSession*>(user_data);
        if (s && s->on_leave) s->on_leave(ctx);
    }

    struct Txn {
        GumInterceptor* inv;
        explicit Txn(GumInterceptor* i) : inv(i) { gum_interceptor_begin_transaction(inv); }
        ~Txn() { gum_interceptor_end_transaction(inv); }
    };
} // namespace

// ============================================================================
// GumHookBackend (INativeHookBackend 抽象层适配)
// ============================================================================
bool GumHookBackend::init() {
    std::lock_guard<std::mutex> lock(g_gum_mutex);
    if (g_gum_initialized) return true;
    gum_init_embedded();
    g_gum_initialized = true;
    GH_LOGI("gum backend initialized (embedded)");
    return true;
}

bool GumHookBackend::isInitialized() const {
    std::lock_guard<std::mutex> lock(g_gum_mutex);
    return g_gum_initialized;
}

bool GumHookBackend::attach(void* target,
                            const NativeHookCallback& onEnter,
                            const NativeHookCallback& onLeave,
                            void** outHandle) {
    if (target == nullptr || (!onEnter && !onLeave)) return false;
    if (!isInitialized() && !init()) return false;

    // 会话生命周期由 gum listener 的 data_destroy 托管 (见析构 lambda)
    auto* session = new BackendSession{onEnter, onLeave, nullptr};

    GumInterceptor* inv = sharedInterceptor();
    Txn txn(inv);

    session->listener = gum_make_call_listener(
        onEnter ? &BE_ON_ENTER : nullptr,
        onLeave ? &BE_ON_LEAVE : nullptr,
        session,
        [](gpointer data) { delete static_cast<BackendSession*>(data); });
    if (session->listener == nullptr) {
        delete session;
        return false;
    }
    if (gum_interceptor_attach(inv, target, session->listener, nullptr) != GUM_ATTACH_OK) {
        // listener unref 触发 data_destroy → session 已释放
        g_object_unref(session->listener);
        return false;
    }
    *outHandle = session;   // detach 时 gum_interceptor_detach 会 unref listener
    return true;
}

bool GumHookBackend::detach(void* handle) {
    auto* session = static_cast<BackendSession*>(handle);
    if (session == nullptr || session->listener == nullptr) return false;
    GumInterceptor* inv = sharedInterceptor();
    Txn txn(inv);
    gum_interceptor_detach(inv, session->listener);
    // gum_interceptor_detach unref listener → data_destroy → session 释放
    return true;
}

bool GumHookBackend::replace(void* target, void* replacement,
                             void** outOriginal) {
    if (target == nullptr || replacement == nullptr) return false;
    if (!isInitialized() && !init()) return false;

    GumInterceptor* inv = sharedInterceptor();
    Txn txn(inv);
    gpointer original = nullptr;
    GumReplaceReturn ret = gum_interceptor_replace(
        inv, target, replacement, &original, nullptr);
    if (ret != GUM_REPLACE_OK) return false;
    if (outOriginal != nullptr) *outOriginal = original;
    return true;
}

void* GumHookBackend::findSymbol(const char* module, const char* symbol) {
    void* handle = xdl_open(module, XDL_DEFAULT);
    if (handle == nullptr) return nullptr;
    void* sym = xdl_sym(handle, symbol, nullptr);
    if (sym == nullptr) sym = xdl_dsym(handle, symbol, nullptr);
    xdl_close(handle);
    return sym;
}

// ============================================================================
// GumHooker 门面 (§3.1 契约: GumInvocationContext* 直通回调)
// ============================================================================
bool GumHooker::init() {
    std::lock_guard<std::mutex> lock(g_gum_mutex);
    if (g_gum_initialized) return true;
    gum_init_embedded();
    g_gum_initialized = true;
    return true;
}

bool GumHooker::isInitialized() {
    std::lock_guard<std::mutex> lock(g_gum_mutex);
    return g_gum_initialized;
}

NativeHookHandle GumHooker::hook(
    void* targetAddr,
    std::function<void(GumInvocationContext*)> onEnter,
    std::function<void(GumInvocationContext*)> onLeave) {
    if (targetAddr == nullptr || (!onEnter && !onLeave)) return NativeHookHandle();
    if (!init()) return NativeHookHandle();

    auto* session = new RawSession{std::move(onEnter), std::move(onLeave), nullptr};
    GumInterceptor* inv = sharedInterceptor();
    Txn txn(inv);

    session->listener = gum_make_call_listener(
        session->on_enter ? &RAW_ON_ENTER : nullptr,
        session->on_leave ? &RAW_ON_LEAVE : nullptr,
        session,
        [](gpointer data) { delete static_cast<RawSession*>(data); });
    if (session->listener == nullptr) {
        delete session;
        return NativeHookHandle();
    }
    if (gum_interceptor_attach(inv, targetAddr, session->listener, nullptr) != GUM_ATTACH_OK) {
        g_object_unref(session->listener);
        return NativeHookHandle();
    }
    return NativeHookHandle::fromCookie(session);   // cookie = RawSession*
}

NativeHookHandle GumHooker::hook(
    const char* moduleName, const char* symbolName,
    std::function<void(GumInvocationContext*)> onEnter,
    std::function<void(GumInvocationContext*)> onLeave) {
    void* handle = xdl_open(moduleName, XDL_DEFAULT);
    if (handle == nullptr) {
        GH_LOGE("xdl_open(%s) failed", moduleName);
        return NativeHookHandle();
    }
    void* sym = xdl_sym(handle, symbolName, nullptr);
    if (sym == nullptr) sym = xdl_dsym(handle, symbolName, nullptr);
    xdl_close(handle);
    if (sym == nullptr) {
        GH_LOGE("symbol %s not found in %s", symbolName, moduleName);
        return NativeHookHandle();
    }
    return hook(sym, std::move(onEnter), std::move(onLeave));
}

NativeHookHandle GumHooker::replace(
    void* targetAddr, void* replacementFunc, void** outOriginal) {
    if (targetAddr == nullptr || replacementFunc == nullptr) return NativeHookHandle();
    if (!init()) return NativeHookHandle();

    auto* session = new RawSession{};
    GumInterceptor* inv = sharedInterceptor();
    Txn txn(inv);
    gpointer original = nullptr;
    GumReplaceReturn ret = gum_interceptor_replace(
        inv, targetAddr, replacementFunc, &original, nullptr);
    if (ret != GUM_REPLACE_OK) {
        delete session;
        return NativeHookHandle();
    }
    if (outOriginal != nullptr) *outOriginal = original;
    return NativeHookHandle::fromCookie(session);
}

}} // namespace PI::Native

// ============================================================================
// NativeHookManager / NativeHookHandle (抽象管理层) 实现 — gum 为默认后端
// ============================================================================
namespace PI { namespace Native {

struct NativeHookManager::Impl {
    std::mutex mutex;
    std::vector<std::unique_ptr<INativeHookBackend>> backends;
    INativeHookBackend* current = nullptr;
};

NativeHookManager& NativeHookManager::instance() {
    static NativeHookManager mgr;
    static std::mutex s_init_mutex;
    static bool seeded = false;
    if (mgr.impl_ == nullptr) {
        mgr.impl_ = new Impl();
    }
    if (!seeded) {
        std::lock_guard<std::mutex> lock(s_init_mutex);
        if (!seeded) {
            // 默认后端: libgum (未来 libdobby 在此追加 registerBackend)
            mgr.impl_->backends.push_back(std::make_unique<GumHookBackend>());
            mgr.impl_->current = mgr.impl_->backends.back().get();
            seeded = true;
        }
    }
    return mgr;
}



bool NativeHookManager::init(const char* backendName) {
    auto& impl = *NativeHookManager::instance().impl_;
    std::lock_guard<std::mutex> lock(impl.mutex);
    INativeHookBackend* be = impl.current;
    if (backendName != nullptr) {
        for (auto& b : impl.backends) {
            if (std::strcmp(b->name(), backendName) == 0) { be = b.get(); break; }
        }
    }
    if (be == nullptr) return false;
    impl.current = be;
    return be->init();
}

bool NativeHookManager::isInitialized() const {
    auto& impl = *NativeHookManager::instance().impl_;
    std::lock_guard<std::mutex> lock(impl.mutex);
    return impl.current != nullptr && impl.current->isInitialized();
}

INativeHookBackend* NativeHookManager::backend(const char* name) const {
    auto& impl = *NativeHookManager::instance().impl_;
    std::lock_guard<std::mutex> lock(impl.mutex);
    if (name == nullptr) return impl.current;
    for (auto& b : impl.backends) {
        if (std::strcmp(b->name(), name) == 0) return b.get();
    }
    return nullptr;
}

void* NativeHookManager::hook(void* target,
                              const NativeHookCallback& onEnter,
                              const NativeHookCallback& onLeave) {
    auto& impl = *NativeHookManager::instance().impl_;
    std::lock_guard<std::mutex> lock(impl.mutex);
    if (impl.current == nullptr || !impl.current->isInitialized()) return nullptr;
    void* cookie = nullptr;
    if (!impl.current->attach(target, onEnter, onLeave, &cookie)) return nullptr;
    return cookie;
}

void* NativeHookManager::hook(const char* module, const char* symbol,
                              const NativeHookCallback& onEnter,
                              const NativeHookCallback& onLeave) {
    auto& impl = *NativeHookManager::instance().impl_;
    std::lock_guard<std::mutex> lock(impl.mutex);
    if (impl.current == nullptr || !impl.current->isInitialized()) return nullptr;
    void* target = impl.current->findSymbol(module, symbol);
    if (target == nullptr) return nullptr;
    void* cookie = nullptr;
    if (!impl.current->attach(target, onEnter, onLeave, &cookie)) return nullptr;
    return cookie;
}

void* NativeHookManager::replace(void* target, void* replacement,
                                 void** outOriginal) {
    auto& impl = *NativeHookManager::instance().impl_;
    std::lock_guard<std::mutex> lock(impl.mutex);
    if (impl.current == nullptr || !impl.current->isInitialized()) return nullptr;
    void* cookie = nullptr;
    if (!impl.current->replace(target, replacement, outOriginal)) return nullptr;
    return cookie;
}

bool NativeHookManager::unhook(void* handle) {
    auto& impl = *NativeHookManager::instance().impl_;
    std::lock_guard<std::mutex> lock(impl.mutex);
    if (impl.current == nullptr || handle == nullptr) return false;
    return impl.current->detach(handle);
}

// ---------------------------------------------------------------------------
// NativeHookHandle (RAII): cookie 直存, 生命周期语义见 pi_native_hook.h
// ---------------------------------------------------------------------------
NativeHookHandle::NativeHookHandle() : cookie_(nullptr) {}

NativeHookHandle::~NativeHookHandle() {
    if (cookie_ != nullptr) NativeHookManager::unhook(cookie_);
    cookie_ = nullptr;
}

NativeHookHandle::NativeHookHandle(NativeHookHandle&& other) noexcept
    : cookie_(other.cookie_) { other.cookie_ = nullptr; }

NativeHookHandle& NativeHookHandle::operator=(NativeHookHandle&& other) noexcept {
    if (this != &other) {
        if (cookie_ != nullptr) NativeHookManager::unhook(cookie_);
        cookie_ = other.cookie_;
        other.cookie_ = nullptr;
    }
    return *this;
}

bool NativeHookHandle::isValid() const { return cookie_ != nullptr; }

bool NativeHookHandle::unhook() {
    if (cookie_ == nullptr) return false;
    bool ok = NativeHookManager::unhook(cookie_);
    cookie_ = nullptr;
    return ok;
}

void* NativeHookHandle::getBackup() const { return cookie_; }

}} // namespace PI::Native