//
// pi_qbdi_engine.cpp - QBDI 0.12 VM 封装实现 (完整重写)
//

#include "pi_qbdi_engine.h"
#include <android/log.h>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "QBDI.h"
#include "QBDI/Memory.h"

#define QE_LOGI(...) __android_log_print(ANDROID_LOG_INFO, "PI_QBDI", __VA_ARGS__)
#define QE_LOGW(...) __android_log_print(ANDROID_LOG_WARN, "PI_QBDI", __VA_ARGS__)

namespace PI { namespace Native {

struct QBDIEngine::Impl {
    QBDI::VM vm;
    std::recursive_mutex vmMutex;
    uint64_t budget = 0;
    uint64_t executed = 0;
    bool     aborted = false;

    std::function<int(uintptr_t, const char*, const char*, int, void*)> insnCb;
    std::function<void(uintptr_t, uintptr_t, size_t, bool, uint64_t)> memCb;

    uint8_t* fakeStack = nullptr;
    static constexpr uint32_t kStackSize = 1u << 20;

    uint32_t insnCbId = QBDI::INVALID_EVENTID;
    uint32_t memCbId  = QBDI::INVALID_EVENTID;

    static QBDI::VMAction budgetAndInsnTrampoline(QBDI::VMInstanceRef vm,
                                                  QBDI::GPRState*, QBDI::FPRState*, void*);
    static QBDI::VMAction memTrampoline(QBDI::VMInstanceRef vm,
                              QBDI::GPRState*, QBDI::FPRState*, void*);
};

namespace {
    void qbdiExitSentinel() {}
} // namespace

QBDIEngine* QBDIEngine::current() {
    static thread_local std::unique_ptr<QBDIEngine> engine;
    if (!engine) engine.reset(new QBDIEngine());
    return engine.get();
}

QBDIEngine::QBDIEngine() : impl_(new Impl()) {}

QBDIEngine::~QBDIEngine() {
    if (impl_->fakeStack != nullptr) {
        QBDI::alignedFree(impl_->fakeStack);
        impl_->fakeStack = nullptr;
    }
    delete impl_;
}

QBDI::VMAction QBDIEngine::Impl::budgetAndInsnTrampoline(
        QBDI::VMInstanceRef vmRef, QBDI::GPRState* gpr, QBDI::FPRState*, void* data) {
    Impl* impl = static_cast<Impl*>(data);
    impl->executed++;

    if (impl->budget != 0 && impl->executed > impl->budget) {
        QE_LOGW("QBDI budget exhausted (%llu insns), aborting run",
                (unsigned long long) impl->budget);
        impl->aborted = true;
        return QBDI::VMAction::STOP;
    }
    if (impl->insnCb) {
        const QBDI::InstAnalysis* ana = vmRef->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY |
            QBDI::ANALYSIS_SYMBOL | QBDI::ANALYSIS_OPERANDS);
        // NOTE: do NOT call addInstrumentedModuleFromAddr() here. Mutating
        // instrumented ranges while the VM is running invalidates QBDI's code
        // cache and makes vm.run() return false (status EXECUTION_ERROR),
        // discarding the real return value. Target modules are pre-added by
        // the caller (e.g. JniNativeBridge::dispatchToNative) before run().
        int action = impl->insnCb(
            (uintptr_t) (ana ? ana->address : 0),
            (ana && ana->mnemonic) ? ana->mnemonic : "",
            (ana && ana->disassembly) ? ana->disassembly : "",
            0,
            static_cast<void*>(gpr));
        if (action != 0) {
            impl->aborted = true;
            return QBDI::VMAction::STOP;
        }
    }
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction QBDIEngine::Impl::memTrampoline(
        QBDI::VMInstanceRef vmRef, QBDI::GPRState*, QBDI::FPRState*, void* data) {
    Impl* impl = static_cast<Impl*>(data);
    if (!impl->memCb) return QBDI::VMAction::CONTINUE;
    for (const QBDI::MemoryAccess& ma : vmRef->getInstMemoryAccess()) {
        bool isWrite = (ma.type & QBDI::MEMORY_WRITE) != 0;
        impl->memCb((uintptr_t) ma.instAddress,
                    (uintptr_t) ma.accessAddress,
                    (size_t) ma.size,
                    isWrite,
                    (uint64_t) ma.value);
    }
    return QBDI::VMAction::CONTINUE;
}



bool QBDIEngine::addInstrumentedModule(const char* moduleName) {
    std::lock_guard<std::recursive_mutex> lock(impl_->vmMutex);
    bool ok = impl_->vm.addInstrumentedModule(moduleName);
    QE_LOGI("addInstrumentedModule(%s) = %d", moduleName, ok ? 1 : 0);
    return ok;
}

bool QBDIEngine::addInstrumentedModuleFromAddr(uintptr_t addr) {
    std::lock_guard<std::recursive_mutex> lock(impl_->vmMutex);
    bool ok = impl_->vm.addInstrumentedModuleFromAddr((QBDI::rword) addr);
    QE_LOGI("addInstrumentedModuleFromAddr(%p) = %d", (void*) addr, ok ? 1 : 0);
    return ok;
}

bool QBDIEngine::addInstrumentedRange(uintptr_t start, uintptr_t end) {
    std::lock_guard<std::recursive_mutex> lock(impl_->vmMutex);
    impl_->vm.addInstrumentedRange((QBDI::rword) start, (QBDI::rword) end);
    return true;
}

void QBDIEngine::clearInstrumentedRanges() {
    std::lock_guard<std::recursive_mutex> lock(impl_->vmMutex);
    impl_->vm.removeAllInstrumentedRanges();
}

void QBDIEngine::setInstructionBudget(uint64_t maxInsns) {
    std::lock_guard<std::recursive_mutex> lock(impl_->vmMutex);
    impl_->budget = maxInsns;
}

void QBDIEngine::setInstructionCallback(
        std::function<int(uintptr_t, const char*, const char*, int, void*)> cb) {
    std::lock_guard<std::recursive_mutex> lock(impl_->vmMutex);
    impl_->insnCb = std::move(cb);
    if (impl_->insnCbId == QBDI::INVALID_EVENTID) {
        impl_->insnCbId = impl_->vm.addCodeCB(
            QBDI::InstPosition::PREINST,
            &QBDIEngine::Impl::budgetAndInsnTrampoline, impl_,
            QBDI::PRIORITY_DEFAULT);
    }
}

void QBDIEngine::setMemoryAccessCallback(
        std::function<void(uintptr_t, uintptr_t, size_t, bool, uint64_t)> cb) {
    std::lock_guard<std::recursive_mutex> lock(impl_->vmMutex);
    impl_->memCb = std::move(cb);
    if (impl_->memCbId == QBDI::INVALID_EVENTID) {
        impl_->vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
        impl_->memCbId = impl_->vm.addMemAccessCB(
            QBDI::MEMORY_READ_WRITE,
            &QBDIEngine::Impl::memTrampoline, (void*) impl_,
            QBDI::PRIORITY_DEFAULT);
    }
}

NativeRunResult QBDIEngine::run(void* functionAddr,
                                const std::vector<uint64_t>& gprs,
                                const std::vector<double>& fprs) {
    std::lock_guard<std::recursive_mutex> lock(impl_->vmMutex);
    NativeRunResult result;
    impl_->executed = 0;
    impl_->aborted = false;

    QBDI::GPRState* gpr = impl_->vm.getGPRState();
    QBDI::FPRState* fpr = impl_->vm.getFPRState();
    if (gpr == nullptr || fpr == nullptr) return result;

    if (impl_->fakeStack == nullptr) {
        if (!QBDI::allocateVirtualStack(gpr, Impl::kStackSize, &impl_->fakeStack)) {
            QE_LOGW("allocateVirtualStack failed");
            return result;
        }
    }
    QBDI::rword* x = &gpr->x0;

    for (size_t i = 0; i < gprs.size() && i < 8; i++) x[i] = gprs[i];
    for (size_t i = gprs.size(); i < 8; i++) x[i] = 0;
    QBDI::rword* v = reinterpret_cast<QBDI::rword*>(&fpr->v0);
    for (size_t i = 0; i < fprs.size() && i < 8; i++)
        v[2 * i] = *reinterpret_cast<const QBDI::rword*>(&fprs[i]);

    gpr->lr = (QBDI::rword) &qbdiExitSentinel;

    bool ok = impl_->vm.run((QBDI::rword) functionAddr,
                            (QBDI::rword) &qbdiExitSentinel);

    if (impl_->aborted) {
        result.status = NativeRunResult::MAX_INSTRUCTIONS_REACHED;
    } else if (!ok) {
        result.status = NativeRunResult::EXECUTION_ERROR;
    } else {
        result.status = NativeRunResult::OK;
    }
    result.gprResult = gpr->x0;
    result.fprResult = *reinterpret_cast<const double*>(&fpr->v0);
    result.instructionsExecuted = impl_->executed;

    gpr->sp = (QBDI::rword)(impl_->fakeStack + Impl::kStackSize - 64);
    return result;
}

}} // namespace PI::Native
