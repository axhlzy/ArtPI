//
// pi_qbdi_engine.h - §3.3 QBDI 原生指令插桩执行器
//
// 封装 QBDI::VM:
//   - ThreadLocal 独占实例 (杜绝多线程竞争)
//   - 白名单 Instrumented Range (业务 SO 之外全速穿透)
//   - 指令/内存事件通道 + 死循环熔断 (指令预算)
//   - AAPCS64 寄存器规范执行 (gprs: X0..X7, fprs: D0..D7)
//

#ifndef PI_QBDI_ENGINE_H
#define PI_QBDI_ENGINE_H

#include <jni.h>
#include <cstdint>
#include <functional>
#include <vector>

namespace PI { namespace Native {

struct NativeRunResult {
    enum Status {
        OK = 0,
        MAX_INSTRUCTIONS_REACHED = 1,
        CRASH_PROTECTED = 2,
        EXECUTION_ERROR = 3
    };

    Status   status = EXECUTION_ERROR;
    uint64_t gprResult = 0;             // X0 标量/指针返回值
    double   fprResult = 0.0;           // D0 浮点返回值
    uint64_t instructionsExecuted = 0;
};

class QBDIEngine {
public:
    QBDIEngine();
    ~QBDIEngine();

    // ThreadLocal 独占实例
    static QBDIEngine* current();

    // 1. 作用域配置
    bool addInstrumentedModule(const char* moduleName);
    bool addInstrumentedModuleFromAddr(uintptr_t addr);
    bool addInstrumentedRange(uintptr_t start, uintptr_t end);
    void clearInstrumentedRanges();

    // 2. 执行预算配置 (0 = 不限)
    void setInstructionBudget(uint64_t maxInsns);

    // 3. 执行原生函数 (AAPCS64)
    //    gprs: X0 ~ X7 参数 (最多 8; JniNativeBridge 负责打包)
    //    fprs: D0 ~ D7 参数 (浮点/双精度)
    NativeRunResult run(void* functionAddr,
                        const std::vector<uint64_t>& gprs,
                        const std::vector<double>& fprs);

    // 4. 事件通道注入 (lambda)
    //    返回 TraceAction 语义: CONTINUE=继续, 其他=中止本次执行
    void setInstructionCallback(
        std::function<int(uintptr_t pc, const char* mnemonic,
                          const char* disasm, int depth, void* rawGpr)> cb);
    void setInstructionCallback(
        std::function<int(uintptr_t pc, const char* mnemonic,
                          const char* disasm, int depth)> cb) {
        setInstructionCallback([cb = std::move(cb)](uintptr_t pc, const char* mnemonic,
                                                    const char* disasm, int depth, void*) {
            return cb(pc, mnemonic, disasm, depth);
        });
    }
    void setMemoryAccessCallback(
        std::function<void(uintptr_t insnPc, uintptr_t addr, size_t size,
                           bool isWrite, uint64_t val)> cb);

private:
    struct Impl;
    Impl* impl_ = nullptr;
};

}} // namespace PI::Native

#endif // PI_QBDI_ENGINE_H
