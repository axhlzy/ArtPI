//
// pi_unified_tracer.h - §7 Unified Full-Stack Tracer abstraction
//
// Smali (Dalvik VM) 与 QBDI (Native 机器码) 在概念上同属"控制流与执行状态
// 的虚拟化拦截"。本头文件定义跨层统一抽象接口, 作为未来 Java + Native 连贯
// 混合追踪 (JNI 边界上下文接力) 的引擎插槽契约:
//
//   Java 层  : nmmvm 解释器  -> onInstruction(layer = JAVA_SMALI)
//   JNI 边界 : onCall(is_cross_bridge = true) -> 移交 Native 引擎
//   Native 层: QBDI addCodeCB -> onInstruction(layer = NATIVE_ARM64)
//   返回接力 : onReturn -> 解释器无缝恢复单步
//
// QBDI / Dobby 桥接 (engine/tracer/qbdi|dobby) 为 [预留], 未实现。
//

#ifndef PI_UNIFIED_TRACER_H
#define PI_UNIFIED_TRACER_H

#include <cstdint>

namespace PI { namespace Trace {

enum class Layer {
    JAVA_SMALI   = 0,  // Dalvik 字节码层
    NATIVE_ARM64 = 1   // ARM64 机器码层 (QBDI / Dobby)
};

// 底层引擎端: 动态单步控制原语 (相当于调试器按键 F7 / F8 / F9)
enum class TraceAction {
    CONTINUE  = 0,     // F9: 继续向下全速执行
    STEP_IN   = 1,     // F7: 深入子函数 (Java 递归解释 / QBDI 跟入 Native)
    STEP_OVER = 2,     // F8: 步过 (子函数黑盒执行, 只取结果)
    MOCK      = 3,     // 拦截并就地伪造返回值, 跳过真实执行
    ABORT     = 4      // 中止整个追踪会话
};

// 统一指令事件
struct InstructionEvent {
    Layer       layer;          // Java 或 Native
    uint64_t    pc;             // 字节码偏移 (Java) 或 内存绝对虚拟地址 (Native)
    uint32_t    opcode;         // Dalvik 操作码 或 ARM64 指令机器码
    const char* mnemonic;       // 助记符 ("const-string" / "ldr x0, [x1]")
    int         call_depth;     // Java + Native 统一累加深度
    void*       raw_context;    // VmFrameCtx* 或 QBDI::GPRState*
};

// 统一调用事件
struct CallEvent {
    Layer       layer;
    uint64_t    caller_pc;
    uint64_t    callee_target;  // ArtMethod* (Java) 或 函数绝对地址 (Native)
    const char* symbol_name;    // 方法名或导出函数符号名
    bool        is_cross_bridge;// 是否跨越 JNI 边界
    int         argc;
    uint64_t    args[8];        // 统一提取的前 8 个参数
    uint64_t    return_value;   // 仅 post 阶段有效
};

class ITracerListener {
public:
    virtual ~ITracerListener() = default;

    // 1. 每条指令执行前触发 (Smali 或 ARM64)
    virtual TraceAction onInstruction(const InstructionEvent& e) {
        (void) e;
        return TraceAction::CONTINUE;
    }

    // 2. 调用发生前触发 (决定 StepIn / 穿透 / Mock)
    virtual TraceAction onCall(const CallEvent& e, uint64_t* mock_return) {
        (void) e; (void) mock_return;
        return TraceAction::CONTINUE;
    }

    // 3. 调用完成后触发 (捕获返回值, 重新接管上下文)
    virtual void onReturn(const CallEvent& e) { (void) e; }

    // 4. 异常发生时触发
    virtual void onException(Layer layer, uint64_t exception_code_or_obj) {
        (void) layer; (void) exception_code_or_obj;
    }
};

class UnifiedCallDepth {
public:
    static int get();
    static void set(int depth);
    static void push();
    static void pop();
};

void setupFullStackNativeCallbacks(int baseDepth);
void cleanupFullStackNativeCallbacks();

}} // namespace PI::Trace

#endif // PI_UNIFIED_TRACER_H
