//
// VmTracer.h - per-frame tracer hooks for the embedded Dalvik interpreter
//
// Allows a host (ArtPI sandbox) to observe and control interpreted runs:
//   - onInsn        : per-instruction pre-execute (may abort the run)
//   - onInvokePre   : called before a Java/JNI method invocation; returns
//                     a policy (JNI / STEP_IN / MOCK)
//   - stepIn        : executes a callee inside the host when policy is
//                     VM_INVOKE_STEP_IN (fills outRet, returns 0 = handled)
//   - onInvokePost  : after the callee returned (JNI or stepped-in)
//   - onException   : when a Java exception is raised inside the frame
//
// The interpreter creates ONE VmFrameCtx per vmInterpret2() call; nested
// frames (StepIn recursion) chain through `caller`.
//

#ifndef NMMVM_VMTRACER_H
#define NMMVM_VMTRACER_H

#include "vm.h"

#ifdef __cplusplus
extern "C" {
#endif

// onInvokePre return policy
#define VM_INVOKE_JNI     0  // 正常通过 JNI 调用原生方法
#define VM_INVOKE_STEP_IN 1  // 原地递归单步进入该方法解释执行
#define VM_INVOKE_MOCK    2  // 跳过方法调用，直接填充 mockRet

typedef struct VmFrameCtx {
    void* user;                  // host-defined session (PI::Interp::Session)
    const vmCode* code;
    struct VmFrameCtx* caller;   // StepIn 递归链的调用方帧
    int depth;                   // 0 = 顶层帧
    uint32_t pc;                 // 当前指令偏移 (16-bit code units)
    uint16_t inst;               // 当前指令字
    const regptr_t* regs;        // 寄存器文件
    const u1* regFlags;          // 对象标记
    uint64_t insns_executed;     // 本帧已执行指令数
    struct VmTracer const* tracer;
} VmFrameCtx;

typedef struct VmTracer {
    void* user;
    // return 0 = continue, nonzero = abort the whole run (bail)
    int  (*onInsn)(VmFrameCtx* c);
    int  (*onInvokePre)(VmFrameCtx* c, const vmMethod* m, int opcode,
                        jobject receiver, int argc, const jvalue* args,
                        jvalue* mockRet);
    int  (*stepIn)(VmFrameCtx* c, const vmMethod* m, int opcode,
                   jobject receiver, int argc, const jvalue* args,
                   jvalue* outRet);
    void (*onInvokePost)(VmFrameCtx* c, const vmMethod* m, int opcode,
                         const jvalue* ret, jboolean excPending);
    void (*onException)(VmFrameCtx* c, jthrowable exception, uint32_t throwPc,
                        int catchPc);
    void (*onFrameExit)(VmFrameCtx* c, const jvalue* ret);
} VmTracer;

#ifdef __cplusplus
}
#endif

#endif // NMMVM_VMTRACER_H
