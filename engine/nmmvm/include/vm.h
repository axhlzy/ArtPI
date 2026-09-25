//
// Created by mao on 20-8-11.
//

#ifndef DEX_EDITOR_VM_H
#define DEX_EDITOR_VM_H

#include <jni.h>
#include "Common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    u2 classIdx;
    char type;
    jfieldID fieldId;
} vmField;

typedef struct {
    u2 classIdx;
    u4 idx;              // method_idx in the owning dex (for tracer naming)
    const char *shorty;  //包含返回类型及参数类型,用于确定使用什么样的方法调用
    jmethodID methodId;
} vmMethod;

typedef struct {
    const u2 *insns;             //指令
    const u4 insnsSize;          //指令大小
    regptr_t *regs;                    //寄存器
    u1 *reg_flags;               //寄存器数据类型标记,主要标记是否为对象
    const u1 *triesHandlers;     //异常表
} vmCode;

typedef struct {

    const vmField *(*dvmResolveField)(JNIEnv *env, u4 idx, bool isStatic);

    const vmMethod *(*dvmResolveMethod)(JNIEnv *env, u4 idx, bool isStatic);

    //从类型常量池取得类型名
    const char *(*dvmResolveTypeUtf)(JNIEnv *env, u4 idx);

    //直接返回jclass对象,本地引用需要释放引用
    jclass (*dvmResolveClass)(JNIEnv *env, u4 idx);

    //根据类型名得到class
    jclass (*dvmFindClass)(JNIEnv *env, const char *type);

    //const_string指令加载的字符串对象
    jstring (*dvmConstantString)(JNIEnv *env, u4 idx);

} vmResolver;

//每条指令分发前调用(FINISH处),可空;用于trace/单步调试
//  pcOffset: 相对 insns 的偏移(16bit码元), inst: 已取出的指令字,
//  regs/regFlags: 当前寄存器文件与对象标记
typedef void (*vmTraceHookFn)(JNIEnv *env, const vmCode *code, u4 pcOffset,
                              u2 inst, const regptr_t *regs, const u1 *regFlags);

extern vmTraceHookFn g_vmTraceHook;


jvalue vmInterpret(
        JNIEnv *env,
        const vmCode *code,
        const vmResolver *dvmResolver
);

// tracer-aware entry: fctx may be NULL (behaves exactly like vmInterpret).
// When a VmTracer is attached, invoke sites / instructions / exceptions are
// reported through the callbacks (see VmTracer.h).
typedef struct VmFrameCtx VmFrameCtx;
jvalue vmInterpret2(
        JNIEnv *env,
        const vmCode *code,
        const vmResolver *dvmResolver,
        VmFrameCtx *fctx
);

#ifdef __cplusplus
}
#endif

#endif //DEX_EDITOR_VM_H
