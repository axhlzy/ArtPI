//
// pi_interp_executor.h - interpreter main scheduler (L3/L4/L5)
//
// Runs a method body on the embedded nmmvm VM (full Dalvik portable
// instruction set incl. try/catch, switches, wide/float ops, monitor).
//
// Public API:
//   runMethod(env, ArtMethod*, thisObj, args, shorty)
//       -> interprets with default policy (no callbacks)
//
// Internal API (used by CallFrame::invokeInterpreted / StepIn recursion):
//   runMethodInternal(..., Callbacks*, Options*, FilterOptions*, depth)
//       -> full sandbox session: per-instruction callbacks, invoke
//          interception (StepIn / Mock), scope filtering
//
// Guarantees handled here:
//   - ARM64 AAPCS argument mapping (x-regs vs d-regs vs stack spill)
//   - JNI local-ref scoping (PushLocalFrame / PopLocalFrame)
//   - bytecode pre-scan (reject unsupported opcodes before running)
//   - per-thread reentrancy bookkeeping
//

#ifndef PI_INTERP_EXECUTOR_H
#define PI_INTERP_EXECUTOR_H

#include "pi_common.h"
#include "dex/pi_dex_resolver.h"
#include "pi_interp_tracer.h"

namespace PI { namespace Interp {

struct RunResult {
    enum Status : int {
        OK = 0,
        NO_CODE = 1,       // native / abstract / missing code_item
        RESOLVE_FAIL = 2,  // dex or code-item parsing failure
        UNSUPPORTED = 3,   // bytecode pre-scan rejected (unsupported opcodes)
        PACK_FAIL = 4,     // args do not fit the register layout
        ABORTED = 5,       // callback aborted the run / budget exhausted
        ERROR = 6,
    };

    Status status = ERROR;
    bool exceptionPending = false;  // Java exception left pending on env
    bool handoff = false;           // ABORTED specifically for safe hand-off
    bool isVoid = true;
    bool isWide = false;
    bool isObject = false;
    jvalue value{};                 // scalar / wide result
    jobject objectResult = nullptr; // local ref, valid when isObject
};

// Interpret the body of `method` (must be non-native / non-abstract).
//
//   thisObj : receiver for instance methods, ignored when static
//   args    : one jvalue per parameter, ordered per `shorty`
//   shorty  : dalvik shorty, shorty[0] = return type char,
//             then one char per parameter ('I','J','F','D','L',...)
RunResult runMethod(JNIEnv* env, ArtMethod* method, jobject thisObj,
                    const jvalue* args, const char* shorty);

// Full session variant with sandbox callbacks (StepIn recursion entry).
// label: optional method-name used in per-instruction trace section markers.
RunResult runMethodInternal(JNIEnv* env, ArtMethod* method, jobject thisObj,
                            const jvalue* args, const char* shorty,
                            const Callbacks* cbs, const Options* opts,
                            const FilterOptions* filter, int depth,
                            const char* label = nullptr);

// Build a dalvik shorty string from a JNI method signature
// "(II[Ljava/lang/String;)V" -> "VILL".
bool shortyFromSignature(const std::string& sig, std::string& out);

// One-time init (primitive + exception class cache). Called by PI::init().
bool init(JNIEnv* env);

// Per-instruction logging trace (logcat "PI_VMTrace" lines).
void setTraceEnabled(bool on);
bool isTraceEnabled();

}} // namespace PI::Interp

#endif // PI_INTERP_EXECUTOR_H
