//
// agent_java.cpp - Java / ART domain bindings facade for QuickJS
//
#include "agent_java.h"
#include "agent_java_ref.h"
#include "agent_java_resolve.h"
#include "agent_java_decompile.h"
#include "agent_java_hook.h"
#include "agent_java_choose.h"
#include "agent_java_ui.h"

extern "C" {
    typedef void (*PineObservedObjectCallback)(JNIEnv* env, uint64_t raw, jobject obj);
    void PineNative_SetObservedObjectCallback(PineObservedObjectCallback cb);
}

namespace artpi { namespace agent {

void RegisterJavaApis(JSContext* ctx, JSValue global, JSValue java) {
    // 1. Hook callback for tracking objects observed during native calls
    PineNative_SetObservedObjectCallback(RegisterObservedObject);

    // 2. Register child subsystems in proper logical order
    RegisterJavaRefApis(ctx, global, java);
    RegisterJavaResolveApis(ctx, global, java);
    RegisterJavaDecompileApis(ctx, global, java);
    RegisterJavaHookApis(ctx, global, java);
    RegisterJavaChooseApis(ctx, global, java);
    RegisterJavaUiApis(ctx, global);
}

}} // namespace artpi::agent
