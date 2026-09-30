// ===========================================================================
// UI Hierarchy & Click Event Inspection
// ===========================================================================
static jobject GetWindowManagerViews(JNIEnv* env) {
    if (!env) return nullptr;
    jclass wmgCls = FindClassWithFallback(env, "android.view.WindowManagerGlobal");
    if (!wmgCls) return nullptr;
    jmethodID getInstanceMid = env->GetStaticMethodID(wmgCls, "getInstance", "()Landroid/view/WindowManagerGlobal;");
    if (env->ExceptionCheck()) { env->ExceptionClear(); getInstanceMid = nullptr; }
    if (!getInstanceMid) { env->DeleteLocalRef(wmgCls); return nullptr; }
    jobject wmg = env->CallStaticObjectMethod(wmgCls, getInstanceMid);
    if (env->ExceptionCheck()) { env->ExceptionClear(); wmg = nullptr; }
    if (!wmg) { env->DeleteLocalRef(wmgCls); return nullptr; }
    jfieldID mViewsFid = env->GetFieldID(wmgCls, "mViews", "Ljava/util/ArrayList;");
    if (env->ExceptionCheck()) { env->ExceptionClear(); mViewsFid = nullptr; }
    jobject mViews = mViewsFid ? env->GetObjectField(wmg, mViewsFid) : nullptr;
    if (env->ExceptionCheck()) { env->ExceptionClear(); mViews = nullptr; }
    env->DeleteLocalRef(wmg);
    env->DeleteLocalRef(wmgCls);
    return mViews;
}

struct ViewNode {
    jobject view = nullptr;
    std::string className;
    std::string simpleName;
    int32_t id = 0;
    std::string idName;
    std::string text;
    std::string contentDesc;
    int32_t left = 0, top = 0, right = 0, bottom = 0;
    int32_t width = 0, height = 0;
    int32_t cx = 0, cy = 0;
    int32_t visibility = 0;
    bool isClickable = false;
    bool isEnabled = true;
    std::string listenerClassName;
    uint64_t listenerArtMethod = 0;
    std::string longClickListenerClassName;
    uint64_t longClickListenerArtMethod = 0;
    int depth = 0;
    std::vector<ViewNode> children;
};

struct UiFilterOptions {
    std::string pattern;
    std::string text;
    std::string id;
    std::string className;
    bool clickableOnly = false;
    bool visibleOnly = false;
    int maxDepth = 1000;

    bool hasFilter() const {
        return !pattern.empty() || !text.empty() || !id.empty() || !className.empty() || clickableOnly || visibleOnly;
    }
};

static bool ContainsCaseInsensitive(const std::string& str, const std::string& sub) {
    if (sub.empty()) return true;
    auto it = std::search(str.begin(), str.end(), sub.begin(), sub.end(),
                          [](char a, char b) { return tolower(a) == tolower(b); });
    return it != str.end();
}

static bool NodeMatchesFilter(const ViewNode& node, const UiFilterOptions& opt) {
    if (opt.clickableOnly && !node.isClickable && node.listenerClassName.empty() && node.longClickListenerClassName.empty()) return false;
    if (opt.visibleOnly && node.visibility != 0) return false;

    if (!opt.text.empty() && !ContainsCaseInsensitive(node.text, opt.text)) return false;
    if (!opt.id.empty() && !ContainsCaseInsensitive(node.idName, opt.id)) return false;
    if (!opt.className.empty() && !ContainsCaseInsensitive(node.simpleName, opt.className) && !ContainsCaseInsensitive(node.className, opt.className)) return false;

    if (!opt.pattern.empty()) {
        if (ContainsCaseInsensitive(node.text, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.idName, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.simpleName, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.className, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.listenerClassName, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.longClickListenerClassName, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.contentDesc, opt.pattern)) return true;
        char idBuf[32];
        snprintf(idBuf, sizeof(idBuf), "0x%x", node.id);
        if (ContainsCaseInsensitive(idBuf, opt.pattern)) return true;
        return false;
    }
    return true;
}

static bool HasMatchingDescendant(const ViewNode& node, const UiFilterOptions& opt) {
    for (const auto& child : node.children) {
        if (NodeMatchesFilter(child, opt) || HasMatchingDescendant(child, opt)) {
            return true;
        }
    }
    return false;
}

static UiFilterOptions ParseUiFilterOptions(JSContext* ctx, int argc, JSValueConst* argv) {
    UiFilterOptions opt;
    if (argc <= 0 || JS_IsUndefined(argv[0]) || JS_IsNull(argv[0])) return opt;

    if (JS_IsString(argv[0])) {
        const char* p = JS_ToCString(ctx, argv[0]);
        if (p) { opt.pattern = p; JS_FreeCString(ctx, p); }
    } else if (JS_IsObject(argv[0])) {
        JSValue patVal = JS_GetPropertyStr(ctx, argv[0], "pattern");
        if (JS_IsString(patVal)) { const char* s = JS_ToCString(ctx, patVal); if (s) { opt.pattern = s; JS_FreeCString(ctx, s); } }
        JS_FreeValue(ctx, patVal);

        JSValue textVal = JS_GetPropertyStr(ctx, argv[0], "text");
        if (JS_IsString(textVal)) { const char* s = JS_ToCString(ctx, textVal); if (s) { opt.text = s; JS_FreeCString(ctx, s); } }
        JS_FreeValue(ctx, textVal);

        JSValue idVal = JS_GetPropertyStr(ctx, argv[0], "id");
        if (JS_IsString(idVal)) { const char* s = JS_ToCString(ctx, idVal); if (s) { opt.id = s; JS_FreeCString(ctx, s); } }
        JS_FreeValue(ctx, idVal);

        JSValue clsVal = JS_GetPropertyStr(ctx, argv[0], "className");
        if (JS_IsString(clsVal)) { const char* s = JS_ToCString(ctx, clsVal); if (s) { opt.className = s; JS_FreeCString(ctx, s); } }
        JS_FreeValue(ctx, clsVal);

        JSValue clkVal = JS_GetPropertyStr(ctx, argv[0], "clickable");
        if (JS_IsBool(clkVal)) opt.clickableOnly = JS_ToBool(ctx, clkVal);
        JS_FreeValue(ctx, clkVal);

        JSValue visVal = JS_GetPropertyStr(ctx, argv[0], "visible");
        if (JS_IsBool(visVal)) opt.visibleOnly = JS_ToBool(ctx, visVal);
        JS_FreeValue(ctx, visVal);

        JSValue depVal = JS_GetPropertyStr(ctx, argv[0], "maxDepth");
        if (JS_IsNumber(depVal)) JS_ToInt32(ctx, &opt.maxDepth, depVal);
        JS_FreeValue(ctx, depVal);
    }
    return opt;
}

static void TraverseViewTree(JNIEnv* env, jobject v, int depth, ViewNode& node,
                             jclass viewCls, jclass viewGroupCls, jclass textViewCls,
                             jclass resCls, jmethodID getIdMid, jmethodID getVisMid,
                             jmethodID isClickableMid, jmethodID isEnabledMid,
                             jmethodID getWidthMid, jmethodID getHeightMid,
                             jmethodID getLocMid, jmethodID getResMid, jmethodID getEntryNameMid,
                             jmethodID getContentDescMid, jfieldID mListenerInfoFid,
                             jclass liCls, jfieldID liOnClickFid, jfieldID liOnLongClickFid,
                             jmethodID getChildCountMid, jmethodID getChildAtMid,
                             jmethodID getTextMid, jmethodID csToStringMid,
                             jintArray locArr, bool keepViewRefs) {
    if (!env || !v) return;
    node.depth = depth;
    if (keepViewRefs) {
        node.view = env->NewLocalRef(v);
    }

    jclass cls = env->GetObjectClass(v);
    node.className = JavaClassName(env, cls);
    node.simpleName = SimplifyJavaType(node.className);
    env->DeleteLocalRef(cls);

    if (getIdMid) {
        node.id = env->CallIntMethod(v, getIdMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (getVisMid) {
        node.visibility = env->CallIntMethod(v, getVisMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (isClickableMid) {
        node.isClickable = env->CallBooleanMethod(v, isClickableMid) != 0;
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (isEnabledMid) {
        node.isEnabled = env->CallBooleanMethod(v, isEnabledMid) != 0;
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (getWidthMid) {
        node.width = env->CallIntMethod(v, getWidthMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (getHeightMid) {
        node.height = env->CallIntMethod(v, getHeightMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (getLocMid && locArr) {
        env->CallVoidMethod(v, getLocMid, locArr);
        if (env->ExceptionCheck()) env->ExceptionClear();
        jint locBuf[2] = {0, 0};
        env->GetIntArrayRegion(locArr, 0, 2, locBuf);
        node.left = locBuf[0];
        node.top = locBuf[1];
        node.right = node.left + node.width;
        node.bottom = node.top + node.height;
        node.cx = node.left + node.width / 2;
        node.cy = node.top + node.height / 2;
    }

    if (node.id > 0 && node.id != -1 && getResMid && getEntryNameMid) {
        jobject res = env->CallObjectMethod(v, getResMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (res) {
            jstring nameJ = (jstring) env->CallObjectMethod(res, getEntryNameMid, node.id);
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            } else if (nameJ) {
                const char* s = env->GetStringUTFChars(nameJ, nullptr);
                if (s) {
                    node.idName = std::string("id/") + s;
                    env->ReleaseStringUTFChars(nameJ, s);
                }
                env->DeleteLocalRef(nameJ);
            }
            env->DeleteLocalRef(res);
        }
    }

    if (textViewCls && env->IsInstanceOf(v, textViewCls) && getTextMid) {
        jobject cs = env->CallObjectMethod(v, getTextMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (cs) {
            if (csToStringMid) {
                jstring ts = (jstring) env->CallObjectMethod(cs, csToStringMid);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (ts) {
                    const char* s = env->GetStringUTFChars(ts, nullptr);
                    if (s) {
                        node.text = s;
                        env->ReleaseStringUTFChars(ts, s);
                    }
                    env->DeleteLocalRef(ts);
                }
            }
            env->DeleteLocalRef(cs);
        }
    }

    if (getContentDescMid) {
        jobject cd = env->CallObjectMethod(v, getContentDescMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (cd) {
            if (csToStringMid) {
                jstring ts = (jstring) env->CallObjectMethod(cd, csToStringMid);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (ts) {
                    const char* s = env->GetStringUTFChars(ts, nullptr);
                    if (s) {
                        node.contentDesc = s;
                        env->ReleaseStringUTFChars(ts, s);
                    }
                    env->DeleteLocalRef(ts);
                }
            }
            env->DeleteLocalRef(cd);
        }
    }

    if (mListenerInfoFid) {
        jobject li = env->GetObjectField(v, mListenerInfoFid);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (li) {
            if (liOnClickFid) {
                jobject l = env->GetObjectField(li, liOnClickFid);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (l) {
                    jclass lCls = env->GetObjectClass(l);
                    node.listenerClassName = JavaClassName(env, lCls);
                    PI::Method pm = PI::resolve(env, lCls, "onClick", "(Landroid/view/View;)V");
                    if (pm.isValid()) {
                        node.listenerArtMethod = reinterpret_cast<uintptr_t>(pm.getArtMethod());
                    }
                    env->DeleteLocalRef(lCls);
                    env->DeleteLocalRef(l);
                }
            }
            if (liOnLongClickFid) {
                jobject ll = env->GetObjectField(li, liOnLongClickFid);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (ll) {
                    jclass llCls = env->GetObjectClass(ll);
                    node.longClickListenerClassName = JavaClassName(env, llCls);
                    PI::Method pm = PI::resolve(env, llCls, "onLongClick", "(Landroid/view/View;)Z");
                    if (pm.isValid()) {
                        node.longClickListenerArtMethod = reinterpret_cast<uintptr_t>(pm.getArtMethod());
                    }
                    env->DeleteLocalRef(llCls);
                    env->DeleteLocalRef(ll);
                }
            }
            env->DeleteLocalRef(li);
        }
    }

    if (viewGroupCls && env->IsInstanceOf(v, viewGroupCls) && getChildCountMid && getChildAtMid) {
        int childCount = env->CallIntMethod(v, getChildCountMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
        for (int i = 0; i < childCount; i++) {
            jobject child = env->CallObjectMethod(v, getChildAtMid, i);
            if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
            if (child) {
                ViewNode childNode;
                TraverseViewTree(env, child, depth + 1, childNode,
                                 viewCls, viewGroupCls, textViewCls, resCls,
                                 getIdMid, getVisMid, isClickableMid, isEnabledMid,
                                 getWidthMid, getHeightMid, getLocMid, getResMid, getEntryNameMid,
                                 getContentDescMid, mListenerInfoFid, liCls, liOnClickFid, liOnLongClickFid,
                                 getChildCountMid, getChildAtMid, getTextMid,
                                 csToStringMid, locArr, keepViewRefs);
                node.children.push_back(std::move(childNode));
                env->DeleteLocalRef(child);
            }
        }
    }
}

static void FormatViewTree(const ViewNode& v, const std::string& prefix, bool isLast,
                           std::ostringstream& ss, const UiFilterOptions& opt) {
    bool hasFilt = opt.hasFilter();
    bool selfMatch = NodeMatchesFilter(v, opt);
    bool childMatch = hasFilt && HasMatchingDescendant(v, opt);

    if (hasFilt && !selfMatch && !childMatch) return;

    std::string branch = prefix.empty() ? "" : (prefix + (isLast ? "└─ " : "├─ "));
    ss << branch << v.simpleName;
    if (!v.idName.empty()) {
        ss << " " << v.idName;
    } else if (v.id > 0) {
        char idBuf[32];
        snprintf(idBuf, sizeof(idBuf), " #0x%x", v.id);
        ss << idBuf;
    }
    if (!v.text.empty()) {
        std::string t = v.text;
        if (t.size() > 32) t = t.substr(0, 30) + "...";
        for (char& c : t) if (c == '\n' || c == '\r') c = ' ';
        ss << " \"" << t << "\"";
    }
    char boundsBuf[96];
    snprintf(boundsBuf, sizeof(boundsBuf), " [%d, %d, %d, %d] center=(%d, %d)",
             v.left, v.top, v.right, v.bottom, v.cx, v.cy);
    ss << boundsBuf;

    if (v.visibility != 0) {
        ss << (v.visibility == 4 ? " [INVISIBLE]" : " [GONE]");
    }
    if (v.isClickable || !v.listenerClassName.empty()) {
        ss << " [CLICKABLE]";
    }
    if (!v.isEnabled) {
        ss << " [DISABLED]";
    }
    if (!v.contentDesc.empty()) {
        ss << " desc=\"" << v.contentDesc << "\"";
    }
    if (hasFilt && selfMatch) {
        ss << " [★ MATCH]";
    }
    ss << "\n";

    if (!v.listenerClassName.empty()) {
        std::string nextPrefix = prefix.empty() ? "  " : (prefix + (isLast ? "    " : "│   "));
        ss << nextPrefix << "└─ ClickListener: " << v.listenerClassName;
        if (v.listenerArtMethod) {
            char artBuf[32];
            snprintf(artBuf, sizeof(artBuf), " (ArtMethod=0x%llx)", (unsigned long long) v.listenerArtMethod);
            ss << artBuf;
        }
        ss << "\n";
    }

    if (!v.longClickListenerClassName.empty()) {
        std::string nextPrefix = prefix.empty() ? "  " : (prefix + (isLast ? "    " : "│   "));
        ss << nextPrefix << "└─ LongClickListener: " << v.longClickListenerClassName;
        if (v.longClickListenerArtMethod) {
            char artBuf[32];
            snprintf(artBuf, sizeof(artBuf), " (ArtMethod=0x%llx)", (unsigned long long) v.longClickListenerArtMethod);
            ss << artBuf;
        }
        ss << "\n";
    }

    if (v.depth >= opt.maxDepth) return;

    std::vector<const ViewNode*> visibleChildren;
    for (const auto& child : v.children) {
        if (!hasFilt || NodeMatchesFilter(child, opt) || HasMatchingDescendant(child, opt)) {
            visibleChildren.push_back(&child);
        }
    }

    std::string childPrefix = prefix.empty() ? "  " : (prefix + (isLast ? "    " : "│   "));
    for (size_t i = 0; i < visibleChildren.size(); i++) {
        FormatViewTree(*visibleChildren[i], childPrefix, i + 1 == visibleChildren.size(), ss, opt);
    }
}

static bool DispatchTouchEventPair(JNIEnv* env, jobject decorView, float x, float y) {
    if (!env || !decorView) return false;
    jclass sysClockCls = env->FindClass("android/os/SystemClock");
    jmethodID uptimeMid = sysClockCls ? env->GetStaticMethodID(sysClockCls, "uptimeMillis", "()J") : nullptr;
    jlong now = uptimeMid ? env->CallStaticLongMethod(sysClockCls, uptimeMid) : 0;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jclass motionEventCls = env->FindClass("android/view/MotionEvent");
    jmethodID obtainMid = motionEventCls ? env->GetStaticMethodID(motionEventCls, "obtain", "(JJIFFI)Landroid/view/MotionEvent;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!obtainMid) {
        if (motionEventCls) env->DeleteLocalRef(motionEventCls);
        if (sysClockCls) env->DeleteLocalRef(sysClockCls);
        return false;
    }

    jclass viewCls = env->FindClass("android/view/View");
    jmethodID dispatchMid = viewCls ? env->GetMethodID(viewCls, "dispatchTouchEvent", "(Landroid/view/MotionEvent;)Z") : nullptr;
    jmethodID recycleMid = motionEventCls ? env->GetMethodID(motionEventCls, "recycle", "()V") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    // ACTION_DOWN = 0
    jobject downEv = env->CallStaticObjectMethod(motionEventCls, obtainMid, now, now, 0, x, y, 0);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (downEv && dispatchMid) {
        env->CallBooleanMethod(decorView, dispatchMid, downEv);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (recycleMid) env->CallVoidMethod(downEv, recycleMid);
        env->DeleteLocalRef(downEv);
    }

    // ACTION_UP = 1 (40ms later)
    jobject upEv = env->CallStaticObjectMethod(motionEventCls, obtainMid, now, now + 40, 1, x, y, 0);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (upEv && dispatchMid) {
        env->CallBooleanMethod(decorView, dispatchMid, upEv);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (recycleMid) env->CallVoidMethod(upEv, recycleMid);
        env->DeleteLocalRef(upEv);
    }

    if (viewCls) env->DeleteLocalRef(viewCls);
    if (motionEventCls) env->DeleteLocalRef(motionEventCls);
    if (sysClockCls) env->DeleteLocalRef(sysClockCls);
    return true;
}

static bool DispatchTouchSequence(JNIEnv* env, jobject decorView,
                                  float x1, float y1, float x2, float y2, int durationMs) {
    if (!env || !decorView) return false;
    jclass sysClockCls = env->FindClass("android/os/SystemClock");
    jmethodID uptimeMid = sysClockCls ? env->GetStaticMethodID(sysClockCls, "uptimeMillis", "()J") : nullptr;
    jlong downTime = uptimeMid ? env->CallStaticLongMethod(sysClockCls, uptimeMid) : 0;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jclass motionEventCls = env->FindClass("android/view/MotionEvent");
    jmethodID obtainMid = motionEventCls ? env->GetStaticMethodID(motionEventCls, "obtain", "(JJIFFI)Landroid/view/MotionEvent;") : nullptr;
    jclass viewCls = env->FindClass("android/view/View");
    jmethodID dispatchMid = viewCls ? env->GetMethodID(viewCls, "dispatchTouchEvent", "(Landroid/view/MotionEvent;)Z") : nullptr;
    jmethodID recycleMid = motionEventCls ? env->GetMethodID(motionEventCls, "recycle", "()V") : nullptr;

    if (!obtainMid || !dispatchMid) {
        if (viewCls) env->DeleteLocalRef(viewCls);
        if (motionEventCls) env->DeleteLocalRef(motionEventCls);
        if (sysClockCls) env->DeleteLocalRef(sysClockCls);
        return false;
    }

    // ACTION_DOWN = 0
    jobject downEv = env->CallStaticObjectMethod(motionEventCls, obtainMid, downTime, downTime, 0, x1, y1, 0);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (downEv) {
        env->CallBooleanMethod(decorView, dispatchMid, downEv);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (recycleMid) env->CallVoidMethod(downEv, recycleMid);
        env->DeleteLocalRef(downEv);
    }

    // Intermediate ACTION_MOVEs
    int steps = 10;
    int totalMs = durationMs > 0 ? durationMs : 250;
    int stepDelay = totalMs / steps;
    if (stepDelay < 5) stepDelay = 5;

    for (int i = 1; i <= steps; i++) {
        float factor = static_cast<float>(i) / static_cast<float>(steps);
        float curX = x1 + (x2 - x1) * factor;
        float curY = y1 + (y2 - y1) * factor;
        jlong curTime = downTime + i * stepDelay;
        // ACTION_MOVE = 2
        jobject moveEv = env->CallStaticObjectMethod(motionEventCls, obtainMid, downTime, curTime, 2, curX, curY, 0);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (moveEv) {
            env->CallBooleanMethod(decorView, dispatchMid, moveEv);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (recycleMid) env->CallVoidMethod(moveEv, recycleMid);
            env->DeleteLocalRef(moveEv);
        }
        usleep(stepDelay * 1000);
    }

    // ACTION_UP = 1
    jlong upTime = downTime + totalMs;
    jobject upEv = env->CallStaticObjectMethod(motionEventCls, obtainMid, downTime, upTime, 1, x2, y2, 0);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (upEv) {
        env->CallBooleanMethod(decorView, dispatchMid, upEv);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (recycleMid) env->CallVoidMethod(upEv, recycleMid);
        env->DeleteLocalRef(upEv);
    }

    if (viewCls) env->DeleteLocalRef(viewCls);
    if (motionEventCls) env->DeleteLocalRef(motionEventCls);
    if (sysClockCls) env->DeleteLocalRef(sysClockCls);
    return true;
}

static void FlattenViewNodes(JNIEnv* env, JSContext* ctx, const ViewNode& node,
                             const UiFilterOptions& opt, JSValue arr, uint32_t& idx) {
    if (NodeMatchesFilter(node, opt)) {
        JSValue item = JS_NewObject(ctx);
        if (node.view) {
            void* artObj = PineNative_ToArtObject(env, node.view);
            uint64_t addr = artObj ? reinterpret_cast<uintptr_t>(artObj) : reinterpret_cast<uintptr_t>(node.view);
            DoRegisterObservedObject(env, addr, node.view);
            int h = AddJRef(env, node.view, addr, /*persistent=*/true);
            JS_SetPropertyStr(ctx, item, "view", CreateJRefValue(ctx, h));
        } else {
            JS_SetPropertyStr(ctx, item, "view", JS_NULL);
        }
        JS_SetPropertyStr(ctx, item, "className", JS_NewString(ctx, node.className.c_str()));
        JS_SetPropertyStr(ctx, item, "simpleName", JS_NewString(ctx, node.simpleName.c_str()));
        JS_SetPropertyStr(ctx, item, "id", JS_NewInt32(ctx, node.id));
        JS_SetPropertyStr(ctx, item, "idName", JS_NewString(ctx, node.idName.c_str()));
        JS_SetPropertyStr(ctx, item, "text", JS_NewString(ctx, node.text.c_str()));
        JS_SetPropertyStr(ctx, item, "contentDesc", JS_NewString(ctx, node.contentDesc.c_str()));
        JS_SetPropertyStr(ctx, item, "clickable", JS_NewBool(ctx, node.isClickable || !node.listenerClassName.empty()));
        JS_SetPropertyStr(ctx, item, "enabled", JS_NewBool(ctx, node.isEnabled));
        JS_SetPropertyStr(ctx, item, "visibility", JS_NewInt32(ctx, node.visibility));

        JSValue b = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, b, "left", JS_NewInt32(ctx, node.left));
        JS_SetPropertyStr(ctx, b, "top", JS_NewInt32(ctx, node.top));
        JS_SetPropertyStr(ctx, b, "right", JS_NewInt32(ctx, node.right));
        JS_SetPropertyStr(ctx, b, "bottom", JS_NewInt32(ctx, node.bottom));
        JS_SetPropertyStr(ctx, b, "width", JS_NewInt32(ctx, node.width));
        JS_SetPropertyStr(ctx, b, "height", JS_NewInt32(ctx, node.height));
        JS_SetPropertyStr(ctx, b, "cx", JS_NewInt32(ctx, node.cx));
        JS_SetPropertyStr(ctx, b, "cy", JS_NewInt32(ctx, node.cy));
        JS_SetPropertyStr(ctx, item, "bounds", b);

        if (!node.listenerClassName.empty()) {
            JSValue l = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, l, "className", JS_NewString(ctx, node.listenerClassName.c_str()));
            if (node.listenerArtMethod) {
                JS_SetPropertyStr(ctx, l, "artMethod", JS_NewBigInt64(ctx, node.listenerArtMethod));
            }
            JS_SetPropertyStr(ctx, item, "clickListener", l);
        } else {
            JS_SetPropertyStr(ctx, item, "clickListener", JS_NULL);
        }

        if (!node.longClickListenerClassName.empty()) {
            JSValue ll = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, ll, "className", JS_NewString(ctx, node.longClickListenerClassName.c_str()));
            if (node.longClickListenerArtMethod) {
                JS_SetPropertyStr(ctx, ll, "artMethod", JS_NewBigInt64(ctx, node.longClickListenerArtMethod));
            }
            JS_SetPropertyStr(ctx, item, "longClickListener", ll);
        } else {
            JS_SetPropertyStr(ctx, item, "longClickListener", JS_NULL);
        }

        const char* kClickFn = "(function(){ return function(){ return UI.click(this); }; })()";
        JS_SetPropertyStr(ctx, item, "click", JS_Eval(ctx, kClickFn, strlen(kClickFn), "<click_fn>", JS_EVAL_TYPE_GLOBAL));

        const char* kLongClickFn = "(function(){ return function(){ return UI.longClick(this); }; })()";
        JS_SetPropertyStr(ctx, item, "longClick", JS_Eval(ctx, kLongClickFn, strlen(kLongClickFn), "<long_click_fn>", JS_EVAL_TYPE_GLOBAL));

        const char* kSetTextFn = "(function(){ return function(txt){ return UI.setText(this, txt); }; })()";
        JS_SetPropertyStr(ctx, item, "setText", JS_Eval(ctx, kSetTextFn, strlen(kSetTextFn), "<set_text_fn>", JS_EVAL_TYPE_GLOBAL));

        const char* kStrFn = "(function(){ return function(){ var idStr = this.idName ? (' ' + this.idName) : ''; var txt = this.text ? (' \"' + this.text + '\"') : ''; var clk = this.clickListener ? (' [Click: ' + this.clickListener.className + ']') : ''; return '[View ' + this.simpleName + idStr + txt + ' bounds=[' + this.bounds.left + ',' + this.bounds.top + ',' + this.bounds.right + ',' + this.bounds.bottom + ']' + clk + ']'; }; })()";
        JS_SetPropertyStr(ctx, item, "toString", JS_Eval(ctx, kStrFn, strlen(kStrFn), "<view_str_fn>", JS_EVAL_TYPE_GLOBAL));

        JS_SetPropertyUint32(ctx, arr, idx++, item);
    }

    for (const auto& child : node.children) {
        FlattenViewNodes(env, ctx, child, opt, arr, idx);
    }
}

static void FreeViewNodeTree(JNIEnv* env, ViewNode& node) {
    if (node.view) {
        env->DeleteLocalRef(node.view);
        node.view = nullptr;
    }
    for (auto& ch : node.children) {
        FreeViewNodeTree(env, ch);
    }
}

static jobject FindDeepestChildAt(JNIEnv* env, jobject parent, int x, int y,
                                  jclass viewCls, jclass viewGroupCls,
                                  jmethodID getVisMid, jmethodID getWidthMid,
                                  jmethodID getHeightMid, jmethodID getLocMid,
                                  jmethodID getChildCountMid, jmethodID getChildAtMid,
                                  jintArray locArr) {
    if (!env || !parent) return nullptr;
    if (getVisMid && env->CallIntMethod(parent, getVisMid) != 0) return nullptr;
    if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }

    env->CallVoidMethod(parent, getLocMid, locArr);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
    jint loc[2] = {0, 0};
    env->GetIntArrayRegion(locArr, 0, 2, loc);
    int w = env->CallIntMethod(parent, getWidthMid);
    int h = env->CallIntMethod(parent, getHeightMid);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }

    if (x < loc[0] || x > loc[0] + w || y < loc[1] || y > loc[1] + h) {
        return nullptr;
    }

    if (viewGroupCls && env->IsInstanceOf(parent, viewGroupCls) && getChildCountMid && getChildAtMid) {
        int count = env->CallIntMethod(parent, getChildCountMid);
        if (env->ExceptionCheck()) { env->ExceptionClear(); count = 0; }
        for (int i = count - 1; i >= 0; i--) {
            jobject child = env->CallObjectMethod(parent, getChildAtMid, i);
            if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
            if (child) {
                jobject hit = FindDeepestChildAt(env, child, x, y, viewCls, viewGroupCls,
                                                getVisMid, getWidthMid, getHeightMid, getLocMid,
                                                getChildCountMid, getChildAtMid, locArr);
                if (hit) {
                    env->DeleteLocalRef(child);
                    return hit;
                }
                env->DeleteLocalRef(child);
            }
        }
    }
    return env->NewLocalRef(parent);
}

struct HitViewResult {
    jobject targetView = nullptr;   // LocalRef
    jobject decorView = nullptr;    // LocalRef
    std::string className;
    std::string simpleName;
    std::string idName;
    std::string text;
    int left = 0, top = 0, right = 0, bottom = 0;
    int cx = 0, cy = 0;
};

static bool FindHitViewAt(JNIEnv* env, int x, int y, HitViewResult& out) {
    jobject mViews = GetWindowManagerViews(env);
    if (!mViews) return false;

    jclass listCls = env->FindClass("java/util/List");
    jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
    jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
    int numRoots = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
    if (env->ExceptionCheck()) { env->ExceptionClear(); numRoots = 0; }

    jclass viewCls = env->FindClass("android/view/View");
    jclass viewGroupCls = env->FindClass("android/view/ViewGroup");
    jclass textViewCls = env->FindClass("android/widget/TextView");
    jclass resCls = env->FindClass("android/content/res/Resources");
    jclass charSeqCls = env->FindClass("java/lang/CharSequence");
    jclass liCls = env->FindClass("android/view/View$ListenerInfo");

    jmethodID getIdMid = viewCls ? env->GetMethodID(viewCls, "getId", "()I") : nullptr;
    jmethodID getVisMid = viewCls ? env->GetMethodID(viewCls, "getVisibility", "()I") : nullptr;
    jmethodID isClickableMid = viewCls ? env->GetMethodID(viewCls, "isClickable", "()Z") : nullptr;
    jmethodID getWidthMid = viewCls ? env->GetMethodID(viewCls, "getWidth", "()I") : nullptr;
    jmethodID getHeightMid = viewCls ? env->GetMethodID(viewCls, "getHeight", "()I") : nullptr;
    jmethodID getLocMid = viewCls ? env->GetMethodID(viewCls, "getLocationOnScreen", "([I)V") : nullptr;
    jmethodID getResMid = viewCls ? env->GetMethodID(viewCls, "getResources", "()Landroid/content/res/Resources;") : nullptr;
    jmethodID getEntryNameMid = resCls ? env->GetMethodID(resCls, "getResourceEntryName", "(I)Ljava/lang/String;") : nullptr;
    jmethodID getParentMid = viewCls ? env->GetMethodID(viewCls, "getParent", "()Landroid/view/ViewParent;") : nullptr;
    jfieldID mListenerInfoFid = viewCls ? env->GetFieldID(viewCls, "mListenerInfo", "Landroid/view/View$ListenerInfo;") : nullptr;
    jfieldID liOnClickFid = liCls ? env->GetFieldID(liCls, "mOnClickListener", "Landroid/view/View$OnClickListener;") : nullptr;

    jmethodID getChildCountMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildCount", "()I") : nullptr;
    jmethodID getChildAtMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildAt", "(I)Landroid/view/View;") : nullptr;
    jmethodID getTextMid = textViewCls ? env->GetMethodID(textViewCls, "getText", "()Ljava/lang/CharSequence;") : nullptr;
    jmethodID csToStringMid = charSeqCls ? env->GetMethodID(charSeqCls, "toString", "()Ljava/lang/String;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jintArray locArr = env->NewIntArray(2);
    bool found = false;

    // Search from top-most window (highest index) down to 0
    for (int i = numRoots - 1; i >= 0 && !found; i--) {
        jobject root = env->CallObjectMethod(mViews, getMid, i);
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!root) continue;

        jobject hit = FindDeepestChildAt(env, root, x, y, viewCls, viewGroupCls,
                                         getVisMid, getWidthMid, getHeightMid,
                                         getLocMid, getChildCountMid, getChildAtMid, locArr);
        if (hit) {
            found = true;
            out.decorView = env->NewLocalRef(root);

            // Walk up to find clickable parent if hit itself is not clickable
            jobject target = env->NewLocalRef(hit);
            jboolean clickable = env->CallBooleanMethod(target, isClickableMid);
            jobject li = mListenerInfoFid ? env->GetObjectField(target, mListenerInfoFid) : nullptr;
            jobject l = (li && liOnClickFid) ? env->GetObjectField(li, liOnClickFid) : nullptr;
            if (l) env->DeleteLocalRef(l);
            if (li) env->DeleteLocalRef(li);

            if (!clickable && !l && getParentMid) {
                jobject curr = env->NewLocalRef(target);
                while (curr) {
                    jobject parent = env->CallObjectMethod(curr, getParentMid);
                    if (env->ExceptionCheck()) { env->ExceptionClear(); break; }
                    if (parent && env->IsInstanceOf(parent, viewCls)) {
                        jboolean pClickable = env->CallBooleanMethod(parent, isClickableMid);
                        jobject pLi = mListenerInfoFid ? env->GetObjectField(parent, mListenerInfoFid) : nullptr;
                        jobject pL = (pLi && liOnClickFid) ? env->GetObjectField(pLi, liOnClickFid) : nullptr;
                        bool isTarget = (pClickable != 0) || (pL != nullptr);
                        if (pL) env->DeleteLocalRef(pL);
                        if (pLi) env->DeleteLocalRef(pLi);
                        if (isTarget) {
                            env->DeleteLocalRef(target);
                            target = parent;
                            env->DeleteLocalRef(curr);
                            break;
                        }
                        env->DeleteLocalRef(curr);
                        curr = parent;
                    } else {
                        if (parent) env->DeleteLocalRef(parent);
                        env->DeleteLocalRef(curr);
                        break;
                    }
                }
            }

            out.targetView = target;
            jclass tCls = env->GetObjectClass(target);
            out.className = JavaClassName(env, tCls);
            size_t lastDot = out.className.find_last_of('.');
            out.simpleName = (lastDot != std::string::npos) ? out.className.substr(lastDot + 1) : out.className;
            env->DeleteLocalRef(tCls);

            int tId = env->CallIntMethod(target, getIdMid);
            if (tId > 0 && tId != -1 && getResMid && getEntryNameMid) {
                jobject res = env->CallObjectMethod(target, getResMid);
                if (res) {
                    jstring nameJ = (jstring) env->CallObjectMethod(res, getEntryNameMid, tId);
                    if (nameJ) {
                        const char* s = env->GetStringUTFChars(nameJ, nullptr);
                        if (s) { out.idName = std::string("id/") + s; env->ReleaseStringUTFChars(nameJ, s); }
                        env->DeleteLocalRef(nameJ);
                    }
                    env->DeleteLocalRef(res);
                }
            }

            if (textViewCls && env->IsInstanceOf(target, textViewCls) && getTextMid) {
                jobject cs = env->CallObjectMethod(target, getTextMid);
                if (cs && csToStringMid) {
                    jstring ts = (jstring) env->CallObjectMethod(cs, csToStringMid);
                    if (ts) {
                        const char* s = env->GetStringUTFChars(ts, nullptr);
                        if (s) { out.text = s; env->ReleaseStringUTFChars(ts, s); }
                        env->DeleteLocalRef(ts);
                    }
                    env->DeleteLocalRef(cs);
                }
            }

            env->CallVoidMethod(target, getLocMid, locArr);
            jint locBuf[2] = {0, 0};
            env->GetIntArrayRegion(locArr, 0, 2, locBuf);
            int tw = env->CallIntMethod(target, getWidthMid);
            int th = env->CallIntMethod(target, getHeightMid);
            out.left = locBuf[0];
            out.top = locBuf[1];
            out.right = out.left + tw;
            out.bottom = out.top + th;
            out.cx = out.left + tw / 2;
            out.cy = out.top + th / 2;

            env->DeleteLocalRef(hit);
        }
        env->DeleteLocalRef(root);
    }

    if (locArr) env->DeleteLocalRef(locArr);
    if (liCls) env->DeleteLocalRef(liCls);
    if (charSeqCls) env->DeleteLocalRef(charSeqCls);
    if (resCls) env->DeleteLocalRef(resCls);
    if (textViewCls) env->DeleteLocalRef(textViewCls);
    if (viewGroupCls) env->DeleteLocalRef(viewGroupCls);
    if (viewCls) env->DeleteLocalRef(viewCls);
    if (listCls) env->DeleteLocalRef(listCls);
    env->DeleteLocalRef(mViews);

    return found;
}

static jobject GetCurrentActivity(JNIEnv* env) {
    jobject mViews = GetWindowManagerViews(env);
    if (!mViews) return nullptr;

    jclass listCls = env->FindClass("java/util/List");
    jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
    jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
    int numRoots = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
    if (env->ExceptionCheck()) { env->ExceptionClear(); numRoots = 0; }

    jclass viewCls = env->FindClass("android/view/View");
    jmethodID getContextMid = viewCls ? env->GetMethodID(viewCls, "getContext", "()Landroid/content/Context;") : nullptr;
    jclass activityCls = env->FindClass("android/app/Activity");
    jclass wrapperCls = env->FindClass("android/view/ContextThemeWrapper");
    jmethodID getBaseMid = wrapperCls ? env->GetMethodID(wrapperCls, "getBaseContext", "()Landroid/content/Context;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jobject resultAct = nullptr;
    for (int i = numRoots - 1; i >= 0 && !resultAct; i--) {
        jobject root = env->CallObjectMethod(mViews, getMid, i);
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!root) continue;
        if (getContextMid) {
            jobject ctx = env->CallObjectMethod(root, getContextMid);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (ctx) {
                if (activityCls && env->IsInstanceOf(ctx, activityCls)) {
                    resultAct = ctx;
                } else if (wrapperCls && env->IsInstanceOf(ctx, wrapperCls) && getBaseMid) {
                    jobject base = env->CallObjectMethod(ctx, getBaseMid);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (base && activityCls && env->IsInstanceOf(base, activityCls)) {
                        resultAct = base;
                    }
                    if (base && base != resultAct) env->DeleteLocalRef(base);
                }
                if (ctx != resultAct) env->DeleteLocalRef(ctx);
            }
        }
        env->DeleteLocalRef(root);
    }

    if (wrapperCls) env->DeleteLocalRef(wrapperCls);
    if (activityCls) env->DeleteLocalRef(activityCls);
    if (viewCls) env->DeleteLocalRef(viewCls);
    if (listCls) env->DeleteLocalRef(listCls);
    env->DeleteLocalRef(mViews);
    return resultAct;
}

static JSValue JsUiDumpViews(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    JNIEnv* env = GetEnv();
    if (!env) return JS_UNDEFINED;

    UiFilterOptions opt = ParseUiFilterOptions(ctx, argc, argv);

    jobject mViews = GetWindowManagerViews(env);
    if (!mViews) return JS_NewString(ctx, "[-] Failed to obtain WindowManagerGlobal.mViews");

    jclass listCls = env->FindClass("java/util/List");
    jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
    jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
    int numRoots = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
    if (env->ExceptionCheck()) { env->ExceptionClear(); numRoots = 0; }

    jclass viewCls = env->FindClass("android/view/View");
    jclass viewGroupCls = env->FindClass("android/view/ViewGroup");
    jclass textViewCls = env->FindClass("android/widget/TextView");
    jclass resCls = env->FindClass("android/content/res/Resources");
    jclass charSeqCls = env->FindClass("java/lang/CharSequence");
    jclass liCls = env->FindClass("android/view/View$ListenerInfo");

    jmethodID getIdMid = viewCls ? env->GetMethodID(viewCls, "getId", "()I") : nullptr;
    jmethodID getVisMid = viewCls ? env->GetMethodID(viewCls, "getVisibility", "()I") : nullptr;
    jmethodID isClickableMid = viewCls ? env->GetMethodID(viewCls, "isClickable", "()Z") : nullptr;
    jmethodID isEnabledMid = viewCls ? env->GetMethodID(viewCls, "isEnabled", "()Z") : nullptr;
    jmethodID getWidthMid = viewCls ? env->GetMethodID(viewCls, "getWidth", "()I") : nullptr;
    jmethodID getHeightMid = viewCls ? env->GetMethodID(viewCls, "getHeight", "()I") : nullptr;
    jmethodID getLocMid = viewCls ? env->GetMethodID(viewCls, "getLocationOnScreen", "([I)V") : nullptr;
    jmethodID getResMid = viewCls ? env->GetMethodID(viewCls, "getResources", "()Landroid/content/res/Resources;") : nullptr;
    jmethodID getEntryNameMid = resCls ? env->GetMethodID(resCls, "getResourceEntryName", "(I)Ljava/lang/String;") : nullptr;
    jmethodID getContentDescMid = viewCls ? env->GetMethodID(viewCls, "getContentDescription", "()Ljava/lang/CharSequence;") : nullptr;
    jfieldID mListenerInfoFid = viewCls ? env->GetFieldID(viewCls, "mListenerInfo", "Landroid/view/View$ListenerInfo;") : nullptr;

    jmethodID getChildCountMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildCount", "()I") : nullptr;
    jmethodID getChildAtMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildAt", "(I)Landroid/view/View;") : nullptr;

    jmethodID getTextMid = textViewCls ? env->GetMethodID(textViewCls, "getText", "()Ljava/lang/CharSequence;") : nullptr;
    jmethodID csToStringMid = charSeqCls ? env->GetMethodID(charSeqCls, "toString", "()Ljava/lang/String;") : nullptr;
    jfieldID liOnClickFid = liCls ? env->GetFieldID(liCls, "mOnClickListener", "Landroid/view/View$OnClickListener;") : nullptr;
    jfieldID liOnLongClickFid = liCls ? env->GetFieldID(liCls, "mOnLongClickListener", "Landroid/view/View$OnLongClickListener;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jintArray locArr = env->NewIntArray(2);

    std::ostringstream ss;
    ss << "=== Active Window View Tree (" << numRoots << " window(s))";
    if (opt.hasFilter()) {
        ss << " [Filter: \"" << (opt.pattern.empty() ? (opt.text.empty() ? opt.id : opt.text) : opt.pattern) << "\"]";
    }
    ss << " ===\n";

    bool anyMatched = false;
    for (int i = 0; i < numRoots; i++) {
        jobject root = env->CallObjectMethod(mViews, getMid, i);
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!root) continue;

        ViewNode rootNode;
        TraverseViewTree(env, root, 0, rootNode,
                         viewCls, viewGroupCls, textViewCls, resCls,
                         getIdMid, getVisMid, isClickableMid, isEnabledMid,
                         getWidthMid, getHeightMid, getLocMid, getResMid, getEntryNameMid,
                         getContentDescMid, mListenerInfoFid, liCls, liOnClickFid, liOnLongClickFid,
                         getChildCountMid, getChildAtMid, getTextMid,
                         csToStringMid, locArr, false);

        if (!opt.hasFilter() || NodeMatchesFilter(rootNode, opt) || HasMatchingDescendant(rootNode, opt)) {
            anyMatched = true;
            ss << "[Window " << i << "] ";
            FormatViewTree(rootNode, "", true, ss, opt);
        }
        env->DeleteLocalRef(root);
    }

    if (locArr) env->DeleteLocalRef(locArr);
    if (liCls) env->DeleteLocalRef(liCls);
    if (charSeqCls) env->DeleteLocalRef(charSeqCls);
    if (resCls) env->DeleteLocalRef(resCls);
    if (textViewCls) env->DeleteLocalRef(textViewCls);
    if (viewGroupCls) env->DeleteLocalRef(viewGroupCls);
    if (viewCls) env->DeleteLocalRef(viewCls);
    if (listCls) env->DeleteLocalRef(listCls);
    env->DeleteLocalRef(mViews);

    if (opt.hasFilter() && !anyMatched) {
        std::string msg = "[-] No views found matching filter: \"" +
                          (opt.pattern.empty() ? (opt.text.empty() ? opt.id : opt.text) : opt.pattern) + "\"\n";
        return JS_NewString(ctx, msg.c_str());
    }

    return JS_NewString(ctx, ss.str().c_str());
}

static JSValue JsUiGetViews(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    JNIEnv* env = GetEnv();
    if (!env) return JS_NewArray(ctx);

    UiFilterOptions opt = ParseUiFilterOptions(ctx, argc, argv);

    jobject mViews = GetWindowManagerViews(env);
    if (!mViews) return JS_NewArray(ctx);

    jclass listCls = env->FindClass("java/util/List");
    jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
    jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
    int numRoots = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
    if (env->ExceptionCheck()) { env->ExceptionClear(); numRoots = 0; }

    jclass viewCls = env->FindClass("android/view/View");
    jclass viewGroupCls = env->FindClass("android/view/ViewGroup");
    jclass textViewCls = env->FindClass("android/widget/TextView");
    jclass resCls = env->FindClass("android/content/res/Resources");
    jclass charSeqCls = env->FindClass("java/lang/CharSequence");
    jclass liCls = env->FindClass("android/view/View$ListenerInfo");

    jmethodID getIdMid = viewCls ? env->GetMethodID(viewCls, "getId", "()I") : nullptr;
    jmethodID getVisMid = viewCls ? env->GetMethodID(viewCls, "getVisibility", "()I") : nullptr;
    jmethodID isClickableMid = viewCls ? env->GetMethodID(viewCls, "isClickable", "()Z") : nullptr;
    jmethodID isEnabledMid = viewCls ? env->GetMethodID(viewCls, "isEnabled", "()Z") : nullptr;
    jmethodID getWidthMid = viewCls ? env->GetMethodID(viewCls, "getWidth", "()I") : nullptr;
    jmethodID getHeightMid = viewCls ? env->GetMethodID(viewCls, "getHeight", "()I") : nullptr;
    jmethodID getLocMid = viewCls ? env->GetMethodID(viewCls, "getLocationOnScreen", "([I)V") : nullptr;
    jmethodID getResMid = viewCls ? env->GetMethodID(viewCls, "getResources", "()Landroid/content/res/Resources;") : nullptr;
    jmethodID getEntryNameMid = resCls ? env->GetMethodID(resCls, "getResourceEntryName", "(I)Ljava/lang/String;") : nullptr;
    jmethodID getContentDescMid = viewCls ? env->GetMethodID(viewCls, "getContentDescription", "()Ljava/lang/CharSequence;") : nullptr;
    jfieldID mListenerInfoFid = viewCls ? env->GetFieldID(viewCls, "mListenerInfo", "Landroid/view/View$ListenerInfo;") : nullptr;

    jmethodID getChildCountMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildCount", "()I") : nullptr;
    jmethodID getChildAtMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildAt", "(I)Landroid/view/View;") : nullptr;

    jmethodID getTextMid = textViewCls ? env->GetMethodID(textViewCls, "getText", "()Ljava/lang/CharSequence;") : nullptr;
    jmethodID csToStringMid = charSeqCls ? env->GetMethodID(charSeqCls, "toString", "()Ljava/lang/String;") : nullptr;
    jfieldID liOnClickFid = liCls ? env->GetFieldID(liCls, "mOnClickListener", "Landroid/view/View$OnClickListener;") : nullptr;
    jfieldID liOnLongClickFid = liCls ? env->GetFieldID(liCls, "mOnLongClickListener", "Landroid/view/View$OnLongClickListener;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jintArray locArr = env->NewIntArray(2);
    JSValue arr = JS_NewArray(ctx);
    uint32_t outIdx = 0;

    for (int i = 0; i < numRoots; i++) {
        jobject root = env->CallObjectMethod(mViews, getMid, i);
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!root) continue;

        ViewNode rootNode;
        TraverseViewTree(env, root, 0, rootNode,
                         viewCls, viewGroupCls, textViewCls, resCls,
                         getIdMid, getVisMid, isClickableMid, isEnabledMid,
                         getWidthMid, getHeightMid, getLocMid, getResMid, getEntryNameMid,
                         getContentDescMid, mListenerInfoFid, liCls, liOnClickFid, liOnLongClickFid,
                         getChildCountMid, getChildAtMid, getTextMid,
                         csToStringMid, locArr, true);

        FlattenViewNodes(env, ctx, rootNode, opt, arr, outIdx);
        FreeViewNodeTree(env, rootNode);
        env->DeleteLocalRef(root);
    }

    if (locArr) env->DeleteLocalRef(locArr);
    if (liCls) env->DeleteLocalRef(liCls);
    if (charSeqCls) env->DeleteLocalRef(charSeqCls);
    if (resCls) env->DeleteLocalRef(resCls);
    if (textViewCls) env->DeleteLocalRef(textViewCls);
    if (viewGroupCls) env->DeleteLocalRef(viewGroupCls);
    if (viewCls) env->DeleteLocalRef(viewCls);
    if (listCls) env->DeleteLocalRef(listCls);
    env->DeleteLocalRef(mViews);

    return arr;
}

static JSValue JsUiClick(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: UI.click(x, y) | UI.click('textOrId') | UI.click(viewNode)");
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    // Case 1: Coordinate click UI.click(x, y)
    if (argc >= 2 && JS_IsNumber(argv[0]) && JS_IsNumber(argv[1])) {
        int x = 0, y = 0;
        JS_ToInt32(ctx, &x, argv[0]);
        JS_ToInt32(ctx, &y, argv[1]);

        HitViewResult hit;
        bool found = FindHitViewAt(env, x, y, hit);
        if (found) {
            bool touchDispatched = DispatchTouchEventPair(env, hit.decorView, static_cast<float>(x), static_cast<float>(y));

            jclass vCls = env->GetObjectClass(hit.targetView);
            jmethodID callOnClickMid = env->GetMethodID(vCls, "callOnClick", "()Z");
            jmethodID performClickMid = env->GetMethodID(vCls, "performClick", "()Z");
            if (env->ExceptionCheck()) env->ExceptionClear();

            jboolean clicked = JNI_FALSE;
            if (callOnClickMid) {
                clicked = env->CallBooleanMethod(hit.targetView, callOnClickMid);
                if (env->ExceptionCheck()) env->ExceptionClear();
            }
            if (!clicked && performClickMid) {
                clicked = env->CallBooleanMethod(hit.targetView, performClickMid);
                if (env->ExceptionCheck()) env->ExceptionClear();
            }
            env->DeleteLocalRef(vCls);
            env->DeleteLocalRef(hit.targetView);
            env->DeleteLocalRef(hit.decorView);

            char outBuf[256];
            std::string idPart = hit.idName.empty() ? "" : (" (" + hit.idName + ")");
            std::string txtPart = hit.text.empty() ? "" : (" \"" + hit.text + "\"");
            snprintf(outBuf, sizeof(outBuf),
                     "[+] Clicked %s%s%s at (%d, %d) [bounds: %d,%d,%d,%d | clickTriggered=%s, touchDispatched=%s]",
                     hit.simpleName.c_str(), idPart.c_str(), txtPart.c_str(), x, y,
                     hit.left, hit.top, hit.right, hit.bottom,
                     clicked ? "true" : "false", touchDispatched ? "true" : "false");
            return JS_NewString(ctx, outBuf);
        } else {
            jobject mViews = GetWindowManagerViews(env);
            if (mViews) {
                jclass listCls = env->FindClass("java/util/List");
                jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
                jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
                int count = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
                if (count > 0 && getMid) {
                    jobject topRoot = env->CallObjectMethod(mViews, getMid, count - 1);
                    if (topRoot) {
                        DispatchTouchEventPair(env, topRoot, static_cast<float>(x), static_cast<float>(y));
                        env->DeleteLocalRef(topRoot);
                    }
                }
                if (listCls) env->DeleteLocalRef(listCls);
                env->DeleteLocalRef(mViews);
            }
            char outBuf[128];
            snprintf(outBuf, sizeof(outBuf), "[+] Dispatched MotionEvent at (%d, %d) [no view hit]", x, y);
            return JS_NewString(ctx, outBuf);
        }
    }

    // Case 2: String pattern click UI.click("SIGTRAP") or UI.click("id/btn_test")
    if (argc == 1 && JS_IsString(argv[0])) {
        const char* pat = JS_ToCString(ctx, argv[0]);
        if (!pat) return JS_FALSE;
        std::string patternStr = pat;
        JS_FreeCString(ctx, pat);

        JSValue viewsArr = JsUiGetViews(ctx, JS_UNDEFINED, argc, argv);
        int len = 0;
        JSValue lenVal = JS_GetPropertyStr(ctx, viewsArr, "length");
        if (JS_IsNumber(lenVal)) JS_ToInt32(ctx, &len, lenVal);
        JS_FreeValue(ctx, lenVal);

        if (len <= 0) {
            JS_FreeValue(ctx, viewsArr);
            std::string err = "[-] No view found matching \"" + patternStr + "\" to click";
            return JS_NewString(ctx, err.c_str());
        }

        int targetIdx = 0;
        for (int i = 0; i < len; i++) {
            JSValue item = JS_GetPropertyUint32(ctx, viewsArr, i);
            JSValue clkVal = JS_GetPropertyStr(ctx, item, "clickable");
            bool isClk = JS_ToBool(ctx, clkVal);
            JS_FreeValue(ctx, clkVal);
            JS_FreeValue(ctx, item);
            if (isClk) { targetIdx = i; break; }
        }

        JSValue targetItem = JS_GetPropertyUint32(ctx, viewsArr, targetIdx);
        JS_FreeValue(ctx, viewsArr);

        JSValue clickFn = JS_GetPropertyStr(ctx, targetItem, "click");
        JSValue retVal = JS_UNDEFINED;
        if (JS_IsFunction(ctx, clickFn)) {
            retVal = JS_Call(ctx, clickFn, targetItem, 0, nullptr);
        }
        JS_FreeValue(ctx, clickFn);
        JS_FreeValue(ctx, targetItem);
        return retVal;
    }

    // Case 3: UI.click(viewNode) or UI.click(viewJRef)
    JSValue targetVal = argv[0];
    bool needFreeTarget = false;
    int cx = -1, cy = -1;
    if (JS_IsObject(targetVal)) {
        JSValue boundsVal = JS_GetPropertyStr(ctx, targetVal, "bounds");
        if (JS_IsObject(boundsVal)) {
            JSValue cxVal = JS_GetPropertyStr(ctx, boundsVal, "cx");
            JSValue cyVal = JS_GetPropertyStr(ctx, boundsVal, "cy");
            if (JS_IsNumber(cxVal)) JS_ToInt32(ctx, &cx, cxVal);
            if (JS_IsNumber(cyVal)) JS_ToInt32(ctx, &cy, cyVal);
            JS_FreeValue(ctx, cxVal);
            JS_FreeValue(ctx, cyVal);
        }
        JS_FreeValue(ctx, boundsVal);

        JSValue vVal = JS_GetPropertyStr(ctx, targetVal, "view");
        if (JS_IsObject(vVal)) {
            targetVal = vVal;
            needFreeTarget = true;
        } else {
            JS_FreeValue(ctx, vVal);
        }
    }

    int h = ExtractJRefHandle(ctx, targetVal);
    if (needFreeTarget) JS_FreeValue(ctx, targetVal);

    if (h < 0) {
        return JS_ThrowTypeError(ctx, "Argument must be coordinates (x, y), string pattern, or View object");
    }

    jobject obj = GetJRef(h);
    if (!obj) return JS_FALSE;

    if (cx >= 0 && cy >= 0) {
        HitViewResult hit;
        if (FindHitViewAt(env, cx, cy, hit)) {
            DispatchTouchEventPair(env, hit.decorView, static_cast<float>(cx), static_cast<float>(cy));
            if (hit.targetView) env->DeleteLocalRef(hit.targetView);
            if (hit.decorView) env->DeleteLocalRef(hit.decorView);
        }
    }

    jclass viewCls = env->GetObjectClass(obj);
    jmethodID callOnClickMid = env->GetMethodID(viewCls, "callOnClick", "()Z");
    jmethodID performClickMid = env->GetMethodID(viewCls, "performClick", "()Z");
    if (env->ExceptionCheck()) env->ExceptionClear();

    jboolean clicked = JNI_FALSE;
    if (callOnClickMid) {
        clicked = env->CallBooleanMethod(obj, callOnClickMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (!clicked && performClickMid) {
        clicked = env->CallBooleanMethod(obj, performClickMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    env->DeleteLocalRef(viewCls);

    return JS_NewBool(ctx, clicked != 0);
}

static JSValue JsUiLongClick(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: UI.longClick(view) | UI.longClick(x, y) | UI.longClick('text')");
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    if (argc >= 2 && JS_IsNumber(argv[0]) && JS_IsNumber(argv[1])) {
        int x = 0, y = 0;
        JS_ToInt32(ctx, &x, argv[0]);
        JS_ToInt32(ctx, &y, argv[1]);

        HitViewResult hit;
        if (FindHitViewAt(env, x, y, hit)) {
            jclass vCls = env->GetObjectClass(hit.targetView);
            jmethodID longClickMid = env->GetMethodID(vCls, "performLongClick", "()Z");
            if (env->ExceptionCheck()) env->ExceptionClear();
            jboolean done = longClickMid ? env->CallBooleanMethod(hit.targetView, longClickMid) : JNI_FALSE;
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(vCls);
            env->DeleteLocalRef(hit.targetView);
            env->DeleteLocalRef(hit.decorView);

            char outBuf[128];
            snprintf(outBuf, sizeof(outBuf), "[+] LongClicked %s at (%d, %d) [result=%s]",
                     hit.simpleName.c_str(), x, y, done ? "true" : "false");
            return JS_NewString(ctx, outBuf);
        }
        return JS_NewString(ctx, "[-] No view found at coordinates for longClick");
    }

    if (argc == 1 && JS_IsString(argv[0])) {
        JSValue viewsArr = JsUiGetViews(ctx, JS_UNDEFINED, argc, argv);
        int len = 0;
        JSValue lenVal = JS_GetPropertyStr(ctx, viewsArr, "length");
        if (JS_IsNumber(lenVal)) JS_ToInt32(ctx, &len, lenVal);
        JS_FreeValue(ctx, lenVal);

        if (len <= 0) {
            JS_FreeValue(ctx, viewsArr);
            return JS_NewString(ctx, "[-] No view found matching pattern for longClick");
        }

        JSValue targetItem = JS_GetPropertyUint32(ctx, viewsArr, 0);
        JS_FreeValue(ctx, viewsArr);
        JSValue lclkFn = JS_GetPropertyStr(ctx, targetItem, "longClick");
        JSValue retVal = JS_UNDEFINED;
        if (JS_IsFunction(ctx, lclkFn)) {
            retVal = JS_Call(ctx, lclkFn, targetItem, 0, nullptr);
        }
        JS_FreeValue(ctx, lclkFn);
        JS_FreeValue(ctx, targetItem);
        return retVal;
    }

    JSValue targetVal = argv[0];
    bool needFreeTarget = false;
    if (JS_IsObject(targetVal)) {
        JSValue vVal = JS_GetPropertyStr(ctx, targetVal, "view");
        if (JS_IsObject(vVal)) { targetVal = vVal; needFreeTarget = true; }
        else { JS_FreeValue(ctx, vVal); }
    }

    int h = ExtractJRefHandle(ctx, targetVal);
    if (needFreeTarget) JS_FreeValue(ctx, targetVal);
    if (h < 0) return JS_ThrowTypeError(ctx, "Invalid View target for longClick");

    jobject obj = GetJRef(h);
    if (!obj) return JS_FALSE;

    jclass vCls = env->GetObjectClass(obj);
    jmethodID longClickMid = env->GetMethodID(vCls, "performLongClick", "()Z");
    if (env->ExceptionCheck()) env->ExceptionClear();
    jboolean done = longClickMid ? env->CallBooleanMethod(obj, longClickMid) : JNI_FALSE;
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(vCls);
    return JS_NewBool(ctx, done != 0);
}

static JSValue JsUiSwipe(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 4) return JS_NewString(ctx, "Usage: UI.swipe(x1, y1, x2, y2, [durationMs])");
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    int x1 = 0, y1 = 0, x2 = 0, y2 = 0, durationMs = 250;
    JS_ToInt32(ctx, &x1, argv[0]);
    JS_ToInt32(ctx, &y1, argv[1]);
    JS_ToInt32(ctx, &x2, argv[2]);
    JS_ToInt32(ctx, &y2, argv[3]);
    if (argc >= 5 && JS_IsNumber(argv[4])) JS_ToInt32(ctx, &durationMs, argv[4]);

    jobject mViews = GetWindowManagerViews(env);
    if (!mViews) return JS_NewString(ctx, "[-] Failed to obtain active window for swipe");

    jclass listCls = env->FindClass("java/util/List");
    jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
    jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
    int numRoots = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
    if (numRoots <= 0 || !getMid) {
        if (listCls) env->DeleteLocalRef(listCls);
        env->DeleteLocalRef(mViews);
        return JS_NewString(ctx, "[-] No active root view found for swipe");
    }

    jobject topRoot = env->CallObjectMethod(mViews, getMid, numRoots - 1);
    bool ok = false;
    if (topRoot) {
        ok = DispatchTouchSequence(env, topRoot, static_cast<float>(x1), static_cast<float>(y1),
                                   static_cast<float>(x2), static_cast<float>(y2), durationMs);
        env->DeleteLocalRef(topRoot);
    }

    if (listCls) env->DeleteLocalRef(listCls);
    env->DeleteLocalRef(mViews);

    char outBuf[128];
    snprintf(outBuf, sizeof(outBuf), "[+] Swiped (%d, %d) -> (%d, %d) over %dms [result=%s]",
             x1, y1, x2, y2, durationMs, ok ? "true" : "false");
    return JS_NewString(ctx, outBuf);
}

static JSValue JsUiSetText(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_NewString(ctx, "Usage: UI.setText(viewOrSelector, 'newText')");
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    const char* textStr = JS_ToCString(ctx, argv[1]);
    if (!textStr) return JS_FALSE;
    std::string newText = textStr;
    JS_FreeCString(ctx, textStr);

    jobject targetView = nullptr;
    bool needDeleteTarget = false;

    if (JS_IsString(argv[0])) {
        JSValue viewsArr = JsUiGetViews(ctx, JS_UNDEFINED, 1, argv);
        int len = 0;
        JSValue lenVal = JS_GetPropertyStr(ctx, viewsArr, "length");
        if (JS_IsNumber(lenVal)) JS_ToInt32(ctx, &len, lenVal);
        JS_FreeValue(ctx, lenVal);
        if (len > 0) {
            JSValue item = JS_GetPropertyUint32(ctx, viewsArr, 0);
            JSValue vVal = JS_GetPropertyStr(ctx, item, "view");
            int h = ExtractJRefHandle(ctx, vVal);
            if (h >= 0) targetView = GetJRef(h);
            JS_FreeValue(ctx, vVal);
            JS_FreeValue(ctx, item);
        }
        JS_FreeValue(ctx, viewsArr);
    } else {
        JSValue targetVal = argv[0];
        bool needFreeTarget = false;
        if (JS_IsObject(targetVal)) {
            JSValue vVal = JS_GetPropertyStr(ctx, targetVal, "view");
            if (JS_IsObject(vVal)) { targetVal = vVal; needFreeTarget = true; }
            else { JS_FreeValue(ctx, vVal); }
        }
        int h = ExtractJRefHandle(ctx, targetVal);
        if (needFreeTarget) JS_FreeValue(ctx, targetVal);
        if (h >= 0) targetView = GetJRef(h);
    }

    if (!targetView) {
        return JS_NewString(ctx, "[-] No target view found to setText");
    }

    jclass textViewCls = env->FindClass("android/widget/TextView");
    if (!textViewCls || !env->IsInstanceOf(targetView, textViewCls)) {
        if (textViewCls) env->DeleteLocalRef(textViewCls);
        return JS_NewString(ctx, "[-] Target view is not an instance of TextView/EditText");
    }

    jmethodID setTextMid = env->GetMethodID(textViewCls, "setText", "(Ljava/lang/CharSequence;)V");
    if (setTextMid) {
        jstring js = env->NewStringUTF(newText.c_str());
        env->CallVoidMethod(targetView, setTextMid, js);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(js);
    }
    env->DeleteLocalRef(textViewCls);
    if (needDeleteTarget) env->DeleteLocalRef(targetView);

    return JS_NewString(ctx, "[+] setText completed");
}

static JSValue JsUiCurrentActivity(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    JNIEnv* env = GetEnv();
    if (!env) return JS_NULL;

    jobject act = GetCurrentActivity(env);
    if (!act) return JS_NULL;

    void* artObj = PineNative_ToArtObject(env, act);
    uint64_t addr = artObj ? reinterpret_cast<uintptr_t>(artObj) : reinterpret_cast<uintptr_t>(act);
    DoRegisterObservedObject(env, addr, act);
    int h = AddJRef(env, act, addr, /*persistent=*/true);
    env->DeleteLocalRef(act);
    return CreateJRefValue(ctx, h);
}

static JSValue JsUiPressBack(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    jobject act = GetCurrentActivity(env);
    if (!act) return JS_NewString(ctx, "[-] No foreground Activity found to trigger back");

    jclass actCls = env->GetObjectClass(act);
    jmethodID backMid = env->GetMethodID(actCls, "onBackPressed", "()V");
    if (backMid) {
        env->CallVoidMethod(act, backMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    std::string actName = JavaClassName(env, actCls);
    env->DeleteLocalRef(actCls);
    env->DeleteLocalRef(act);

    std::string msg = "[+] Triggered onBackPressed() on " + actName;
    return JS_NewString(ctx, msg.c_str());
}

static JSValue JsUiHelp(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    const char* kHelp =
        "=== ArtPI UI Automation & Inspection APIs ===\n"
        "• UI.dump([filter])                 - Print formatted UI hierarchy tree (prunes non-matching nodes)\n"
        "• UI.find(patternOrObj)             - Search views by text, idName, className, clickable\n"
        "• UI.views([patternOrObj])          - Alias for UI.find()\n"
        "• UI.click(view | 'text' | x, y)    - Click a view, text label, or screen coordinates\n"
        "• UI.longClick(view | 'text' | x, y)- Long-press a view, text, or coordinates\n"
        "• UI.swipe(x1, y1, x2, y2, [ms])   - Smooth swipe gesture between two points\n"
        "• UI.setText(view | 'id', 'text')   - Set text on EditText or TextView\n"
        "• UI.currentActivity()              - Get current foreground Activity (JRef)\n"
        "• UI.pressBack()                    - Trigger Activity back button\n"
        "==============================================";
    return JS_NewString(ctx, kHelp);
}
