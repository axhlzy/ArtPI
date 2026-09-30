// JRef field proxy: obj.field / obj.field = v  (backed by reflection)
JS_SetPropertyStr(ctx, global, "__native_jfget", JS_NewCFunction(ctx, JsJFieldGet, "__native_jfget", 2));
JS_SetPropertyStr(ctx, global, "__native_jfset", JS_NewCFunction(ctx, JsJFieldSet, "__native_jfset", 3));
JS_SetPropertyStr(ctx, global, "__native_jstr", JS_NewCFunction(ctx, JsJRefStr, "__native_jstr", 1));
JS_SetPropertyStr(ctx, global, "__native_jdump", JS_NewCFunction(ctx, JsJRefStr, "__native_jdump", 1));
JS_SetPropertyStr(ctx, global, "__native_jmethods", JS_NewCFunction(ctx, JsJMethods, "__native_jmethods", 1));
JS_SetPropertyStr(ctx, global, "__native_jfields", JS_NewCFunction(ctx, JsJFields, "__native_jfields", 1));
JS_SetPropertyStr(ctx, global, "__native_jcall", JS_NewCFunction(ctx, JsJCall, "__native_jcall", 2));
JS_SetPropertyStr(ctx, global, "__native_jarrlen", JS_NewCFunction(ctx, JsJArrayLen, "__native_jarrlen", 1));
JS_SetPropertyStr(ctx, global, "__native_jarrget", JS_NewCFunction(ctx, JsJArrayGet, "__native_jarrget", 2));
JS_SetPropertyStr(ctx, global, "__native_jarrset", JS_NewCFunction(ctx, JsJArraySet, "__native_jarrset", 3));
JS_SetPropertyStr(ctx, global, "__native_jmembers", JS_NewCFunction(ctx, JsJMembers, "__native_jmembers", 1));

const char* kJRefBoot =
    "(function(){"
    "  globalThis.__makeJRef = function(h){"
    "    return new Proxy({ __h: h }, {"
    "      get(t, p) {"
    "        if (p === '__h') return h;"
    "        if (p === 'toString' || p === 'valueOf' || p === '$dump' || p === 'dump') return function(){ return __native_jdump(h); };"
    "        if (p === '$methods' || p === 'methods') return function(){ return __native_jmethods(h); };"
    "        if (p === '$fields' || p === 'fields') return function(){ return __native_jfields(h); };"
    "        if (p === '$call' || p === '$invoke') return function(m, ...a){ return __native_jcall(h, m, ...a); };"
    "        if (p === 'length') { var L = __native_jarrlen(h); if (L >= 0) return L; try { var sz = __native_jcall(h, 'size'); if (typeof sz === 'number') return sz; } catch(e){} }"
    "        if (typeof p === 'string' && /^\\d+$/.test(p)) {"
    "          var v = __native_jarrget(h, +p); if (v !== undefined) return v;"
    "          try { var item = __native_jcall(h, 'get', +p); if (item !== undefined) return item; } catch(e){}"
    "        }"
    "        if (p === Symbol.iterator) {"
    "          return function*(){"
    "            var L = __native_jarrlen(h);"
    "            if (L >= 0) { for (var i = 0; i < L; i++) yield __native_jarrget(h, i); return; }"
    "            try { var sz = __native_jcall(h, 'size'); if (typeof sz === 'number') { for (var i = 0; i < sz; i++) yield __native_jcall(h, 'get', i); } } catch(e){}"
    "          };"
    "        }"
    "        if (typeof p === 'string' && p.charCodeAt(0) !== 95) {"
    "          var fv = __native_jfget(h, p);"
    "          if (fv !== undefined) return fv;"
    "          return function(...args){ return __native_jcall(h, p, ...args); };"
    "        }"
    "        return t[p];"
    "      },"
    "      set(t, p, v) {"
    "        if (typeof p === 'string' && /^\\d+$/.test(p)) { if (__native_jarrset(h, +p, v)) return true; }"
    "        if (typeof p === 'string' && p.charCodeAt(0) !== 95) { __native_jfset(h, p, v); return true; }"
    "        t[p] = v; return true;"
    "      }"
    "    });"
    "  };"
    "  globalThis.__getCompletions = function(expr){"
    "    try {"
    "      var val = eval(expr);"
    "      if (val === null || val === undefined) return [];"
    "      if (typeof val === 'object' && val !== null && val.__h !== undefined) {"
    "        return __native_jmembers(val.__h);"
    "      }"
    "      var s = {};"
    "      for (var o = val; o !== null && o !== Object.prototype; o = Object.getPrototypeOf(o)) {"
    "        var props = Object.getOwnPropertyNames(o);"
    "        for (var i = 0; i < props.length; i++) {"
    "          if (props[i].charCodeAt(0) !== 95) s[props[i]] = true;"
    "        }"
    "      }"
    "      return Object.keys(s).sort();"
    "    } catch(e) {"
    "      return [];"
    "    }"
    "  };"
    "})();";
JSValue jrefBoot = JS_Eval(ctx, kJRefBoot, strlen(kJRefBoot), "<jref_boot>", JS_EVAL_TYPE_GLOBAL);
if (JS_IsException(jrefBoot)) {
    JSValue exc = JS_GetException(ctx);
    const char* e = JS_ToCString(ctx, exc);
    PI_LOGE("JRef bootstrap failed: %s", e ? e : "?");
    if (e) JS_FreeCString(ctx, e);
    JS_FreeValue(ctx, exc);
}
JS_FreeValue(ctx, jrefBoot);
