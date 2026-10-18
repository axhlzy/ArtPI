// Dual-path invocation test: the SAME ArtMethod* through
//   (a) ART/JNI        : MethodBox.invokeJni(...)  / Java.invoke(art,'jni',...)
//   (b) nmmvm          : MethodBox.invokeInterp(...) / Java.invoke(art,'interp',...)
//
// Covers static, direct (private / private static) and virtual (public instance)
// methods, plus String args / return values.
//
// Run: artpi-cli -S <pkg> -f /data/local/tmp/artpi_invoke_modes.js
(function () {
    var out = [];
    function chk(n, a, e) {
        var ok = String(a) === String(e);
        out.push((ok ? 'PASS ' : 'FAIL ') + n + ' = ' + a + (ok ? '' : '  (want ' + e + ')'));
    }

    var C = 'com.artpi.js.JsTarget';

    function mb(name, sig, clazz) {
        var art = findmethod(clazz || C, name, sig);
        if (!art) throw new Error('findmethod failed: ' + (clazz || C) + '.' + name + sig);
        return jmethodBox(art);
    }

    try {
        // Load the probe dex (contains com.artpi.js.JsTarget) into the app.
        var app = __native_jcall('android.app.ActivityThread', 'currentApplication');
        var dir = app.getCacheDir().getAbsolutePath();
        var D = Java.loadDex(dir + '/artpi_probe.dex', { name: 'probe' });
        out.push('loadDex injected=' + D.$injected);

        // ---------- 1. static method ----------
        var add = mb('add', '(II)I');
        chk('static.jni', add.invokeJni(20, 22), 42);
        chk('static.interp', add.invokeInterp(20, 22), 42);
        chk('static.legacyCall', add(20, 22), 42);          // m(...) == JNI
        chk('static.invokeAlias', add.invoke(20, 22), 42);  // .invoke == interp
        chk('static.explicitJni',
            Java.invoke(add.artMethod, 'jni', null, 20, 22), 42);
        chk('static.explicitInterp',
            Java.invoke(add.artMethod, 'interp', null, 20, 22), 42);

        // ---------- 2. direct methods (ACC_PRIVATE) ----------
        var hidden = mb('hiddenStatic', '(I)I');            // private static
        chk('directStatic.jni', hidden.invokeJni(6), 42);
        chk('directStatic.interp', hidden.invokeInterp(6), 42);

        // ---------- 3. virtual + private instance ----------
        var inst = __native_jcall(C, 'create');              // receiver
        out.push('receiver = ' + inst);

        var mul = mb('mul', '(II)I').bind(inst);             // public virtual
        chk('virtual.jni', mul.invokeJni(6, 7), 42);
        chk('virtual.interp', mul.invokeInterp(6, 7), 42);
        chk('virtual.call', mul.call(6, 7), 42);             // alias -> JNI
        chk('virtual.nmmvm', mul.nmmvm ? mul.nmmvm(6, 7) : 'n/a', 42);

        var secret = mb('secret', '(I)I').bind(inst);        // private direct
        chk('directInstance.jni', secret.invokeJni(13), 40);
        chk('directInstance.interp', secret.invokeInterp(13), 40);

        // ---------- 4. reference args / return ----------
        var greet = mb('greet', '(Ljava/lang/String;)Ljava/lang/String;');
        chk('string.jni', greet.invokeJni('artpi'), 'hi artpi');
        chk('string.interp', greet.invokeInterp('artpi'), 'hi artpi');

        // ---------- 5. both engines agree ----------
        chk('compare.static', add.invokeJni(3, 4) === add.invokeInterp(3, 4), true);
        chk('compare.virtual', mul.invokeJni(5, 9) === mul.invokeInterp(5, 9), true);
        chk('compare.private', secret.invokeJni(7) === secret.invokeInterp(7), true);

        // ---------- 6. error paths ----------
        try {
            add.invokeInterp(1);                  // wrong arity
            out.push('FAIL arity.notRejected');
        } catch (e) {
            out.push('PASS arity.rejected (' + String(e).split('\n')[0] + ')');
        }
        // A genuinely native method has no bytecode -> interp must reject it.
        var nat = mb('nadd', '(II)I', 'com.artpi.js.JsNativeTarget');
        try {
            nat.invokeInterp(1, 2);
            out.push('FAIL native.interpRejected');
        } catch (e) {
            out.push('PASS native.interpRejected (' + String(e).split('\n')[0] + ')');
        }
    } catch (e) {
        out.push('EXC ' + e);
    }

    out.push('DONE');
    return out.join('\n');
})();
