// Step-by-step probe for the DEX splice path. console.log is mirrored to
// logcat, so the last marker tells us where it hangs.
(function () {
    function mark(s) { console.log('[probe] ' + s); }

    mark('1 start');
    var G = Java.registerClass({
        name: 'com.artpi.probe.GenInj',
        methods: { ping: { returnType: 'java.lang.String', argumentTypes: [], static: true,
                           implementation: function () { return 'pong'; } } }
    });
    mark('2 registered injected=' + G.$injected);
    mark('3 ping=' + G.ping());

    mark('4 forName via app loader');
    var cls = __native_jcall('java.lang.Class', 'forName', 'com.artpi.probe.GenInj', true, G.$loader);
    mark('5 forName=' + cls.getName());

    mark('6 cacheDir');
    var app = __native_jcall('android.app.ActivityThread', 'currentApplication');
    var dir = app.getCacheDir().getAbsolutePath();
    mark('7 dir=' + dir);

    mark('8 loadDex');
    var D = Java.loadDex(dir + '/artpi_probe.dex', { name: 'probe' });
    mark('9 loadDex injected=' + D.$injected);

    mark('10 loadClass');
    var t = D.loadClass('com.artpi.js.JsTarget');
    mark('11 loadClass=' + t.getName());

    mark('12 call add');
    var v = __native_jcall('com.artpi.js.JsTarget', 'add', 20, 22);
    mark('13 add=' + v);

    mark('14 forName probe via app loader');
    var c2 = __native_jcall('java.lang.Class', 'forName', 'com.artpi.js.JsTarget', true, D.$loader);
    mark('15 forName=' + c2.getName());

    mark('16 isolated load');
    var I = Java.loadDex(dir + '/artpi_probe.dex', { name: 'isolated', inject: false });
    mark('17 isolated injected=' + I.$injected);

    mark('DONE');
    return 'ok';
})();
