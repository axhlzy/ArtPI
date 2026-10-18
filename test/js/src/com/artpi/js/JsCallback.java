package com.artpi.js;

/** Interface implemented by a JS-side Java.registerClass() class. */
public interface JsCallback {
    void onValue(int v);

    String describe(String tag);
}
