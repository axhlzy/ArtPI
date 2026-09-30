// UI inspection & interaction APIs
JSValue ui = JS_NewObject(ctx);
JS_SetPropertyStr(ctx, ui, "dump", JS_NewCFunction(ctx, JsUiDumpViews, "dump", 1));
JS_SetPropertyStr(ctx, ui, "views", JS_NewCFunction(ctx, JsUiGetViews, "views", 1));
JS_SetPropertyStr(ctx, ui, "find", JS_NewCFunction(ctx, JsUiGetViews, "find", 1));
JS_SetPropertyStr(ctx, ui, "click", JS_NewCFunction(ctx, JsUiClick, "click", 2));
JS_SetPropertyStr(ctx, ui, "longClick", JS_NewCFunction(ctx, JsUiLongClick, "longClick", 2));
JS_SetPropertyStr(ctx, ui, "swipe", JS_NewCFunction(ctx, JsUiSwipe, "swipe", 5));
JS_SetPropertyStr(ctx, ui, "setText", JS_NewCFunction(ctx, JsUiSetText, "setText", 2));
JS_SetPropertyStr(ctx, ui, "currentActivity", JS_NewCFunction(ctx, JsUiCurrentActivity, "currentActivity", 0));
JS_SetPropertyStr(ctx, ui, "topActivity", JS_NewCFunction(ctx, JsUiCurrentActivity, "topActivity", 0));
JS_SetPropertyStr(ctx, ui, "pressBack", JS_NewCFunction(ctx, JsUiPressBack, "pressBack", 0));
JS_SetPropertyStr(ctx, ui, "help", JS_NewCFunction(ctx, JsUiHelp, "help", 0));

JS_SetPropertyStr(ctx, global, "UI", ui);
JS_SetPropertyStr(ctx, global, "ui", JS_DupValue(ctx, ui));
JS_SetPropertyStr(ctx, global, "dumpViews", JS_NewCFunction(ctx, JsUiDumpViews, "dumpViews", 1));
JS_SetPropertyStr(ctx, global, "dumpviews", JS_NewCFunction(ctx, JsUiDumpViews, "dumpviews", 1));
JS_SetPropertyStr(ctx, global, "findViews", JS_NewCFunction(ctx, JsUiGetViews, "findViews", 1));
JS_SetPropertyStr(ctx, global, "findviews", JS_NewCFunction(ctx, JsUiGetViews, "findviews", 1));
JS_SetPropertyStr(ctx, global, "click", JS_NewCFunction(ctx, JsUiClick, "click", 2));
JS_SetPropertyStr(ctx, global, "swipe", JS_NewCFunction(ctx, JsUiSwipe, "swipe", 5));
JS_SetPropertyStr(ctx, global, "currentActivity", JS_NewCFunction(ctx, JsUiCurrentActivity, "currentActivity", 0));
JS_SetPropertyStr(ctx, global, "pressBack", JS_NewCFunction(ctx, JsUiPressBack, "pressBack", 0));
