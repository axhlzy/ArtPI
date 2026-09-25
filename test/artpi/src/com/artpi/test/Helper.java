package com.artpi.test;

/** Nested call target used by the interpreter sandbox Mock test. */
public class Helper {

    public static boolean check(int x) {
        return x > 0;
    }

    public static int twice(int x) {
        return x * 2;
    }
}
