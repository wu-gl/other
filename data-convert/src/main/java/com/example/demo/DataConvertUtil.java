package com.example.demo;

public class DataConvertUtil {

    public static String c2t8(String num) {
        return c10t8(c2t10(num));
    }

    public static int c2t10(String num) {
        return Integer.parseInt(num, 2);
    }

    public static String c2t16(String num) {
        return c10t16(c2t10(num));
    }

    public static String c8t2(String num) {
        return c10t2(c8t10(num));
    }

    public static int c8t10(String num) {
        return Integer.parseInt(num, 8);
    }

    public static String c8t16(String num) {
        return c10t16(c8t10(num));
    }

    public static String c10t2(int num) {
        return Integer.toBinaryString(num);
    }

    public static String c10t8(int num) {
        return Integer.toOctalString(num);
    }

    public static String c10t16(int num) {
        return Integer.toHexString(num);
    }

    public static String c16t2(String num) {
        return c10t2(c16t10(num));
    }

    public static String c16t8(String num) {
        return c10t8(c16t10(num));
    }

    public static int c16t10(String num) {
        return Integer.parseInt(num, 16);
    }
}

