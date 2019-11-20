package com.example.demo;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import org.junit.Assert;

@SpringBootTest
class DemoApplicationTests {

    @Test
    void contextLoads() {
        String c2 = "1010100";
        String c8 = "124";
        int c10 = 84;
        String c16 = "54";

        Assert.assertEquals("c2t8 不通过", c8, DataConvertUtil.c2t8(c2));
        Assert.assertEquals("c2t10 不通过", c10, DataConvertUtil.c2t10(c2));
        Assert.assertEquals("c2t16 不通过", c16, DataConvertUtil.c2t16(c2));
        Assert.assertEquals("c8t2 不通过", c2, DataConvertUtil.c8t2(c8));
        Assert.assertEquals("c8t10 不通过", c10, DataConvertUtil.c8t10(c8));
        Assert.assertEquals("c8t16 不通过", c16, DataConvertUtil.c8t16(c8));
        Assert.assertEquals("c10t2 不通过", c2, DataConvertUtil.c10t2(c10));
        Assert.assertEquals("c10t8 不通过", c8, DataConvertUtil.c10t8(c10));
        Assert.assertEquals("c10t16 不通过", c16, DataConvertUtil.c10t16(c10));
        Assert.assertEquals("c16t2 不通过", c2, DataConvertUtil.c16t2(c16));
        Assert.assertEquals("c16t8 不通过", c8, DataConvertUtil.c16t8(c16));
        Assert.assertEquals("c16t10 不通过", c10, DataConvertUtil.c16t10(c16));
    }
}
