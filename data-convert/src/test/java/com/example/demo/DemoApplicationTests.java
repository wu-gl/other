package com.example.demo;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import org.junit.Assert;

@SpringBootTest
class DemoApplicationTests {

    @Test
    void contextLoads() {
        int c10 = -5;

        //5
        //00000101
        //11111010
        //11111001
        //10000110          -6

        //-5
        //10000101
        //10000100
        //01111011
        //00000100  4


        System.out.println(~c10);
    }
}
