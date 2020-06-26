package com.sxt.test;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
//@WebAppConfiguration
@ContextConfiguration(locations = {"classpath:applicationContext-spring.xml"})
public class ShiroRelamTest {

    @Autowired
    private SecurityManager securityManager;

    @Test
    public void test(){
//        1、使用SecurityUtils将securityManager设置到运行环境中
        SecurityUtils.setSecurityManager(securityManager);
//        2、使用SecurityUtils创建一个Subject实例，该实例认证要使用上边创建的securityManager进行
        Subject subject = SecurityUtils.getSubject();
//        3、创建token令牌，记录用户认证的身份和凭证即账号和密码
        UsernamePasswordToken token = new UsernamePasswordToken("test","123456");
//        4、用户登录
        subject.login(token);
        System.out.println(subject.isAuthenticated());
        boolean admin = subject.hasRole("admin");
        subject.checkPermissions("user:create");
    }
}
