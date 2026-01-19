package org.example.multimedia_file_security.controller;

import cn.hutool.jwt.JWT;
import lombok.extern.slf4j.Slf4j;
import org.example.multimedia_file_security.dto.Result;
import org.example.multimedia_file_security.dto.UserLogin;
import org.example.multimedia_file_security.dto.UserRegister;
import org.example.multimedia_file_security.pojo.User;
import org.example.multimedia_file_security.service.UserService;
import org.example.multimedia_file_security.utils.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
public class UserController {
    @Autowired
    private UserService userService;

    /**
     * 用户登录
     * @param user
     * @return Result
     */
    @PostMapping("/login")
    public Result login(@RequestBody UserLogin user) {
        User e = userService.login(user);

        //登陆成功，生成令牌，下发令牌
        if(e != null){
            Map<String, Object> claims = new HashMap<>();
            claims.put("id",e.getId());
            claims.put("username",e.getUsername());
            String jwt = JWTUtil.generateJwt(claims);
            return Result.success(jwt);

        }

        //登录失败，返回错误信息
        else return Result.error(500,"用户名或密码错误");
    }

    /**
     * 用户注册
     * @param user
     * @return Result
     */
    @PostMapping("/register")
    public Result register(@RequestBody UserRegister user) {
        if (userService.selectByUsername(user.getUsername()) != null){
            return Result.error(500,"用户名已存在");
        }
        userService.register(user);
        return Result.success();
    }
}
