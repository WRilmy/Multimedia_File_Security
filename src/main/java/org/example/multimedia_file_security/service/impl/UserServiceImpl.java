package org.example.multimedia_file_security.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.example.multimedia_file_security.dto.Result;
import org.example.multimedia_file_security.dto.UserLogin;
import org.example.multimedia_file_security.dto.UserRegister;
import org.example.multimedia_file_security.mapper.UserMapper;
import org.example.multimedia_file_security.pojo.User;
import org.example.multimedia_file_security.service.UserService;
import org.example.multimedia_file_security.utils.AESUtil;
import org.example.multimedia_file_security.utils.BCryptPasswordUtil;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.LocalDateTime;

import static org.example.multimedia_file_security.utils.AESUtil.encryptPrivateKey;
import static org.example.multimedia_file_security.utils.Sm2Util.generateKeyPair;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserMapper userMapper;

    @Override
    public User login(UserLogin user) {
        User newUser = userMapper.selectByUsername(user.getUsername());
        if (BCryptPasswordUtil.verifyPassword(user.getPassword(),newUser.getPasswordHash())) {
            return newUser;
        }
        else return null;
    }

    @Override
    public User selectByUsername(String username) {
        return userMapper.selectByUsername(username);
    }

    @Transactional(rollbackFor = Exception.class)
    @Override
    public Result register(UserRegister userRegister) throws Exception {
        // 1. 基本参数校验
        if (!validateParams(userRegister)) {
            return Result.error(500,"参数不合法");
        }

        // 2. 唯一性校验
        if (!checkUnique(userRegister.getUsername(), userRegister.getEmail())) {
            return Result.error(500,"用户名或邮箱已存在");
        }

        // 3. 生成SM2秘钥对
        String[] keyPair = generateKeyPair();

        // 3. 密码和私钥加密（密码使用BCrypt，私钥使用AES）
        String encryptedPassword  = BCryptPasswordUtil.encryptPassword(userRegister.getPassword());
        String encryptedPrivateKey = encryptPrivateKey(keyPair[1]);

        // 4. 数据转换与填充
        User user = new User();
        BeanUtils.copyProperties(userRegister, user);
        user.setPasswordHash(encryptedPassword);
        user.setRole("USER"); // 默认角色
        user.setStatus("1"); // 默认状态：激活
        user.setSm2PublicKey(keyPair[0]);
        user.setEncryptedSm2PrivateKey(encryptedPrivateKey);
        user.setSm2KeyCreatedAt(Timestamp.valueOf(LocalDateTime.now()));
        user.setCreatedAt(Timestamp.valueOf(LocalDateTime.now()));
        user.setUpdatedAt(Timestamp.valueOf(LocalDateTime.now()));

        // 5. 写入数据库
        try {
            int result = userMapper.insert(user);
            if (result > 0) {
                // 6. 注册后处理（可选：发送欢迎邮件、初始化信息等）
                postRegisterProcess(user);
                return Result.success("注册成功");
            } else {
                return Result.error(500,"注册失败");
            }
        } catch (Exception e) {
            // 记录日志
            System.err.println("注册异常: " + e.getMessage());
            return Result.error(500,"系统异常，注册失败");
        }
    }

    /**
     * 参数校验
     */
    private boolean validateParams(UserRegister userRegister) {
        return StringUtils.hasText(userRegister.getUsername()) &&
                StringUtils.hasText(userRegister.getPassword()) &&
                StringUtils.hasText(userRegister.getEmail()) &&
                userRegister.getPassword().length() >= 6;
    }

    /**
     * 唯一性校验
     */
    private boolean checkUnique(String username, String email) {
        // 检查用户名是否唯一
        Long countByUsername = userMapper.selectCount(
                new QueryWrapper<User>().eq("username", username)
        );
        if (countByUsername > 0) {
            return false;
        }

        // 检查邮箱是否唯一
        Long countByEmail = userMapper.selectCount(
                new QueryWrapper<User>().eq("email", email)
        );
        return countByEmail <= 0;
    }

    /**
     * 注册后处理
     */
    private void postRegisterProcess(User user) {
        // 这里可以实现：发送欢迎邮件、初始化用户信息等
        System.out.println("用户注册成功，ID: " + user.getId());
    }
}
