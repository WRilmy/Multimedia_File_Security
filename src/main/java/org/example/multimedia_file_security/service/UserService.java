package org.example.multimedia_file_security.service;

import org.example.multimedia_file_security.dto.Result;
import org.example.multimedia_file_security.dto.UserLogin;
import org.example.multimedia_file_security.dto.UserRegister;
import org.example.multimedia_file_security.pojo.User;

public interface UserService {
    User login(UserLogin user);

    User selectByUsername(String username);

    Result register(UserRegister user);
}
