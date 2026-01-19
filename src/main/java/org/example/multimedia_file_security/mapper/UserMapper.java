package org.example.multimedia_file_security.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.example.multimedia_file_security.pojo.User;

@Mapper
public interface UserMapper extends BaseMapper<User> {
    @Select("select * from user where username = #{username}")
    User selectByUsername(String username);
}
