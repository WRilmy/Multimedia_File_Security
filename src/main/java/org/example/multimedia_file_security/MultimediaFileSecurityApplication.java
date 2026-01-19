package org.example.multimedia_file_security;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("org.example.multimedia_file_security.mapper")
public class MultimediaFileSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(MultimediaFileSecurityApplication.class, args);
    }

}
