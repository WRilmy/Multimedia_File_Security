package org.example.multimedia_file_security.config;

import io.minio.MinioClient;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 适配 Spring Boot 的 MinIO 配置类
 * 1. 自动绑定 application.yml 中 minio 前缀的配置
 * 2. 生成由 Spring 管理的 MinioClient Bean，可直接 @Resource 注入
 */
@Configuration // 标记为 Spring 配置类，触发扫描
@ConfigurationProperties(prefix = "minio") // 绑定 yml 中 minio 节点的所有配置
@Data // 自动生成 get/set/无参构造，满足 Spring 配置绑定要求（无需手动写 get/set）
public class MinioConfig {
    // 与 application.yml 中 minio 配置项一一对应，Spring 自动注入值
    private String url;
    private String username;
    private String password;
    private String bucketName;

    /**
     * 核心：添加 @Bean 注解 → 让 Spring 管理 MinioClient 实例
     * Spring 会在「配置属性绑定完成后」执行该方法，确保 url/username/password 非空
     * 后续项目中可直接 @Resource 注入 MinioClient 使用
     */
    @Bean
    public MinioClient minioClient() {
        return MinioClient.builder()
                .endpoint(this.url) // 使用 Spring 自动绑定的 MinIO 服务地址
                .credentials(this.username, this.password) // 使用 Spring 自动绑定的凭证
                .build();
    }
}