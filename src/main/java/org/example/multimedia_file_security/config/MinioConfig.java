package org.example.multimedia_file_security.config;

import io.minio.MinioClient;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "minio")
@Data
public class MinioConfig {
    private String url;
    private String username;
    private String password;
    private String bucketName;

    @Bean
    public MinioClient minioClient() {
        return MinioClient.builder()
                .endpoint(this.url)
                .credentials(this.username, this.password)
                .build();
    }
}
