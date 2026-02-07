package org.example.multimedia_file_security.pojo;


import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class User {

  /**
   * id
   */
  private long id;
  /**
   * 用户名
   */
  private String username;
  /**
   * 邮箱
   */
  private String email;
  /**
   * 密码
   */
  private String passwordHash;
  /**
   * SM2公钥
   */
  private String sm2PublicKey;
  /**
   * SM2私钥密文
   */
  private String encryptedSm2PrivateKey;
  /**
   * SM2私钥创建时间
   */
  private java.sql.Timestamp sm2KeyCreatedAt;
  /**
   * 角色
   */
  private String role;
  /**
   * 状态
   */
  private String status;
  /**
   * 最后登录时间
   */
  private java.sql.Timestamp lastLoginTime;
  /**
   * 创建时间
   */
  private java.sql.Timestamp createdAt;
  /**
   * 更新时间
   */
  private java.sql.Timestamp updatedAt;
}
