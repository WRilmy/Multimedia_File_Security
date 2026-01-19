package org.example.multimedia_file_security.pojo;


import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
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


  public long getId() {
    return id;
  }

  public void setId(long id) {
    this.id = id;
  }


  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }


  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }


  public String getPassword() {
    return passwordHash;
  }

  public void setPassword(String passwordHash) {
    this.passwordHash = passwordHash;
  }


  public String getSm2PublicKey() {
    return sm2PublicKey;
  }

  public void setSm2PublicKey(String sm2PublicKey) {
    this.sm2PublicKey = sm2PublicKey;
  }


  public String getEncryptedSm2PrivateKey() {
    return encryptedSm2PrivateKey;
  }

  public void setEncryptedSm2PrivateKey(String encryptedSm2PrivateKey) {
    this.encryptedSm2PrivateKey = encryptedSm2PrivateKey;
  }


  public java.sql.Timestamp getSm2KeyCreatedAt() {
    return sm2KeyCreatedAt;
  }

  public void setSm2KeyCreatedAt(java.sql.Timestamp sm2KeyCreatedAt) {
    this.sm2KeyCreatedAt = sm2KeyCreatedAt;
  }


  public String getRole() {
    return role;
  }

  public void setRole(String role) {
    this.role = role;
  }


  public String getStatus() {
    return status;
  }

  public void setStatus(String status) {
    this.status = status;
  }


  public java.sql.Timestamp getLastLoginTime() {
    return lastLoginTime;
  }

  public void setLastLoginTime(java.sql.Timestamp lastLoginTime) {
    this.lastLoginTime = lastLoginTime;
  }


  public java.sql.Timestamp getCreatedAt() {
    return createdAt;
  }

  public void setCreatedAt(java.sql.Timestamp createdAt) {
    this.createdAt = createdAt;
  }


  public java.sql.Timestamp getUpdatedAt() {
    return updatedAt;
  }

  public void setUpdatedAt(java.sql.Timestamp updatedAt) {
    this.updatedAt = updatedAt;
  }

}
