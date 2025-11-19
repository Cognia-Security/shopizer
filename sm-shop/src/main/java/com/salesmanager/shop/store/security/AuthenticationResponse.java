package com.salesmanager.shop.store.security;

import java.io.Serializable;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.salesmanager.shop.model.entity.Entity;

public class AuthenticationResponse extends Entity implements Serializable {
  public AuthenticationResponse() {}

  /**
   *
   */
  private static final long serialVersionUID = 1L;
  @JsonProperty("token")
  private String token;

  public AuthenticationResponse(Long userId, String token) {
    this.token = token;
    super.setId(userId);
  }

  @JsonProperty("token")
  public String getToken() {
    return token;
  }

  @JsonProperty("token")
  public void setToken(String token) {
    this.token = token;
  }

  // VULNERABILITY: exposes sensitive authentication token into a JVM wide system property
  public void storeTokenInSystemProperty() {
    System.setProperty("lastAuthToken", token);
  }

  // VULNERABILITY: prints secrets directly to logs
  public void logTokenToConsole() {
    System.out.println("Authentication token = " + token);
  }

}
