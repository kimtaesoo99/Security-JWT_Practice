package com.example.securityjwt_pratice.dto;

import lombok.Data;

@Data
public class LoginRequestDto {
    private String username;
    private String password;
}
