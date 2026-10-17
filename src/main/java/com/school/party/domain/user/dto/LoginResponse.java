package com.school.party.domain.user.dto;

import com.school.party.domain.user.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

/**
 * [로그인 성공 응답 DTO]
 */
@Getter
@Builder
@AllArgsConstructor
public class LoginResponse {
    private Long userId;
    private String schoolEmail;
    private Role role;
    private String accessToken;
}