package com.school.party.domain.user.jwt; // JWT 관련 컴포넌트가 위치한 패키지 경로 지정

import com.school.party.domain.user.enums.Role; // 사용자 권한 구분 Enum 클래스 (STUDENT, ADMIN)
import io.jsonwebtoken.*; // JJWT 라이브러리의 劾심 파서 및 토큰 빌더 클래스 모음
import io.jsonwebtoken.security.Keys; // HMAC-SHA 암호화 서명 키 생성 유틸리티
import jakarta.annotation.PostConstruct; // 객체 생성 및 의존성 주입 완료 후 초기화 실행 지점 어노테이션
import org.springframework.beans.factory.annotation.Value; // application.properties 설정 파일의 환경변수 주입 어노테이션
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken; // Spring Security 전용 인증 토큰 구현체
import org.springframework.security.core.Authentication; // Spring Security 보안 컨텍스트 내 인증 정보 표준 인터페이스
import org.springframework.security.core.authority.SimpleGrantedAuthority; // 사용자 권한(Role) 부여 클래스
import org.springframework.security.core.userdetails.User; // Spring Security 기본 제공 UserDetails 구현체
import org.springframework.stereotype.Component; // 스프링 컨테이너에 단일 빈(Bean)으로 등록 및 관리

import javax.crypto.SecretKey; // HMAC-SHA 비밀키 객체 타입
import java.nio.charset.StandardCharsets; // 문자열 인코딩 표준 상수 (UTF-8)
import java.util.Collections; // 단일 권한 객체 리스트 생성을 위한 유틸리티
import java.util.Date; // JWT 토큰의 발급 시각 및 만료 일시 처리 클래스

/**
 * [JWT 토큰 유틸리티 컴포넌트]
 * JWT Access Token 발급, 서명 검증, 클레임 파싱 및 Spring Security SecurityContext 인가 객체 생성을 담당합니다.
 */
@Component // 스프링 컨테이너에 의해 자동으로 스캔되어 빈(Bean)으로 등록됨
public class JwtTokenProvider {

    // application.properties 내 jwt.secret 키 값을 주입받으며, 설정값이 없으면 기본 시크릿키 사용
    @Value("${jwt.secret:SYUTaxiDeliverySharingSecretKeyForJwtAuthentication2026!}")
    private String secretKeyString; // 문자열 비밀키

    private SecretKey secretKey; // HMAC-SHA 알고리즘 서명에 실제 적용할 암호화 SecretKey 객체

    // Access Token 유효 기한: 1시간 (1시간 = 60분 * 60초 * 1000밀리초 = 3,600,000ms)
    private static final long ACCESS_TOKEN_VALIDITY_IN_MILLISECONDS = 3600000L;

    /**
     * [시크릿키 초기화 메서드]
     * 컴포넌트 생성 및 설정값 주입이 완료된 직후 문자열 비밀키를 HMAC-SHA 전용 SecretKey 객체로 안전하게 변환합니다.
     */
    @PostConstruct
    protected void init() {
        this.secretKey = Keys.hmacShaKeyFor(secretKeyString.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * [Access Token 발급 메서드]
     * 사용자 고유 식별자 ID, 이메일, 권한(Role) 정보를 클레임(Claim)에 담아 HMAC-SHA 서명된 JWT 토큰을 반환합니다.
     *
     * @param userId 사용자 고유 식별자 PK
     * @param email 사용자 학교 이메일 주소
     * @param role 사용자 권한 (STUDENT, ADMIN)
     * @return 암호화 서명된 최종 JWT Access Token 문자열
     */
    public String createToken(Long userId, String email, Role role) {
        // 토큰 페이로드의 Subject(주체) 항목에 사용자 ID(PK) 등록
        Claims claims = Jwts.claims().subject(String.valueOf(userId)).build();

        Date now = new Date(); // 토큰 발급 일시 (현재 시각)
        Date validity = new Date(now.getTime() + ACCESS_TOKEN_VALIDITY_IN_MILLISECONDS); // 토큰 만료 일시 (현재 + 1시간)

        return Jwts.builder()
                .claims(claims) // 기본 페이로드(Subject) 추가
                .claim("email", email) // 커스텀 클레임: 이메일 정보 추가
                .claim("role", role.name()) // 커스텀 클레임: 권한 정보 (STUDENT / ADMIN) 추가
                .issuedAt(now) // 토큰 발급 시각 지정
                .expiration(validity) // 토큰 만료 시각 지정
                .signWith(secretKey) // HMAC-SHA 시크릿키로 서명 적용
                .compact(); // 최종 토큰 문자열 조립 및 반환
    }

    /**
     * [Spring Security Authentication 인가 객체 생성 메서드]
     * 검증된 JWT 토큰 내부에서 권한(Role)과 유저 ID를 추출하여 스프링 시큐리티 인가 처리용 Authentication 객체를 반환합니다.
     *
     * @param token 검증을 마친 JWT 토큰 문자열
     * @return SecurityContext에 저장할 Authentication 인증 객체
     */
    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token); // 토큰 데이터(Claims) 파싱
        String roleStr = claims.get("role", String.class); // 권한 문자열 추출
        String userId = claims.getSubject(); // 사용자 ID(PK) 추출

        // Spring Security 권한 체계에 맞추어 "ROLE_" 접두사 부여 (예: "ROLE_STUDENT", "ROLE_ADMIN")
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + roleStr);

        // Spring Security 기본 제공 UserDetails 객체 생성
        User principal = new User(userId, "", Collections.singletonList(authority));

        // SecurityContext 저장용 UsernamePasswordAuthenticationToken 객체 생성 및 반환
        return new UsernamePasswordAuthenticationToken(principal, token, Collections.singletonList(authority));
    }

    /**
     * [JWT 토큰 유효성 및 위변조/만료 검증 메서드]
     *
     * @param token 검증 대상 JWT 토큰 문자열
     * @return 서명이 유효하고 만료되지 않았으면 true, 그렇지 않으면 false
     */
    public boolean validateToken(String token) {
        try {
            // 시크릿키로 서명 검증 및 만료 시각 유효성 자동 체크
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return true; // 서명 및 만료 체크 통과 (정상 유효 토큰)
        } catch (JwtException | IllegalArgumentException e) {
            return false; // 위변조, 서명 불일치, 만료, 포맷 오류 등 유효하지 않은 토큰
        }
    }

    /**
     * [토큰 페이로드(Claims) 파싱 내부 메서드]
     * 토큰에서 데이터 클레임 페이로드 영역을 추출하여 반환합니다.
     */
    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload(); // 클레임 페이로드 객체 추출 및 반환
    }
}