package com.ddu.home.jwt;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

	@Value("${jwt.secret}")
	private String secret;
	
	@Value("${jwt.expiration}")
	private Long expiration;
	
	 private SecretKey getSigningKey() {
	        // Base64 인코딩된 secret 문자열을 byte[]로 변환
	        byte[] keyBytes = Decoders.BASE64.decode(secret);
	        return Keys.hmacShaKeyFor(keyBytes);
	    }
	
	// 토큰 생성
	public String generate(String username) {
		return Jwts.builder()
				.setSubject(username) // 인증받을 사용자의 이름
				.setIssuedAt(new Date()) // 토큰이 발급된 시간
				.setExpiration(new Date(System.currentTimeMillis() + expiration)) // 토큰 만료시간
				.signWith(getSigningKey(),SignatureAlgorithm.HS256)
				.compact();
}
	// 토큰에서 사용자 이름 추출(username) -> 로그인 후 받은 JWT를 검증 -> 누구(username)의 토큰인지 확인
	public String extractUsername(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(getSigningKey())
				.build()// 서명이 맞는지 검증용 비밀키 설정
				.parseClaimsJws(token) // 토큰 문자열 분석 -> 서명 맞는지 검증
				.getBody() // payload 부분 가져옴
				.getSubject(); // 사용자 이름(username) 추출
	}
}
