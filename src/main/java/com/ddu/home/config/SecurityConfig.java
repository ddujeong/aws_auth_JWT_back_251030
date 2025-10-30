package com.ddu.home.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import com.ddu.home.jwt.JwtAuthenticationFilter;

@Configuration
public class SecurityConfig {

	@Autowired
	JwtAuthenticationFilter authenticationFilter;
	
	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public SecurityFilterChain filterChain (HttpSecurity http) throws Exception {
		http.csrf(csrf -> csrf.disable())
		.authorizeHttpRequests(auth -> auth
				.requestMatchers("/api/auth/**").permitAll()
				.anyRequest().authenticated()) // 위요청 제외 나머지 요청들은 전부 인증 필요
				.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
				// 로그인 하지 않고도 JWT 토큰만 존재하면 요청을 받게하는 설정 
		.cors(cors -> cors
				.configurationSource(
						request -> {
							CorsConfiguration config = new CorsConfiguration();
							config.setAllowCredentials(true);
							config.setAllowedOrigins(List.of("http://localhost:3000", "http://spring-cloudfront-s3.s3-website.ap-northeast-2.amazonaws.com"));
							config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
							config.setAllowedHeaders(List.of("*"));
							return config;
						}));
		return http.build();
	
	}
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
		// 사용자 인증을 처리하는 객체 반환
	}
}
