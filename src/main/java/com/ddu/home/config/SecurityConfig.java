package com.ddu.home.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import com.ddu.home.repository.UserRepository;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class SecurityConfig {

//	@Autowired
//	UserRepository userRepository;
	
	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
//	@Bean
//	public UserDetailsService detailsService () {
//		return username -> userRepository.findByUsername(username)
//				.map(user -> User.withUsername(user.getUsername())
//						.password(user.getPassword())
//						.build())
//				.orElseThrow(() -> new RuntimeException("User not found"));
//	}
	@Bean
	public SecurityFilterChain filterChain (HttpSecurity http) throws Exception {
		http.csrf(csrf -> csrf.disable())
		.authorizeHttpRequests(auth -> auth
				.requestMatchers("/api/auth/**").permitAll()
				.anyRequest().authenticated()) // 위요청 제외 나머지 요청들은 전부 인증 필요
		.formLogin(form -> form
				.loginProcessingUrl("/api/auth/login")
				.defaultSuccessUrl("/api/auth/apicheck", true)
				.failureHandler((req, res, ex) -> res.setStatus(HttpServletResponse.SC_UNAUTHORIZED))
				.permitAll())
		.logout(logout -> logout
				.logoutUrl("/api/auth/logout")
				.permitAll())
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
}
