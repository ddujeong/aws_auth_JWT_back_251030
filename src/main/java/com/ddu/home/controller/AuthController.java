package com.ddu.home.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ddu.home.entity.User;
import com.ddu.home.jwt.JwtUtil;
import com.ddu.home.repository.UserRepository;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
	
	@Autowired
	UserRepository userRepository;
	
	@Autowired
	PasswordEncoder encoder;
	
	@Autowired
	JwtUtil jwtUtil;
	
	@Autowired
	AuthenticationManager authenticationManager;
	
	@PostMapping("/signup")
	public Map<String, String> signup(@RequestBody Map<String, String> body) {
		System.out.println("signup 요청 " + body);
		String username = body.get("username");
		String password = body.get("password");
		User user = new User();
		user.setUsername(username);
		user.setPassword(encoder.encode(password));
		userRepository.save(user);
		
		return Map.of("message", "회원가입 성공");
	}
	@PostMapping("/login")
	public Map<String, String> login(@RequestBody Map<String, String> body ) {
		String username = body.get("username");
		String password = body.get("password");
		
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		String token = jwtUtil.generate(username);
		
		return Map.of("token", token);
		
	}
	@GetMapping("/me")
	public Map<String, String> me (@RequestHeader("Authorization") String authHeader) {
		String token = authHeader.replace("Bearer ", "");
		String username = jwtUtil.extractUsername(token);
		
		return Map.of("username", username);
	}

}
