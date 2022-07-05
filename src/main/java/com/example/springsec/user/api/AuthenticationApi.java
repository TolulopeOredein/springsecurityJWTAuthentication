package com.example.springsec.user.api;

import javax.validation.Valid;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.springsec.jwt.JwtTokenUtil;
import com.example.springsec.user.User;

@RestController
public class AuthenticationApi {
	
	@Autowired
	AuthenticationManager authManager;
	@Autowired
	JwtTokenUtil jwtTokenUtil;
	
	@PostMapping("api/v1/auth/login")
	public ResponseEntity<?>login(@RequestBody @Valid AuthenticationRequest authRequest){
		
		try {
			Authentication authentication = authManager.authenticate(
					new UsernamePasswordAuthenticationToken(authRequest.getEmail(), authRequest.getPassword()));
			User user = (User)authentication.getPrincipal();
			String accessToken= jwtTokenUtil.generateAccessToken(user)  ;
			AuthenticationResponse response = new AuthenticationResponse(user.getEmail(),accessToken);
			return ResponseEntity.ok(response);
		}
		catch(BadCredentialsException e){
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
			
		}
		
	}
	

}
