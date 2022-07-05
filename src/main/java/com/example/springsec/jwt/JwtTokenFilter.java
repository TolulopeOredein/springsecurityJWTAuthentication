package com.example.springsec.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.springsec.user.User;

@Component
public class JwtTokenFilter extends OncePerRequestFilter{
	
	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		if(!hasAuthorizationHeader(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		
		String accessToken = getAccessToken(request);
		
		if(!jwtTokenUtil.validateAccessToken(accessToken)) {
			filterChain.doFilter(request, response);
			return;	
		
		}
		
		setAuthenticationContext(accessToken, request);
		filterChain.doFilter(request, response);
		
		System.out.println(accessToken);
	}
	
	 private void setAuthenticationContext(String token, HttpServletRequest request) {
	        UserDetails userDetails = getUserDetails(token);
	 
	        UsernamePasswordAuthenticationToken
	            authentication = new UsernamePasswordAuthenticationToken(userDetails, null, null);
	 
	        authentication.setDetails(
	                new WebAuthenticationDetailsSource().buildDetails(request));
	 
	        SecurityContextHolder.getContext().setAuthentication(authentication);
	    }

	private UserDetails getUserDetails(String accessToken) {
		
		User userDetails = new User();
		String[] subjectArray =jwtTokenUtil.getSubject(accessToken).split(",");
		userDetails.setId(Integer.parseInt(subjectArray[0]));
		userDetails.setEmail(subjectArray[1]);
		return userDetails;
	}

	private boolean hasAuthorizationHeader(HttpServletRequest request) {
		
		String header = request.getHeader("Authorization");
		System.out.println("Autjorization header:" + header);
		
		if(ObjectUtils.isEmpty(header) || !header.startsWith("Bearer"))
			return false;
		
		return true;
		
	}
	
	private String getAccessToken(HttpServletRequest request) {
		String header = request.getHeader("Authorization");
		String token = header.split(" ")[1].trim();
		System.out.println(token);
		return token;
		
	}

}
