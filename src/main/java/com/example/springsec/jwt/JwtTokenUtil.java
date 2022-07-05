package com.example.springsec.jwt;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.example.springsec.user.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JwtTokenUtil {
	private static final long EXPIRY_DURATION = 24*60*60*1000;
	private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenUtil.class);
	
	@Value(value = "${app.jwt.secret}")
	private String secretKey;
	
	public String generateAccessToken(User user) {
		return Jwts.builder()
				.setSubject(user.getId() + "," + user.getEmail())
				.setIssuer("Tolulope")
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRY_DURATION))
				.signWith(SignatureAlgorithm.HS512, secretKey)
				.compact();
	}
	
	public boolean validateAccessToken(String token) {
		
		try {
			Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
			
			return true;
		}
		
		catch(ExpiredJwtException ex) {
			LOGGER.error("Token Expired", ex);
		}
		catch(IllegalArgumentException ex) {
			
			LOGGER.error("Token is null, empty or has only whitespace", ex);
		}
		catch(MalformedJwtException ex) {
			LOGGER.error("Invalid token", ex);
			
		}
		catch(UnsupportedJwtException ex) {
			LOGGER.error("Unsupported JWT", ex);
		}
		catch(SignatureException ex) {
			LOGGER.error("Signature Validation failed", ex);
		}
		
		return false;
	}
	
	public String getSubject(String token) {
	
		return parseClaims(token).getSubject();
	}
	 
	private Claims parseClaims(String token) {
		
		return Jwts.parser()
				.setSigningKey(secretKey)
				.parseClaimsJws(token)
				.getBody();
	}

}
