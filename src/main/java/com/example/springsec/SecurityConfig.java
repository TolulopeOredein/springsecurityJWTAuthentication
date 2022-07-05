package com.example.springsec;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.springsec.jwt.JwtTokenFilter;
import com.example.springsec.user.UserRepository;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	@Autowired
	private UserRepository userRepo;
	@Autowired
	private JwtTokenFilter jwtTokenFilter;
	
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(username -> userRepo.findByEmail(username)
				.orElseThrow(() ->  new UsernameNotFoundException("user" + username + "not found"))
				);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	
	
	
	@Override @Bean
	protected AuthenticationManager authenticationManager() throws Exception {
		// TODO Auto-generated method stub
		return super.authenticationManager();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		
		http.exceptionHandling().authenticationEntryPoint(
			(request, response, ex)-> {
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
						ex.getMessage());
			}	);
		
		
		http.authorizeHttpRequests()
		.antMatchers("/api/v1/auth/login")
		.permitAll()
		.anyRequest()
		.authenticated();
		
		http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
	}
	

	

}
