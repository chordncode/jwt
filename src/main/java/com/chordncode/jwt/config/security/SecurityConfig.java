package com.chordncode.jwt.config.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.chordncode.jwt.config.jwt.JwtAuthenticationFilter;
import com.chordncode.jwt.config.jwt.JwtTokenProvider;

@Configuration
public class SecurityConfig {
    
    private final JwtTokenProvider jwtTokenProvider;

    public SecurityConfig(JwtTokenProvider jwtTokenProvider){
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Bean
    public SecurityFilterChain filterChain (HttpSecurity http) throws Exception{
        return http.httpBasic(basic -> basic.disable())
                    .csrf(csrf -> csrf.disable())
                    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(request -> request.antMatchers("/sign-api/sign-in", "/sign-api/sign-up", "/sign-api/exception").permitAll()
                                                        .antMatchers(HttpMethod.GET, "/product/**").permitAll()
                                                        .antMatchers("**exception**").permitAll()
                                                        .anyRequest().hasRole("ADMIN"))
                    .exceptionHandling(handling -> handling.accessDeniedHandler(new AccessDeniedHandler() {
                                                                @Override
                                                                public void handle(HttpServletRequest request,
                                                                        HttpServletResponse response,
                                                                        AccessDeniedException accessDeniedException)
                                                                        throws IOException, ServletException {
                                                                            response.setStatus(403);
                                                                            response.setContentType("text/html; charset=utf-8");
                                                                            response.getWriter().print("Access Denied");
                                                                }
                                                            }))
                    .exceptionHandling(handling -> handling.authenticationEntryPoint(new AuthenticationEntryPoint() {
                                                                @Override
                                                                public void commence(HttpServletRequest request,
                                                                        HttpServletResponse response,
                                                                        AuthenticationException authException)
                                                                        throws IOException, ServletException {
                                                                            response.setStatus(401);
                                                                            response.setContentType("text/html; charset=utf-8");
                                                                            response.getWriter().print("Authentication Failed");
                                                                }
                                                            }))
                    .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
                    .build();
                }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


}
