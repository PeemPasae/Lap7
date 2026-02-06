package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((requests) -> requests
                // อนุญาตให้เข้าหน้า register และ login โดยไม่ต้องล็อกอิน
                .requestMatchers("/register", "/login", "/css/**", "/js/**").permitAll()
                // หน้าอื่นๆ ต้องล็อกอินก่อน
                .anyRequest().authenticated()
            )
            .formLogin((form) -> form
                .loginPage("/login") // กำหนด URL หน้า Login ของเราเอง
                .defaultSuccessUrl("/greet", true) // ล็อกอินสำเร็จไปหน้า greet
                .permitAll()
            )
            .logout((logout) -> logout
                .permitAll()
            );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // ใช้การเข้ารหัสแบบ BCrypt
    }
}