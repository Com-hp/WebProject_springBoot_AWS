package com.webproj.spring.aws.config.auth;

import com.webproj.spring.aws.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
                .csrf().disable()
                .headers().frameOptions().disable()//h2-console 화면 사용을 위한 해당 옵션 disable
                .and()
                    //URL별 권한 관리 설정옵션 시작점 > antMatchers 옵션 전 필수
                    .authorizeRequests()
                    //권한 관리 대상 지정 / URL,HTTP  메소드 별로 관리 가능
                    .antMatchers("/", "/css/**", "/images/**", "/js/**", "/h2-console/**").permitAll()//전체 열람 권한부여
                    .antMatchers("/api/v1/**").hasRole(Role.USER.name())//USER권한 가진 사람만 가능
                    //설정값 외의 나머지 URL
                    .anyRequest().authenticated()
                .and()
                    .logout()
                        .logoutSuccessUrl("/")
                .and()
                    .oauth2Login()//oauth2 로그인 기능 설정 진입점
                        .userInfoEndpoint()//로그인 성공 이후 설정
                            .userService(customOAuth2UserService);//소셜 로그인 성공시 후속 조치할 구현체 등록
    }
}
