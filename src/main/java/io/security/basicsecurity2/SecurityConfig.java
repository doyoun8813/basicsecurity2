package io.security.basicsecurity2;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    // 인메모리 방식 유저 설정
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests() // 보안 검사 기능 시작
            .antMatchers("/login").permitAll() // 로그인 페이지 누구나 접근 가능
            .antMatchers("/user").hasRole("USER")
            .antMatchers("/admin/pay").hasRole("ADMIN")
            .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
            .anyRequest().authenticated(); // 어떠한 요청이든 인증을 받아야 서버 내 자원 접근 가능
        http
            .formLogin() // form 로그인 인증방식 작동
            //.loginPage("/loginPage") // 시큐리티에서 제공하는 로그인 페이지가 아닌 커스텀 로그인 페이지 사용
            .defaultSuccessUrl("/") // 인증 성공시 루트 페이지로 이동
            .failureUrl("/login") // 인증 실패시 다시 로그인 페이지로 이동
            .usernameParameter("userId") // username으로 받을 필드 명
            .passwordParameter("passwd") // password로 받을 필드 명
            .loginProcessingUrl("/login_proc") // form 요소 action url
            // .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
            //     // 로그인 성공시 콘솔에 username 출력 후 루트 페이지로 이동
            //     System.out.println("authentication " + authentication.getName());
            //     httpServletResponse.sendRedirect("/");
            // })
            .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                // 인증 예외시 로그인 페이지로 이동하게 되는데 사용자가 로그인 페이지에서 로그인 성공하여 인증 처리 하면
                // 원래 가고자 했던 url 경로로 이동시키기 위해 요청 정보를 저장하고 있는 객체를 세션에서 불러와 페이지를 이동시킨다.
                RequestCache requestCache = new HttpSessionRequestCache(); // 세션에 저장한 객체 생성
                // 세션에 저장된 사용자 요청 정보 가져옴
                SavedRequest savedRequest = requestCache.getRequest(httpServletRequest, httpServletResponse);
                String redirectUrl = savedRequest.getRedirectUrl(); // 사용자가 원래 가고자 했던 경로 정보
                httpServletResponse.sendRedirect(redirectUrl); // 해당 경로로 이동

            })
            .failureHandler((httpServletRequest, httpServletResponse, e) -> {
                // 로그인 실패시 파라미터로 전달받은 인증예외 객체를 사용해 콘솔에 예외 메세지 출력 후 로그인 페이지로 이동
                System.out.println("exception " + e.getMessage());
                httpServletResponse.sendRedirect("/login");
            })
            .permitAll(); // 커스텀 로그인 페이지는 인증없이 접근 가능하게 설정
        http
            .logout() // 로그아웃 기능 작동
            .logoutUrl("/logout") // 로그아웃 form action url. post 방식만 지원
            .logoutSuccessUrl("/login") // 로그아웃 성공시 로그인 페이지로 이동
            .addLogoutHandler((httpServletRequest, httpServletResponse, authentication) -> {
                // 기본 핸들러 대신 로그아웃 처리할 핸들러 구현 세션 무효화
                HttpSession session = httpServletRequest.getSession();
                session.invalidate();
            })
            .logoutSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
                // 로그아웃 성공 후 처리할 핸들러 구현 로그인 페이지로 이동
                httpServletResponse.sendRedirect("/login");
            })
            .deleteCookies("remember-me") // 로그아웃 할 때 서버에서 만든 쿠키 삭제
        .and()
            .rememberMe() // rememberMe 기능 작동
            .rememberMeParameter("remember") // 체크박스 파라미터 명 기본 명은 remember-me
            .tokenValiditySeconds(3600) // 쿠키 만료 시간 설정(초) 기본 14일
            .alwaysRemember(false) // 사용자가 체크박스를 활성화하지 않아도 항상 실행 기본 false
            .userDetailsService(userDetailsService); // 사용자 정보 조회시 필요한 서비스 객체
        http
            .sessionManagement() // 세션 관리 기능이 작동함
            .invalidSessionUrl("/login?error") // 세션이 유효하지 않을 때 이동 할 페이지
            .sessionFixation().none() // 사용자 인증 성공시 기존 세션 ID를 그대로 사용한다. 공격에 취약
            .maximumSessions(1) // 최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용
            .maxSessionsPreventsLogin(false) // 동시 로그인 차단함, false : 기존 세션 만료(default)
            .expiredUrl("/login?error"); // 세션이 만료된 경우 이동 할 페이지
        http
            .exceptionHandling() // 예외처리 기능이 작동함
            // .authenticationEntryPoint((httpServletRequest, httpServletResponse, e) -> {
            //     // 인증예외 발생시 처리하는 인터페이스 구현 로그인 페이지 이동
            //     // 스프링 시큐리티 기본 제공 로그인 페이지가 아닌 커스텀한 로그인 페이지로 이동한다.
            //     httpServletResponse.sendRedirect("/login");
            // })
            .accessDeniedHandler((httpServletRequest, httpServletResponse, e) -> {
               // 인가예외 발생시 처리하는 인터페이스 구현 인가예외 페이지 이동
                httpServletResponse.sendRedirect("/denied");
            });
    }
}
