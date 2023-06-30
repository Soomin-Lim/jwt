package com.cos.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password 전송하면(post)
// 이 필터가 동작함
// formLogin().disable() 했기 때문에 자동으로 작동하지 않기 때문에 직접 등록해야 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도함");

        // 1. username, password를 받아서
        // 2. 정상인지 로그인 시도. authenticationManager로 로그인 시도를 하면
        // PrincipalDetailsService가 호출되고 loadUserByUsername()이 자동 실행됨

        // 3. PrincipalDetails를 세션에 담고 -> 세션에 담지 않으면 권한 관리가 안 됨. 세션에 값이 있어야지 시큐리티가 권한 관리 가능
        // 4. JWT 토큰을 만들어서 응답해주면 됨
        return super.attemptAuthentication(request, response);
    }
}
