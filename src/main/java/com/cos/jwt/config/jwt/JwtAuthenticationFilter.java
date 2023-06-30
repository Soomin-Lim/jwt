package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import java.util.Date;

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
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadByUsername() 함수가 실행됨
            // username만 필요함. 패스워드는 스프링이 DB 사용해서 알아서 처리해줌
            // 인증되면 authentication 반환 (DB에 있는 username과 password가 일치함)
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername()); // 값이 있다면 로그인이 정상적으로 되었다는 뜻

            // authentication 객체가 session 영역에 저장을 해야하고, 그 방법이 authentication을 리턴해주면 됨
            // 리턴 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 거임
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 단지 권한 처리 때문에 session에 넣어준다.
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    // attemptAuthentication() 실행 후 인증이 정상적으로 되었으면 이 함수가 실행됨
    // 4. JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 응답해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨: 인증 완료됨");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // HMAC
        String jwtToken = JWT.create()
                .withSubject("cos토큰") // 큰 의미 없음
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10))) // 현재 시간 + 10분
                .withClaim("id", principalDetails.getUser().getId()) // 비공개 클레임
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos")); // 서버만 아는 고유 값

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
