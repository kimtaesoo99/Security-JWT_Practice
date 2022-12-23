package com.example.securityjwt_pratice.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.securityjwt_pratice.config.auth.PrincipalDetails;
import com.example.securityjwt_pratice.dto.LoginRequestDto;
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

//스프링 시큐리티에서 usernamePassword..filter가 있음
//login 요청해서 username,password를 전송하면 이 필터가 동작
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
    // 인증 요청시에 실행되는 함수 => /login
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException {

        //1.username, password받음
        ObjectMapper om = new ObjectMapper();
        LoginRequestDto loginRequestDto = new LoginRequestDto();
        try {
            loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 유저 아이디와 비밀번호로 토큰을 만듬
        UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword());

        // authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
        // loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
        // UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
        // UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
        // Authentication 객체를 만들어서 필터체인으로 리턴해준다.

        // Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
        // Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
        // 결론은 인증 프로바이더에게 알려줄 필요가 없음.

        //2. 정상인지 로그인 시도를함 -> principalDetailsService이 실행됨
        //authentication에 로그인한 정보가 담김
        //DB에 있는 username과 password가 일치한다는 것
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        //값을 확인 -> 로그인이 정상적을 되었다는 것
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println(principalDetails.getMember().getUsername());

        //3.authentication 객체가 세션 영역에 저장됨 -> 로그인됨
        // 리턴 이유는 권한관리를 시큐리티가 대신해주기 떼문이다.
        return authentication;
    }

    //attemptAuthentication이 실행 후 인증이 정상적으로 되었다면 successfulAuthentication 함수가 실행
    //JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해줌
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
            .withSubject(principalDetails.getUsername())
            .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
            .withClaim("id", principalDetails.getMember().getId())
            .withClaim("username", principalDetails.getMember().getUsername())
            .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);

    }
}
