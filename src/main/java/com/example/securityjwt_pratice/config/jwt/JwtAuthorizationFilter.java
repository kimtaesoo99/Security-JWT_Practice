package com.example.securityjwt_pratice.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.securityjwt_pratice.config.auth.PrincipalDetails;
import com.example.securityjwt_pratice.domain.Member;
import com.example.securityjwt_pratice.repository.MemberRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//시큐리티가 필터를 가지고있는데 그 필터중에 BaiscAuthentication필터 라는 것이 있음
//권한이나 인증이 필요한 특정 주소를요청했을때 위 필터를 타게됨
//만약 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탐
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private MemberRepository memberRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager
        , MemberRepository memberRepository) {
        super(authenticationManager);
        this.memberRepository = memberRepository;
    }

    //인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        String header = request.getHeader(JwtProperties.HEADER_STRING);

        //header가 있는지
        if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)){
            chain.doFilter(request,response);
            return;
        }
        //JWT토큰을 검증해서 정상적인 사용자인지 확인
        String token = request.getHeader(JwtProperties.HEADER_STRING)
            .replace(JwtProperties.TOKEN_PREFIX,"");

        //getClaim -> jwtAuthentication 에서 JWT토큰에 withClam한 username 값을 가져옴
        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
            .build().verify(token).getClaim("username").asString();

        //서명이 정성적으로 됨
        if (username != null){
            Member member = memberRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(member);
            //Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어 준다.
            Authentication authentication
                = new UsernamePasswordAuthenticationToken(principalDetails
                ,null,principalDetails.getAuthorities());

            //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
        chain.doFilter(request,response);
    }
}
