package com.example.securityjwt_pratice.repository;

import com.example.securityjwt_pratice.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member,Long> {
    Member findByUsername(String username);
}
