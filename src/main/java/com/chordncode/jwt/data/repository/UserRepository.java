package com.chordncode.jwt.data.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.chordncode.jwt.data.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {

    User getByUid(String uid);
    
}
