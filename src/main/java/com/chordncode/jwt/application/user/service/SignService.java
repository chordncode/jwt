package com.chordncode.jwt.application.user.service;

import com.chordncode.jwt.data.dto.SignInResultDto;
import com.chordncode.jwt.data.dto.SignUpResultDto;

public interface SignService {
    
    SignUpResultDto signUp(String id, String password, String name, String role);

    SignInResultDto signIn(String id, String password) throws RuntimeException;

}
