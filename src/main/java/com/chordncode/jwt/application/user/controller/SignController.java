package com.chordncode.jwt.application.user.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.chordncode.jwt.application.user.service.SignService;
import com.chordncode.jwt.data.dto.SignInResultDto;
import com.chordncode.jwt.data.dto.SignUpResultDto;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/sign-api")
public class SignController {
    
    private final Logger LOGGER = LoggerFactory.getLogger(SignController.class);
    private final SignService signService;

    @PostMapping("/sign-in")
    public SignInResultDto signIn(@RequestParam String id, @RequestParam String password) throws RuntimeException{
        LOGGER.info("[signIn] 로그인을 시도하고 있습니다. id : {}, pw : ****", id);
        SignInResultDto signInResultDto = signService.signIn(id, password);

        if(signInResultDto.getCode() == 0){
            LOGGER.info("[signIn] 정상적으로 로그인되었습니다. id : {}, token : {}", id, signInResultDto.getToken());
        }

        return signInResultDto;
    }

    @PostMapping("/sign-up")
    public SignUpResultDto signUp(@RequestParam String id, @RequestParam String password, @RequestParam String name, @RequestParam String role){
        LOGGER.info("[signUp] 회원가입을 수행합니다. id : {}. password : ****, name : {}, role : {}", id, name, role);
        SignUpResultDto signUpResultDto = signService.signUp(id, password, name, role);

        LOGGER.info("[signUp] 회원가입을 완료했습니다. id : {}", id);
        return signUpResultDto;
    }

    @GetMapping("/exception")
    public void exceptionTest() throws RuntimeException{
        throw new RuntimeException("접근 금지");
    }

}
