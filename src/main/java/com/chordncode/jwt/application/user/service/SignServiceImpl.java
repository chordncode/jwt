package com.chordncode.jwt.application.user.service;

import java.util.Collections;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.chordncode.jwt.config.jwt.JwtTokenProvider;
import com.chordncode.jwt.data.dto.SignInResultDto;
import com.chordncode.jwt.data.dto.SignUpResultDto;
import com.chordncode.jwt.data.entity.User;
import com.chordncode.jwt.data.repository.UserRepository;
import com.chordncode.jwt.util.CommonResponse;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SignServiceImpl implements SignService {

    private final Logger LOGGER = LoggerFactory.getLogger(SignServiceImpl.class);

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    @Override
    public SignUpResultDto signUp(String id, String password, String name, String role) {
        LOGGER.info("[getSignUpResult] 회원 가입 정보 전달");
        User user;
        if(role.equals("admin")){
            user = User.builder()
                       .uid(id)
                       .name(name)
                       .password(passwordEncoder.encode(password))
                       .roles(Collections.singletonList("ROLE_ADMIN"))
                       .build();
        } else {
            user = User.builder()
                       .uid(id)
                       .name(name)
                       .password(passwordEncoder.encode(password))
                       .roles(Collections.singletonList("ROLE_USER"))
                       .build();
        }

        User savedUser = userRepository.save(user);
        SignUpResultDto signUpResultDto = new SignInResultDto();

        LOGGER.info("[getSignUpResult] userEntity 값이 들어왔는지 확인 후 결과값 주입");
        if(!savedUser.getName().isEmpty()){
            LOGGER.info("[getSignUpResult] 정상 처리 완료");
            setSuccessResult(signUpResultDto);
        } else {
            LOGGER.info("[getSignUpResult] 실패 처리 완료");
            setFailResult(signUpResultDto);
        }

        return signUpResultDto;
    }

    @Override
    public SignInResultDto signIn(String id, String password) throws RuntimeException {
        LOGGER.info("[getSignInResult] signDataHandler 로 회원 정보 요청");
        User user = userRepository.getByUid(id);
        LOGGER.info("[getSignInResult] Id : {}", id);

        LOGGER.info("[getSignInResult] 패스워드 비교 수행");
        if(!passwordEncoder.matches(password, user.getPassword())){
            throw new RuntimeException();
        }
        LOGGER.info("[getSignInResult] 패스워드 일치");

        LOGGER.info("[getSignInResult] SignInResultDto 객체 생성");
        SignInResultDto signInResultDto = SignInResultDto.builder().token(jwtTokenProvider.createToken(String.valueOf(user.getUid()), user.getRoles())).build();

        LOGGER.info("[getSignInResult] SignInResultDto 객체에 값 주입");
        setSuccessResult(signInResultDto);

        return signInResultDto;
    }
    

    private void setSuccessResult(SignUpResultDto result){
        result.setSuccess(true);
        result.setCode(CommonResponse.SUCCESS.getCode());
        result.setMsg(CommonResponse.SUCCESS.getMsg());
    }

    private void setFailResult(SignUpResultDto result){
        result.setSuccess(false);
        result.setCode(CommonResponse.FAIL.getCode());
        result.setMsg(CommonResponse.FAIL.getMsg());
    }
}
