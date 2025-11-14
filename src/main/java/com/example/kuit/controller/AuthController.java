package com.example.kuit.controller;
import com.example.kuit.dto.request.LoginRequest;
import com.example.kuit.dto.request.ReissueRequest;
import com.example.kuit.dto.response.LoginResponse;
import com.example.kuit.dto.response.ReissueResponse;
import com.example.kuit.jwt.JwtUtil;
import com.example.kuit.model.Role;
import com.example.kuit.model.TokenType;
import com.example.kuit.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {
    private final JwtUtil jwtUtil;
    private final AuthService authService;

    // POST /api/auth/login  - 로그인 API
    /**
     * 요청 형식
     1. 일반 유저 로그인
         {
            "username" : "member1",
            "password" : "pass1234"
         }

     2. 관리자 로그인
         {
         "username" : "admin1",
         "password" : "pass1234"
         }
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {

        // TODO: 로그인 성공시 RefreshToken 까지 발급해보기
        LoginResponse response = authService.login(request.username(), request.password());

        return ResponseEntity.ok(response);
    }

    // POST /api/auth/reissue  - 토큰 재발급 API
    /**
     * 요청 형식
        {
            "refreshToken": "<JWT_REFRESH_TOKEN>"
        }

        Bearer 접두사 붙일 필요 X
     */
    @PostMapping("/reissue")
    public ResponseEntity<ReissueResponse> reissue(@RequestBody ReissueRequest request) {
        // 토큰 유효성 검사 - jwtUtil.validate 메서드 활용
        String refreshToken = request.refreshToken();

        // 토큰 타입 검사 - jwtUtil.getTokenType 메서드 활용
        if (!jwtUtil.validate(refreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다.");
        }

        if (jwtUtil.getTokenType(refreshToken) != TokenType.REFRESH) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh Token이 필요합니다.");
        }

        String username = jwtUtil.getUsername(refreshToken);

        Role role = jwtUtil.getRole(refreshToken);

        // reissue API 완성 - Role.ROLE_USER 는 임시값이므로 토큰으로부터 추출해서 넘겨주어야합니다.
        ReissueResponse response = authService.reissue(username, role, refreshToken);


        return ResponseEntity.ok(response);
    }
}
