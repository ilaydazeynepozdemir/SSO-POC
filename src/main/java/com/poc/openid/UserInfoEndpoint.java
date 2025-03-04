package com.poc.openid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/oauth2/userinfo")
public class UserInfoEndpoint {

    @GetMapping
    public ResponseEntity<Map<String, String>> getUserInfo(Authentication authentication) {
        Map<String, String> userInfo = new HashMap<>();
        userInfo.put("sub", authentication.getName());
        userInfo.put("name", "John Doe");
        userInfo.put("email", "johndoe@example.com");
        return ResponseEntity.ok(userInfo);
    }
}
