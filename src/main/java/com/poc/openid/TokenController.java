package com.poc.openid;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class TokenController {

    @PostMapping("/token")
    public Map<String, String> token(@RequestParam("code") String authorizationCode,
                                     @RequestParam("client_id") String clientId,
                                     @RequestParam("client_secret") String clientSecret,
                                     @RequestParam("redirect_uri") String redirectUri) {

        // Authorization code'u doğrulama ve token oluşturma işlemi yapılır
        // Burada basit bir token örneği döndürüyoruz.
        
        Map<String, String> tokenResponse = new HashMap<>();
        tokenResponse.put("access_token", "sample_access_token");
        tokenResponse.put("token_type", "bearer");
        tokenResponse.put("expires_in", "3600"); // token'ın geçerlilik süresi (saniye cinsinden)
        
        return tokenResponse;
    }
}
