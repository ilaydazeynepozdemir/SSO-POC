package com.poc.openid;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthorizationController {

    @GetMapping("/authorize")
    public String authorize(@RequestParam("client_id") String clientId,
                            @RequestParam("redirect_uri") String redirectUri,
                            @RequestParam("response_type") String responseType,
                            @RequestParam("scope") String scope,
                            @RequestParam("state") String state) {
        
        // Burada kullanıcı kimlik doğrulama işlemi yapılır
        // Örneğin, kullanıcı giriş yaptıktan sonra bir authorization code döndürülebilir.
        
        String authorizationCode = "sample_authorization_code";  // Örnek kod

        return "redirect:" + redirectUri + "?code=" + authorizationCode + "&state=" + state;
    }
}
