package com.baeldung;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuth2LoginController {

    @GetMapping("/")
    public String home(@AuthenticationPrincipal OAuth2User user) {
        if(user != null){
            return "Hello, " + user.getAttribute("name") + "! Your email is " + user.getAttribute("email");
        }
        return "Hello, stranger";
    }


    @GetMapping("/token")
    public ResponseEntity<String> getToken(
            @RegisteredOAuth2AuthorizedClient("sso-dashboard") OAuth2AuthorizedClient authorizedClient) {

        if (authorizedClient == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized: No OAuth2 Client Found");
        }

        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        return ResponseEntity.ok("Access Token: " + accessToken);
    }

    @GetMapping("/login")
    public String login() {
        return "redirect:/oauth2/authorization/sso-dashboard-client";
    }
}
