package com.baeldung;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/github-login")
public class GitHubLoginController {

    @GetMapping
    public ResponseEntity<Void> redirectToGitHub(OAuth2AuthorizedClientService authorizedClientService,
                                                 @AuthenticationPrincipal OAuth2User oauth2User) {
        // Kullanıcının kimlik doğrulama durumunu kontrol et
        if (oauth2User == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // GitHub OAuth URL'sine yönlendir
        String githubAuthUrl = "https://aeeb-176-240-136-21.ngrok-free.app/oauth2/authorization/github";
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(githubAuthUrl));

        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }
}
