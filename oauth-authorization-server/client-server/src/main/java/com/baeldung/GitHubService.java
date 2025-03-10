package com.baeldung;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

@Service
public class GitHubService {

    private final OAuth2AuthorizedClientService authorizedClientService;

    public GitHubService(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    public void printAccessToken(String username) {
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                "github", username);  // GitHub client adı ve kullanıcı adı ile authorized client'ı yükle

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        System.out.println("Access Token: " + accessToken.getTokenValue());
    }
}
