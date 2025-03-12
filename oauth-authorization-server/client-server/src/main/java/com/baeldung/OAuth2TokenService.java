package com.baeldung;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class OAuth2TokenService {
    private static final Logger log = LoggerFactory.getLogger(OAuth2TokenService.class);
    private final RestTemplate restTemplate = new RestTemplate();

    public String getAccessToken(String authorizationCode) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", "sso-dashboard-client");
        params.add("client_secret", "secret");
        params.add("redirect_uri", "http://localhost:8080/login/oauth2/code/sso-dashboard-client");
        params.add("code", authorizationCode);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:9000/oauth2/token",
                HttpMethod.POST,
                request,
                Map.class
        );

        String accessToken = response.getBody().get("access_token").toString();

        log.info("ACCESS TOKEN TAKEN "+ accessToken);

        return accessToken;
    }

    public String getIdToken(String authorizationCode) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", "sso-dashboard-client");
        params.add("client_secret", "secret");
        params.add("redirect_uri", "http://localhost:8080/login/oauth2/code/sso-dashboard-client");
        params.add("code", authorizationCode);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:9000/oauth2/token",
                HttpMethod.POST,
                request,
                Map.class
        );

        String accessToken = response.getBody().get("id_token").toString();

        log.info("ID TOKEN TAKEN "+ accessToken);

        return accessToken;
    }
}
