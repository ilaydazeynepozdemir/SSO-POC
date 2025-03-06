package com.baeldung;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Controller
public class GitHubController {
    @Value("${spring.security.oauth2.client.registration.github.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.github.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.github.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.registration.github.scope}")
    private String scope;

   @Autowired
   private OAuth2AuthorizedClientService authorizedClientService;


    @GetMapping("/home")
    public String home() {
        return "homeilayda";
    }

    @GetMapping("/")
    public String home2() {
        return "defaultilayda";
    }

    @GetMapping("/fail")
    public String fail() {
        return "faililayda";
    }

    @GetMapping("/error")
    public String error() {
        return "errorilayda";
    }

    /*@GetMapping("/login")
    public String login() {
        // Kullanıcıyı GitHub OAuth giriş sayfasına yönlendir
        return "redirect:https://github.com/login/oauth/authorize?client_id="+clientId+"&redirect_uri=http://localhost:8080/login/oauth2/code/github&scope=user";
    }*/


    //@GetMapping("/login/oauth2/code/github")
    /*public String callback(@RequestParam("code") String code, @RequestParam("state") String state) {
        // GitHub OAuth access token URL
        String tokenUrl = "https://github.com/login/oauth/access_token";

        // OAuth token exchange için gerekli parametreler
        String redirectUri = "http://localhost:8080/login/oauth2/code/github"; // redirect_uri

        // POST request için parametreler
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(tokenUrl)
                .queryParam("client_id", clientId)
                .queryParam("client_secret", clientSecret)
                .queryParam("code", code)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("grant_type", "authorization_code");

        // RestTemplate kullanarak POST isteği göndereceğiz
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<String> entity = new HttpEntity<>(null, headers);

        // Token exchange isteğini gönder
        ResponseEntity<String> response = restTemplate.exchange(
                builder.toUriString(),
                HttpMethod.POST,
                entity,
                String.class);

        // GitHub'dan dönen token'ı işleme
        String responseBody = response.getBody();
        // GitHub'dan gelen response örneği: access_token=your_access_token&scope=user&token_type=bearer

        String accessToken = extractAccessToken(responseBody);
        System.out.println(accessToken);

        return getGitHubUserInfo(accessToken);
    }*/


    public String getGitHubUserInfo(String accessToken) {
        String apiUrl = "https://api.github.com/user";

        // Authorization header ile access token'ı gönder
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(apiUrl, HttpMethod.GET, entity, String.class);

        // Kullanıcı bilgilerini işleme
        String userInfo = response.getBody();
        System.out.println("User Info: " + userInfo);
        return userInfo;
    }


    private String extractAccessToken(String responseBody) {
        // responseBody örneği: access_token=your_access_token&scope=user&token_type=bearer
        String[] params = responseBody.split("&");
        for (String param : params) {
            if (param.startsWith("access_token=")) {
                return param.substring("access_token=".length());
            }
        }
        return null;
    }




    @GetMapping("/github-token")
    public String getGitHubToken(@AuthenticationPrincipal OAuth2User principal) {
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                "github", principal.getName());

        if (authorizedClient != null) {
            return "Access Token: " + authorizedClient.getAccessToken().getTokenValue();
        }
        return "Token bulunamadı";
    }

    @GetMapping("/github-info")
    public ResponseEntity<String> getGithubInfo(@AuthenticationPrincipal OAuth2User principal, OAuth2AuthenticationToken authentication) {
        // OAuth2AuthenticationToken'dan OAuth2AuthorizedClient alıyoruz
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName()
        );

        // Access Token'ı alıyoruz
        String accessToken = authorizedClient.getAccessToken().getTokenValue();

        // GitHub kullanıcı bilgilerine erişim
        return ResponseEntity.ok("GitHub User Info: " + principal.getAttributes() + "\nAccess Token: " + accessToken);
    }

    @GetMapping("/redirect-github-profile")
    public void redirectToGithubProfile(@AuthenticationPrincipal OAuth2User principal, HttpServletResponse response) throws IOException, IOException {
        String githubUsername = (String) principal.getAttribute("login"); // GitHub kullanıcı adı
        if (githubUsername != null) {
            response.sendRedirect("https://github.com/" + githubUsername);
        } else {
            response.sendRedirect("https://github.com"); // Kullanıcı bilgisi alınamazsa genel GitHub sayfasına yönlendir
        }
    }


}
