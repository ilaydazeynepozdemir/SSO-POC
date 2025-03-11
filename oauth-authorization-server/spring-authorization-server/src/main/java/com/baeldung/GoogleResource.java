package com.baeldung;

import com.google.gson.JsonObject;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

@RestController
public class GoogleResource {

    private static final String GOOGLE_CLIENT_ID = "1050151621152-udj2p6nqfgbp3hj33nkeae1tsjetat2k.apps.googleusercontent.com";
    private static final String GOOGLE_CLIENT_SECRET = "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";
    private static final String REDIRECT_URI = "https://5233-176-240-136-21.ngrok-free.app/callback";

    @GetMapping("/oauth2/authorize/google")
    public void redirectToGoogle(HttpServletResponse response) throws IOException {
        String googleAuthUrl = "https://accounts.google.com/o/oauth2/auth" +
                "?client_id=" + GOOGLE_CLIENT_ID +
                "&redirect_uri=" + REDIRECT_URI +
                "&response_type=code" +
                "&scope=openid email profile";

        response.sendRedirect(googleAuthUrl);
    }



   /* public GoogleTokenResponse getAccessToken(String authorizationCode) throws IOException {
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                httpTransport, jsonFactory, CLIENT_ID, CLIENT_SECRET, Collections.singleton(Oauth2Scopes.PROFILE))
                .setAccessType("offline")
                .build();

        GoogleTokenResponse tokenResponse = flow.newTokenRequest(authorizationCode)
                .setRedirectUri(REDIRECT_URI)
                .execute();

        return tokenResponse;
    }*/



    @GetMapping("/callback")
    public String handleGoogleCallback(@RequestParam("code") String code) {
        String tokenUrl = "https://oauth2.googleapis.com/token";

        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> requestParams = new LinkedMultiValueMap<>();
        requestParams.add("client_id", GOOGLE_CLIENT_ID);
        requestParams.add("client_secret", GOOGLE_CLIENT_SECRET);
        requestParams.add("code", code);
        requestParams.add("grant_type", "authorization_code");
        requestParams.add("redirect_uri", REDIRECT_URI);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(requestParams, headers);

        ResponseEntity<String> response = restTemplate.exchange(tokenUrl, HttpMethod.POST, entity, String.class);
        String accessToken = extractAccessToken(response.getBody());
        JSONObject jsonObject = new JSONObject(response.getBody());
        String idToken = jsonObject.getString("id_token");

        //return "redirect:https://console.cloud.google.com";

        HttpHeaders headers2 = new HttpHeaders();
        headers2.set("Authorization", "Bearer " + idToken);  // id_token'ı Bearer token olarak kullanın

        HttpEntity<String> entity2 = new HttpEntity<>(headers);

        return idToken;
    }

    public String exchangeAuthCodeForAccessToken(String authorizationCode) throws IOException {
        String url = "https://oauth2.googleapis.com/token";
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");

        String urlParameters = "code=" + authorizationCode +
                "&client_id=" +GOOGLE_CLIENT_ID+
                "&client_secret=" +GOOGLE_CLIENT_SECRET +
                "&redirect_uri=" + REDIRECT_URI +
                "&grant_type=authorization_code";

        con.setDoOutput(true);
        OutputStream os = con.getOutputStream();
        os.write(urlParameters.getBytes());
        os.flush();
        os.close();

        BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        // Response'dan access token'ı al
        String accessToken = extractAccessToken(response.toString());
        return accessToken;
    }

    public String extractAccessToken(String jsonResponse) {
        JSONObject jsonObject = new JSONObject(jsonResponse);
        String accessToken = jsonObject.getString("access_token");
        return accessToken;
    }


    /*public static String getAccessToken(String authorizationCode) {
        try {
            // Google OAuth bilgileri
            String clientId = "YOUR_CLIENT_ID";
            String clientSecret = "YOUR_CLIENT_SECRET";
            String redirectUri = "YOUR_REDIRECT_URI";  // IDP'nize yönlendirme URL'si

            // Token URL'sine isteği göndermek için HTTP client'ı başlat
            CloseableHttpClient client = HttpClients.createDefault();

            // POST isteği için URL
            String tokenUrl = "https://oauth2.googleapis.com/token";

            // İstek parametrelerini JSON formatında oluştur
            String body = "code=" + authorizationCode + "&" +
                    "client_id=" + clientId + "&" +
                    "client_secret=" + clientSecret + "&" +
                    "redirect_uri=" + redirectUri + "&" +
                    "grant_type=authorization_code";

            // HTTP POST isteğini oluştur
            HttpPost postRequest = new HttpPost(tokenUrl);
            postRequest.setEntity(new StringEntity(body));
            postRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");

            // İsteği gönder
            HttpResponse response = client.execute(postRequest);

            // Yanıtı al ve işleme
            String responseString = EntityUtils.toString(response.getEntity());
            System.out.println("Response: " + responseString);

            // JSON yanıtını parse et
            JsonObject responseJson = new Gson().fromJson(responseString, JsonObject.class);
            String accessToken = responseJson.get("access_token").getAsString();
            System.out.println("Access Token: " + accessToken);

            return accessToken;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }*/

}
