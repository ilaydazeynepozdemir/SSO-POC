package com.baeldung;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/debug")
public class DebugController {

    @GetMapping("/session-id")
    public ResponseEntity<String> checkSessionId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return ResponseEntity.ok(session != null ? "Client Session ID: " + session.getId() : "Session is null");
    }


    @GetMapping("/auth-request")
    public ResponseEntity<?> checkAuthRequest(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return ResponseEntity.ok("Session is null");
        }
        Object authRequest = session.getAttribute(
                "org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository.AUTHORIZATION_REQUEST"
        );
        return ResponseEntity.ok(authRequest != null ? "Authorization Request exists" : "Authorization Request is null");
    }
}
