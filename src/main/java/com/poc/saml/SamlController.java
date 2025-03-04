package com.poc.saml;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SamlController {

    @GetMapping("/saml/acs")
    public String handleSamlResponse(Authentication authentication) {
        // Kullanıcının SAML kimlik bilgilerini alıyoruz
        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
        String userName = principal.getName(); // Kullanıcı adı

        // Burada kullanıcının kimliğini doğruladıktan sonra işlemleri başlatabilirsiniz
        System.out.println("Authenticated user: " + userName);

        return "Hello, " + userName;  // Başarılı doğrulama mesajı
    }

    @GetMapping("/saml/sso")
    public String samlLogin() {
        // Kullanıcıyı SAML login sayfasına yönlendir
        return "redirect:/login";
    }
}
