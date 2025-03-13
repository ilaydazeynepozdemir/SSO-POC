package com.baeldung;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String loginPage() {
        return "login"; // 🔥 login.html dosyanı döndürüyor
    }
    @GetMapping("/test")
    public String test() {
        return "test"; // 🔥 login.html dosyanı döndürüyor
    }
}