package com.baeldung;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping
    public String home(){
        return "redirect:http://localhost:8080/login";
    }
}
