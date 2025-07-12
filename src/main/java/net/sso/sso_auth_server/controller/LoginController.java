package net.sso.sso_auth_server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController  // This automatically adds @ResponseBody to all methods
public class LoginController {

    @GetMapping("/")
    public String home() {
        return "Authorization Server is running.";
    }

    @GetMapping("/login/success")
    public String loginSuccess() {
        return "✅ Login Successful on Auth Server!";
    }

}
