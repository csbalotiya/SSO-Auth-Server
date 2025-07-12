package net.sso.sso_auth_server.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {


    @GetMapping("/")
    public String home() {
        return "Authorization Server is running.";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/login/success")
    public String loginSuccess() {
        return "✅ Login Successful on Auth Server!";
    }

}
