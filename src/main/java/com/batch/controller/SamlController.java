package com.batch.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/saml")
public class SamlController {

    @GetMapping("/")
    public String index(Model model, @AuthenticationPrincipal Saml2AuthenticatedPrincipal principal) {
        String emailAddress = principal.getFirstAttribute("email");
        model.addAttribute("emailAddress", emailAddress);
        model.addAttribute("userAttributes", principal.getAttributes());
        return "index";
    }

    @RequestMapping("/secured/hello")
    public String hello(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        model.addAttribute("name", principal.getName());
        return "hello";
    }
}
