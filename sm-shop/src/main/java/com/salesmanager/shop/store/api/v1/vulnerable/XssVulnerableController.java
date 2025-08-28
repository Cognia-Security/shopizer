package com.salesmanager.shop.store.api.v1.vulnerable;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * VULNERABILITY: XSS (Cross-Site Scripting) vulnerable controller
 * This file contains multiple XSS vulnerabilities for SAST tool testing
 */
@Controller
@RequestMapping("/api/v1/vulnerable/xss")
public class XssVulnerableController {

    /**
     * VULNERABILITY: Reflected XSS - user input directly reflected in response
     */
    @GetMapping("/search")
    @ResponseBody
    public String searchProducts(@RequestParam("q") String searchQuery) {
        // VULNERABILITY: Direct reflection of user input without sanitization
        return "<html><body><h1>Search Results for: " + searchQuery + "</h1></body></html>";
    }

    /**
     * VULNERABILITY: Stored XSS - user input stored and later displayed
     */
    @PostMapping("/comment")
    @ResponseBody
    public String addComment(@RequestParam("comment") String userComment) {
        // VULNERABILITY: User input stored without sanitization
        String storedComment = userComment; // In real app, this would be saved to database
        return "Comment added: " + storedComment;
    }

    /**
     * VULNERABILITY: DOM-based XSS - user input used in JavaScript
     */
    @GetMapping("/profile")
    @ResponseBody
    public String getUserProfile(@RequestParam("username") String username) {
        // VULNERABILITY: User input embedded in JavaScript without escaping
        return "<script>var username = '" + username + "'; document.getElementById('user').innerHTML = username;</script>";
    }

    /**
     * VULNERABILITY: XSS in HTTP response headers
     */
    @GetMapping("/redirect")
    public void redirectUser(@RequestParam("url") String redirectUrl, 
                           HttpServletResponse response) throws IOException {
        // VULNERABILITY: User input used in HTTP header without validation
        response.setHeader("Location", redirectUrl);
        response.sendRedirect(redirectUrl);
    }

    /**
     * VULNERABILITY: XSS in error messages
     */
    @GetMapping("/error")
    @ResponseBody
    public String handleError(@RequestParam("message") String errorMessage) {
        // VULNERABILITY: Error message directly displayed without sanitization
        return "<div class='error'>Error: " + errorMessage + "</div>";
    }
}
