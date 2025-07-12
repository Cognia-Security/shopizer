package com.salesmanager.shop.store.api.v1.system;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Intentionally vulnerable endpoints for security scanning demos.
 */
@RestController
@RequestMapping("/api/v1")
public class VulnerableSystemApi {

    @GetMapping("/private/system/readfile")
    public ResponseEntity<String> readFile(@RequestParam String filename) throws IOException {
        // This allows path traversal if filename contains ../ sequences
        String content = Files.readString(Paths.get("/tmp/" + filename)); // VULNERABLE CODE!
        return ResponseEntity.ok(content);
    }

    @PostMapping("/private/system/run")
    public ResponseEntity<String> runCommand(@RequestParam String cmd) throws IOException {
        // Command is executed without validation
        Runtime.getRuntime().exec(cmd); // VULNERABLE CODE!
        return ResponseEntity.ok("Executed");
    }
}