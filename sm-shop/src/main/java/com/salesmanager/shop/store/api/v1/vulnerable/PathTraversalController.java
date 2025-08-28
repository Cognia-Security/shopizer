package com.salesmanager.shop.store.api.v1.vulnerable;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

/**
 * VULNERABILITY: Path Traversal vulnerable controller
 * This file contains multiple path traversal vulnerabilities for SAST tool testing
 */
@Controller
@RequestMapping("/api/v1/vulnerable/path")
public class PathTraversalController {

    private static final String BASE_DIR = "/var/www/files/";

    /**
     * VULNERABILITY: Path traversal in file download
     */
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadFile(@RequestParam("file") String fileName) {
        try {
            // VULNERABILITY: Direct path concatenation without validation
            Path filePath = Paths.get(BASE_DIR + fileName);
            Resource resource = new UrlResource(filePath.toUri());
            
            if (resource.exists() && resource.isReadable()) {
                return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                    .body(resource);
            }
        } catch (IOException e) {
            // Handle exception
        }
        return ResponseEntity.notFound().build();
    }

    /**
     * VULNERABILITY: Path traversal in file listing
     */
    @GetMapping("/list")
    @ResponseBody
    public String listFiles(@RequestParam("dir") String directory) {
        try {
            // VULNERABILITY: User input used directly in file operations
            Path dirPath = Paths.get(BASE_DIR + directory);
            List<String> files = Files.list(dirPath)
                .map(Path::getFileName)
                .map(Path::toString)
                .collect(Collectors.toList());
            
            return "Files in " + directory + ": " + String.join(", ", files);
        } catch (IOException e) {
            return "Error listing files: " + e.getMessage();
        }
    }

    /**
     * VULNERABILITY: Path traversal in file deletion
     */
    @DeleteMapping("/delete")
    @ResponseBody
    public String deleteFile(@RequestParam("file") String fileName) {
        try {
            // VULNERABILITY: User input used directly in file deletion
            File file = new File(BASE_DIR + fileName);
            if (file.delete()) {
                return "File " + fileName + " deleted successfully";
            } else {
                return "Failed to delete file " + fileName;
            }
        } catch (Exception e) {
            return "Error deleting file: " + e.getMessage();
        }
    }

    /**
     * VULNERABILITY: Path traversal in file reading
     */
    @GetMapping("/read")
    @ResponseBody
    public String readFile(@RequestParam("file") String fileName) {
        try {
            // VULNERABILITY: User input used directly in file reading
            Path filePath = Paths.get(BASE_DIR + fileName);
            String content = new String(Files.readAllBytes(filePath));
            return "File content: " + content;
        } catch (IOException e) {
            return "Error reading file: " + e.getMessage();
        }
    }

    /**
     * VULNERABILITY: Path traversal in directory creation
     */
    @PostMapping("/mkdir")
    @ResponseBody
    public String createDirectory(@RequestParam("dir") String directory) {
        try {
            // VULNERABILITY: User input used directly in directory creation
            Path dirPath = Paths.get(BASE_DIR + directory);
            Files.createDirectories(dirPath);
            return "Directory " + directory + " created successfully";
        } catch (IOException e) {
            return "Error creating directory: " + e.getMessage();
        }
    }
}
