package com.salesmanager.shop.store.api.v1.vulnerable;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaType;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.Base64;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * VULNERABILITY: Insecure Deserialization vulnerable controller
 * This file contains multiple insecure deserialization vulnerabilities for SAST tool testing
 */
@Controller
@RequestMapping("/api/v1/vulnerable/deserialization")
public class InsecureDeserializationController {

    /**
     * VULNERABILITY: Insecure Java deserialization
     */
    @PostMapping("/deserialize")
    @ResponseBody
    public String deserializeObject(@RequestBody String serializedData) {
        try {
            // VULNERABILITY: Direct deserialization of user input without validation
            byte[] data = Base64.getDecoder().decode(serializedData);
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);
            
            Object obj = ois.readObject();
            ois.close();
            
            return "Deserialized object: " + obj.toString();
        } catch (Exception e) {
            return "Error deserializing object: " + e.getMessage();
        }
    }

    /**
     * VULNERABILITY: Insecure XML deserialization
     */
    @PostMapping("/xml")
    @ResponseBody
    public String processXml(@RequestBody String xmlData) {
        try {
            // VULNERABILITY: XML deserialization without proper security measures
            // This could be vulnerable to XXE attacks
            return "XML processed: " + xmlData;
        } catch (Exception e) {
            return "Error processing XML: " + e.getMessage();
        }
    }

    /**
     * VULNERABILITY: Insecure JSON deserialization
     */
    @PostMapping("/json")
    @ResponseBody
    public String processJson(@RequestBody String jsonData) {
        try {
            // VULNERABILITY: JSON deserialization without type validation
            // This could lead to arbitrary object instantiation
            return "JSON processed: " + jsonData;
        } catch (Exception e) {
            return "Error processing JSON: " + e.getMessage();
        }
    }

    /**
     * VULNERABILITY: Insecure YAML deserialization
     */
    @PostMapping("/yaml")
    @ResponseBody
    public String processYaml(@RequestBody String yamlData) {
        try {
            // VULNERABILITY: YAML deserialization without security restrictions
            // This could lead to arbitrary code execution
            return "YAML processed: " + yamlData;
        } catch (Exception e) {
            return "Error processing YAML: " + e.getMessage();
        }
    }

    /**
     * VULNERABILITY: Insecure custom deserialization
     */
    @PostMapping("/custom")
    @ResponseBody
    public String processCustomData(@RequestBody String customData) {
        try {
            // VULNERABILITY: Custom deserialization without proper validation
            String[] parts = customData.split("\\|");
            if (parts.length >= 2) {
                String className = parts[0];
                String data = parts[1];
                
                // VULNERABILITY: Dynamic class loading without validation
                Class<?> clazz = Class.forName(className);
                Object obj = clazz.getDeclaredConstructor(String.class).newInstance(data);
                
                return "Custom object created: " + obj.toString();
            }
            return "Invalid custom data format";
        } catch (Exception e) {
            return "Error processing custom data: " + e.getMessage();
        }
    }

    /**
     * VULNERABILITY: Insecure compressed data deserialization
     */
    @PostMapping("/compressed")
    @ResponseBody
    public String processCompressedData(@RequestBody String compressedData) {
        try {
            // VULNERABILITY: Deserialization of compressed data without validation
            byte[] data = Base64.getDecoder().decode(compressedData);
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            GZIPInputStream gzip = new GZIPInputStream(bis);
            ObjectInputStream ois = new ObjectInputStream(gzip);
            
            Object obj = ois.readObject();
            ois.close();
            
            return "Compressed object deserialized: " + obj.toString();
        } catch (Exception e) {
            return "Error processing compressed data: " + e.getMessage();
        }
    }
}
