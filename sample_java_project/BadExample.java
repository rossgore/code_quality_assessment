package com.example.security;

import java.sql.*;
import java.io.*;
import java.util.*;

public class BadExample {
    public String username; // Public field - encapsulation violation
    public String password = "hardcoded123"; // Hardcoded password - security issue
    public static String apiKey = "sk-1234567890abcdef"; // Hardcoded API key

    public void authenticateUser(String user, String pass) {
        try {
            // SQL Injection vulnerability
            String query = "SELECT * FROM users WHERE username='" + user + "' AND password='" + pass + "'";
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                System.out.println("User authenticated");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void readFile(String fileName) {
        try {
            // Path traversal vulnerability
            File file = new File("/data/" + fileName);
            FileInputStream fis = new FileInputStream(file);
            BufferedReader reader = new BufferedReader(new InputStreamReader(fis));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void executeCommand(String cmd) {
        try {
            // Command injection vulnerability
            Runtime.getRuntime().exec("ping " + cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void complexMethod(int a, int b, int c, int d, int e) {
        // High cyclomatic complexity method
        if (a > 0) {
            if (b > 0) {
                if (c > 0) {
                    if (d > 0) {
                        if (e > 0) {
                            System.out.println("All positive");
                        } else {
                            System.out.println("e is not positive");
                        }
                    } else {
                        if (e > 0) {
                            System.out.println("d is not positive but e is");
                        } else {
                            System.out.println("d and e are not positive");
                        }
                    }
                } else {
                    if (d > 0 && e > 0) {
                        System.out.println("c is not positive but d and e are");
                    } else {
                        System.out.println("Multiple negative values");
                    }
                }
            } else {
                if (c > 0 && d > 0 && e > 0) {
                    System.out.println("b is not positive but others are");
                } else {
                    System.out.println("Multiple issues");
                }
            }
        } else {
            System.out.println("a is not positive");
        }

        // Code duplication
        for (int i = 0; i < 10; i++) {
            System.out.println("Processing item " + i);
        }
        for (int i = 0; i < 10; i++) {
            System.out.println("Processing item " + i);
        }
        for (int i = 0; i < 10; i++) {
            System.out.println("Processing item " + i);
        }
    }
    // Missing getters and setters for public fields
    // No proper error handling
    // No documentation
}
