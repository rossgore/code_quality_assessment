package com.example.utils;

import java.util.List;
import java.util.ArrayList;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Utility class for common operations
 */
public class UtilityHelper {

    private static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";

    public static String formatDate(Date date) {
        if (date == null) return null;

        SimpleDateFormat formatter = new SimpleDateFormat(DATE_FORMAT);
        return formatter.format(date);
    }

    public static boolean isValidEmail(String email) {
        if (email == null || email.isEmpty()) {
            return false;
        }

        // Simple email validation (could be improved)
        if (email.contains("@") && email.contains(".")) {
            String[] parts = email.split("@");
            if (parts.length == 2) {
                String domain = parts[1];
                if (domain.contains(".")) {
                    return true;
                }
            }
        }
        return false;
    }

    public static List<String> filterEmptyStrings(List<String> input) {
        List<String> result = new ArrayList<>();

        for (String item : input) {
            if (item != null && !item.trim().isEmpty()) {
                result.add(item);
            }
        }
        return result;
    }

    // Method with moderate complexity
    public static int calculateScore(int[] numbers) {
        int score = 0;

        for (int num : numbers) {
            if (num > 0) {
                score += num * 2;
            } else if (num < 0) {
                score -= Math.abs(num);
            }
            // Zero values don't affect score
        }

        // Apply bonus for high totals
        if (score > 100) {
            score = (int) (score * 1.1);
        } else if (score > 50) {
            score = (int) (score * 1.05);
        }

        return Math.max(0, score);
    }
}
