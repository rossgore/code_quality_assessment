#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <ctime>
#include <iostream>
#include <memory>

/**
 * UtilityHelper class providing common utility functions
 * Demonstrates moderate code quality with room for improvement
 */
class UtilityHelper {
public:
    /**
     * Format current time as string
     * @param format Time format string
     * @return Formatted time string
     */
    static std::string formatCurrentTime(const std::string& format = "%Y-%m-%d %H:%M:%S") {
        std::time_t now = std::time(nullptr);
        std::tm* timeinfo = std::localtime(&now);

        char buffer[100];
        std::strftime(buffer, sizeof(buffer), format.c_str(), timeinfo);

        return std::string(buffer);
    }

    /**
     * Simple email validation (basic implementation)
     * @param email Email string to validate
     * @return True if email appears valid
     */
    static bool isValidEmail(const std::string& email) {
        if (email.empty()) {
            return false;
        }

        // Basic validation - could be more robust
        size_t atPos = email.find('@');
        if (atPos == std::string::npos) {
            return false;
        }

        size_t dotPos = email.find('.', atPos);
        if (dotPos == std::string::npos) {
            return false;
        }

        // Check for basic structure
        if (atPos == 0 || dotPos == email.length() - 1) {
            return false;
        }

        return true;
    }

    /**
     * Remove empty strings from vector
     * @param input Vector of strings to filter
     * @return New vector without empty strings
     */
    static std::vector<std::string> filterEmptyStrings(const std::vector<std::string>& input) {
        std::vector<std::string> result;
        result.reserve(input.size()); // Good practice - reserve space

        for (const auto& item : input) {
            if (!item.empty()) {
                // Trim whitespace and check again
                std::string trimmed = trim(item);
                if (!trimmed.empty()) {
                    result.push_back(trimmed);
                }
            }
        }

        return result;
    }

    /**
     * Calculate score based on array of numbers
     * Moderate complexity function
     * @param numbers Array of integers
     * @param size Size of array
     * @return Calculated score
     */
    static int calculateScore(const int* numbers, size_t size) {
        if (!numbers || size == 0) {
            return 0;
        }

        int score = 0;
        int bonusMultiplier = 1;

        for (size_t i = 0; i < size; ++i) {
            int num = numbers[i];

            if (num > 0) {
                score += num * 2;
                if (num > 50) {
                    bonusMultiplier = 2;
                } else if (num > 25) {
                    bonusMultiplier = 1;
                }
            } else if (num < 0) {
                score -= abs(num);
                bonusMultiplier = 1; // Reset bonus for negative numbers
            }
            // Zero values don't affect score
        }

        // Apply bonus multiplier
        if (bonusMultiplier > 1) {
            score = static_cast<int>(score * 1.1);
        }

        // Apply final adjustments based on score range
        if (score > 1000) {
            score = static_cast<int>(score * 0.9); // Diminishing returns
        } else if (score > 500) {
            score = static_cast<int>(score * 1.05); // Small bonus
        }

        return std::max(0, score); // Ensure non-negative result
    }

    /**
     * Split string by delimiter
     * @param str String to split
     * @param delimiter Character delimiter
     * @return Vector of string parts
     */
    static std::vector<std::string> split(const std::string& str, char delimiter) {
        std::vector<std::string> result;
        std::stringstream ss(str);
        std::string item;

        while (std::getline(ss, item, delimiter)) {
            result.push_back(item);
        }

        return result;
    }

    /**
     * Trim whitespace from both ends of string
     * @param str String to trim
     * @return Trimmed string
     */
    static std::string trim(const std::string& str) {
        const std::string whitespace = " \t\n\r\f\v";

        size_t start = str.find_first_not_of(whitespace);
        if (start == std::string::npos) {
            return "";
        }

        size_t end = str.find_last_not_of(whitespace);
        return str.substr(start, end - start + 1);
    }

    /**
     * Convert string to uppercase
     * @param str Input string
     * @return Uppercase version
     */
    static std::string toUpperCase(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), 
                      [](unsigned char c) { return std::toupper(c); });
        return result;
    }

    /**
     * Simple hash function for strings
     * Not cryptographically secure - for general use only
     * @param str String to hash
     * @return Simple hash value
     */
    static size_t simpleHash(const std::string& str) {
        size_t hash = 0;
        const size_t prime = 31;

        for (char c : str) {
            hash = hash * prime + static_cast<size_t>(c);
        }

        return hash;
    }

private:
    // Private constructor - utility class should not be instantiated
    UtilityHelper() = default;
};

// Example usage function
void demonstrateUtilities() {
    std::cout << "Current time: " << UtilityHelper::formatCurrentTime() << std::endl;

    std::vector<std::string> emails = {
        "valid@example.com",
        "invalid-email",
        "another@test.org",
        ""
    };

    for (const auto& email : emails) {
        std::cout << email << " is " 
                  << (UtilityHelper::isValidEmail(email) ? "valid" : "invalid") 
                  << std::endl;
    }

    // Test score calculation
    int numbers[] = {10, -5, 25, 0, 75, -10, 30};
    size_t size = sizeof(numbers) / sizeof(numbers[0]);
    int score = UtilityHelper::calculateScore(numbers, size);
    std::cout << "Calculated score: " << score << std::endl;
}