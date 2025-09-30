#ifndef UTILITYHELPER_H
#define UTILITYHELPER_H

#include <string>
#include <vector>

/**
 * @brief Utility class providing common helper functions
 * 
 * This class contains static utility methods for common operations
 * like string manipulation, validation, and data processing.
 */
class UtilityHelper {
public:
    /**
     * @brief Format current time as string
     * @param format Time format string (default: "%Y-%m-%d %H:%M:%S")
     * @return Formatted time string
     */
    static std::string formatCurrentTime(const std::string& format = "%Y-%m-%d %H:%M:%S");

    /**
     * @brief Validate email address format
     * @param email Email string to validate
     * @return True if email appears to be valid
     */
    static bool isValidEmail(const std::string& email);

    /**
     * @brief Remove empty strings from vector
     * @param input Vector of strings to filter
     * @return New vector containing only non-empty strings
     */
    static std::vector<std::string> filterEmptyStrings(const std::vector<std::string>& input);

    /**
     * @brief Calculate score based on array of numbers
     * @param numbers Array of integers
     * @param size Size of the array
     * @return Calculated score value
     */
    static int calculateScore(const int* numbers, size_t size);

    /**
     * @brief Split string by delimiter
     * @param str String to split
     * @param delimiter Character delimiter
     * @return Vector containing string parts
     */
    static std::vector<std::string> split(const std::string& str, char delimiter);

    /**
     * @brief Remove whitespace from both ends of string
     * @param str String to trim
     * @return Trimmed string
     */
    static std::string trim(const std::string& str);

    /**
     * @brief Convert string to uppercase
     * @param str Input string
     * @return Uppercase version of the string
     */
    static std::string toUpperCase(const std::string& str);

    /**
     * @brief Generate simple hash for string
     * @param str String to hash
     * @return Hash value (not cryptographically secure)
     */
    static size_t simpleHash(const std::string& str);

private:
    UtilityHelper() = default; // Prevent instantiation
};

#endif // UTILITYHELPER_H