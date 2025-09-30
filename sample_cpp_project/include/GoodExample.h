#ifndef GOODEXAMPLE_H
#define GOODEXAMPLE_H

#include <string>
#include <vector>
#include <memory>

/**
 * @brief A well-designed C++ class demonstrating modern best practices
 * 
 * This class showcases proper encapsulation, RAII principles, smart pointers,
 * and comprehensive error handling suitable for production environments.
 * 
 * @author Development Team
 * @version 1.0
 */
class GoodExample {
private:
    std::string name_;
    int age_;
    std::vector<std::string> hobbies_;

public:
    /**
     * @brief Construct a new Good Example object
     * @param name Person's name (must not be empty)
     * @param age Person's age (must be non-negative)
     * @throws std::invalid_argument if parameters are invalid
     */
    GoodExample(const std::string& name, int age);

    /**
     * @brief Destructor - default is sufficient due to RAII
     */
    ~GoodExample() = default;

    // Copy constructor and assignment operator
    GoodExample(const GoodExample& other) = default;
    GoodExample& operator=(const GoodExample& other) = default;

    // Move constructor and assignment operator
    GoodExample(GoodExample&& other) noexcept = default;
    GoodExample& operator=(GoodExample&& other) noexcept = default;

    /**
     * @brief Get the person's name
     * @return const reference to name string
     */
    const std::string& getName() const noexcept;

    /**
     * @brief Set the person's name with validation
     * @param name New name (must not be empty)
     * @throws std::invalid_argument if name is empty
     */
    void setName(const std::string& name);

    /**
     * @brief Get the person's age
     * @return Age value
     */
    int getAge() const noexcept;

    /**
     * @brief Set the person's age with validation
     * @param age New age (must be non-negative)
     * @throws std::invalid_argument if age is negative
     */
    void setAge(int age);

    /**
     * @brief Add a hobby to the collection
     * @param hobby Hobby string to add (ignored if empty)
     */
    void addHobby(const std::string& hobby);

    /**
     * @brief Get copy of hobbies vector
     * @return Vector containing all hobbies
     */
    std::vector<std::string> getHobbies() const;

    /**
     * @brief Get string representation of object
     * @return Formatted string representation
     */
    std::string toString() const;
};

#endif // GOODEXAMPLE_H