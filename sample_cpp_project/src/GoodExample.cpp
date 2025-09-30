#include "../include/GoodExample.h"
#include <stdexcept>
#include <sstream>
#include <algorithm>

GoodExample::GoodExample(const std::string& name, int age) {
    // Input validation with clear error messages
    if (name.empty()) {
        throw std::invalid_argument("Name cannot be empty");
    }
    if (age < 0) {
        throw std::invalid_argument("Age cannot be negative");
    }

    name_ = name;
    age_ = age;
    hobbies_.reserve(10); // Reserve reasonable capacity
}

const std::string& GoodExample::getName() const noexcept {
    return name_;
}

void GoodExample::setName(const std::string& name) {
    if (name.empty()) {
        throw std::invalid_argument("Name cannot be empty");
    }
    name_ = name;
}

int GoodExample::getAge() const noexcept {
    return age_;
}

void GoodExample::setAge(int age) {
    if (age < 0) {
        throw std::invalid_argument("Age cannot be negative");
    }
    age_ = age;
}

void GoodExample::addHobby(const std::string& hobby) {
    // Only add non-empty hobbies and avoid duplicates
    if (!hobby.empty()) {
        auto it = std::find(hobbies_.begin(), hobbies_.end(), hobby);
        if (it == hobbies_.end()) {
            hobbies_.push_back(hobby);
        }
    }
}

std::vector<std::string> GoodExample::getHobbies() const {
    // Return copy to maintain encapsulation
    return hobbies_;
}

std::string GoodExample::toString() const {
    std::ostringstream oss;
    oss << "GoodExample{name='" << name_ << "', age=" << age_ << ", hobbies=[";

    for (size_t i = 0; i < hobbies_.size(); ++i) {
        if (i > 0) {
            oss << ", ";
        }
        oss << "'" << hobbies_[i] << "'";
    }

    oss << "]}";
    return oss.str();
}