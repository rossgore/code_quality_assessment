package com.example.demo;

import java.util.List;
import java.util.ArrayList;

/**
 * A well-documented and properly structured class
 * demonstrating good Java coding practices.
 *
 * @author Developer
 * @version 1.0
 */
public class GoodExample {
    // Private fields with proper encapsulation
    private String name;
    private int age;
    private List<String> hobbies;

    /**
     * Constructor with parameter validation
     * @param name The person's name
     * @param age The person's age
     */
    public GoodExample(String name, int age) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Name cannot be null or empty");
        }
        if (age < 0) {
            throw new IllegalArgumentException("Age cannot be negative");
        }
        this.name = name;
        this.age = age;
        this.hobbies = new ArrayList<>();
    }

    /** Get the person's name */
    public String getName() { return name; }

    /** Set the person's name with validation */
    public void setName(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Name cannot be null or empty");
        }
        this.name = name;
    }

    /** Get the person's age */
    public int getAge() { return age; }

    /** Set the person's age with validation */
    public void setAge(int age) {
        if (age < 0) {
            throw new IllegalArgumentException("Age cannot be negative");
        }
        this.age = age;
    }

    /** Add a hobby to the list */
    public void addHobby(String hobby) {
        if (hobby != null && !hobby.trim().isEmpty()) {
            hobbies.add(hobby);
        }
    }

    /** Get the list of hobbies */
    public List<String> getHobbies() { return new ArrayList<>(hobbies); }

    @Override
    public String toString() {
        return "GoodExample{name='" + name + "', age=" + age + ", hobbies=" + hobbies + "}";
    }
}
