#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <fstream>

// Poor practice: Global variables and hardcoded credentials
char* global_password = "admin123456";
const char* api_secret = "sk-1234567890abcdef1234567890abcdef";

/**
 * BadExample class demonstrating poor C++ practices and security vulnerabilities
 * WARNING: This code contains intentional security flaws for testing purposes
 */
class BadExample {
public:
    char username[50]; // Public member variable - encapsulation violation
    char* buffer;      // Raw pointer without proper management

    BadExample() {
        buffer = (char*)malloc(100); // Memory allocation without checking for failure
    }

    ~BadExample() {
        free(buffer);
        free(buffer); // Double free vulnerability - CWE-415
    }
};

// Buffer overflow vulnerability - CWE-120
void unsafeCopy(const char* input) {
    char buffer[50];
    strcpy(buffer, input); // No bounds checking - dangerous function
    printf("Copied: %s\n", buffer);
}

// Format string vulnerability - CWE-134
void unsafeLogging(const char* userInput) {
    printf(userInput); // User input directly in format string
    fprintf(stderr, userInput); // Another format string vulnerability
}

// SQL injection equivalent - unsafe string concatenation
void buildQuery(const char* userId) {
    char query[200];
    sprintf(query, "SELECT * FROM users WHERE id='%s'", userId); // Unsafe sprintf
    printf("Query: %s\n", query);
}

// Command injection vulnerability
void executeSystemCommand(const char* filename) {
    char command[100];
    sprintf(command, "cat %s", filename); // No input validation
    system(command); // Dangerous system call
}

// Memory leak and unsafe file operations
void processFile(const char* filename) {
    FILE* file = fopen(filename, "r"); // No null check
    char* data = (char*)malloc(1000);  // Memory allocated but may not be freed

    if (file != NULL) {
        fread(data, 1, 1000, file);
        // Missing fclose(file) - resource leak
        // Missing free(data) in some paths - memory leak
    }

    // Complex method with high cyclomatic complexity
    int x = rand() % 100;
    if (x > 80) {
        if (x > 90) {
            if (x > 95) {
                if (x > 97) {
                    if (x > 98) {
                        printf("Very high value\n");
                    } else {
                        printf("High value\n");
                    }
                } else {
                    printf("Above average\n");
                }
            } else {
                printf("Good value\n");
            }
        } else {
            printf("Decent value\n");
        }
    } else {
        if (x < 20) {
            if (x < 10) {
                if (x < 5) {
                    printf("Very low\n");
                } else {
                    printf("Low\n");
                }
            } else {
                printf("Below average\n");
            }
        } else {
            printf("Medium value\n");
        }
    }
}

// Null pointer dereference vulnerability
void unsafePointerUsage(char* ptr) {
    *ptr = 'A'; // No null check - potential crash
    printf("Set value: %c\n", *ptr);
}

// Integer overflow potential
int unsafeMultiplication(int a, int b) {
    return a * b; // No overflow checking
}

// Unsafe string functions
void moreUnsafeFunctions(const char* src) {
    char dest[10];
    strcat(dest, src); // Using uninitialized dest
    gets(dest); // Extremely dangerous function
}

// Use of dangerous C functions
void demonstrateDangerousFunctions() {
    char buffer[100];
    scanf("%s", buffer); // No bounds checking

    // More unsafe operations
    char* ptr = (char*)alloca(1000); // Stack allocation that may overflow
    strcpy(ptr, "Some data that might be too long for safety");
}

// Class with missing virtual destructor
class BaseClass {
public:
    virtual void doSomething() {}
    // Missing virtual destructor - potential issue with polymorphism
};

// Multiple inheritance - can be problematic
class MultipleInheritance : public BadExample, public BaseClass {
public:
    void complexFunction() {
        // More code duplication
        char temp1[50];
        strcpy(temp1, "duplicate");
        printf("Processing: %s\n", temp1);

        char temp2[50];
        strcpy(temp2, "duplicate");  
        printf("Processing: %s\n", temp2);

        char temp3[50];
        strcpy(temp3, "duplicate");
        printf("Processing: %s\n", temp3);
    }
};

int main() {
    // Unsafe usage examples
    BadExample* obj = new BadExample();

    unsafeCopy("This string might be too long for the buffer and cause overflow");
    unsafeLogging("User controlled input %s %d");
    executeSystemCommand("../../../etc/passwd"); // Path traversal attempt

    delete obj;
    return 0;
}