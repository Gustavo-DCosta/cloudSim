#include <iostream>
#include <string>

std::string sanitizeFileName(const std::string& fileName) {
    std::string sanitized = fileName;
    for (char& ch : sanitized) {
        if (ch == ' ') {
            ch = '-'; // Replace spaces with hyphens
        } else if (ch == '\'') {
            ch = '_'; // Replace apostrophes with underscores
        }
    }
    return sanitized;
}

int main() {
    std::string inputFileName;
    std::cout << "Enter a file name: ";
    std::getline(std::cin, inputFileName);

    std::string sanitizedFileName = sanitizeFileName(inputFileName);
    std::cout << "Sanitized file name: " << sanitizedFileName << std::endl;

    // Use sanitizedFileName in your program logic
    return 0;
}
