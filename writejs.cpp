#include <iostream>
#include <chrono>
#include <ctime>
#include <fstream> // For file handling


void stats() {
    std::string username;
    std::cout << "Enter your username: ";
    std::cin >> username;

    auto start = std::chrono::system_clock::now();
    // Some computation here
    auto end = std::chrono::system_clock::now();
 
    std::chrono::duration<double> elapsed_seconds = end - start;
    std::time_t end_time = std::chrono::system_clock::to_time_t(end);
 
    // Open a file in write mode
    std::ofstream output_file("log.txt", std::ios::app); // Append to the file if it exists
    if (output_file.is_open())
    {
        output_file << "Username: " << username << std::endl
                    << "Finished computation at " << std::ctime(&end_time)
                    << "Elapsed time: " << elapsed_seconds.count() << "s\n"
                    << "--------------------------------------------------" << std::endl;
        output_file.close();
        std::cout << "Date and time written to log.txt successfully.\n";
    }
    else
    {
        std::cerr << "Error opening file for writing.\n";
    }
} 

void deleteLogs() {
    if (remove("log.txt") == 0) {
        std::cout << "log.txt deleted successfully.\n";
    } else {
        std::cerr << "Error deleting log.txt.\n";
    }
}

int main()  {
    int choice;
    std::cout << "1. Write logs\n";
    std::cout << "2. Delete logs\n";
    std::cout << "Enter your choice: ";
    std::cin >> choice;
    switch (choice) {
        case 1:
            stats();
            break;
        case 2:
            deleteLogs();
            break;
        default :
            std::cout << "Invalid choice. Please try again.\n";
    }
    
    return 0;   
}
