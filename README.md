# cloudSim
CloudSim – A C++ CLI Cloud Storage App 
CloudSim is a cloud-based file storage system written in C++. It allows users to securely store and manage files with authentication and logging features.

Originally, it was inspired by a Python spyware project I was experimenting with, but it evolved into a cloud storage solution.

🚀 Features
✅ Secure authentification features (hashing + salting)
✅ Log files for tracking activity
✅ File storage

🛠 Tech Stack
C++ (Core development)
SQLite3 library
File I/O for storage
Database content Encryption

🛠 Installation & Usage
(Currently, CloudSim runs locally. Future updates will include HTTPS support once the home server is set up.)

Clone the repository:
git clone https://github.com/your-username/cloudSim.git

Compile the code:
g++ cloudSim.cpp -o cloudSim

Run the program:
./cloudSim

Store files locally and manage them with authentication.

🔧 Future Improvements
Improve Log tracking system
Add files encryption for better security
