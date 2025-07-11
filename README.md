#Ransomware Demo with C2 Server
This project is a demonstration of a ransomware-like tool and its Command and Control (C2) server, implemented in C++ using Qt for the GUI, Boost.Asio for networking, and OpenSSL for AES-256 encryption. This is for educational purposes only and should not be used maliciously.
This tool is tested in parrot os (MATE) 
Overview
The tool consists of two main components:

Ransomware Client: Encrypts files in a specified directory using AES-256-CBC, renames them with a .encrypted extension, and creates a ransom note. It communicates with the C2 server to send encryption keys and listen for decryption commands.
C2 Server: A Qt-based GUI application that listens for client connections, receives encryption keys, and sends decryption commands to connected clients.

Features

Encryption: Recursively encrypts files in a target directory using AES-256-CBC.
Decryption: Decrypts files upon receiving a command from the C2 server.
C2 Communication: Uses TCP sockets (Boost.Asio) for client-server communication.
GUI: Qt-based interface for the C2 server to monitor connections and trigger decryption.
Ransom Note: Generates a RANSOM_NOTE.txt in the target directory.

Prerequisites
To build and run this project, you need:

C++ Compiler: A C++17 compatible compiler (e.g., GCC, Clang).
Qt: Version 5 or 6 for the C2 server GUI.
Boost.Asio: For network communication.
OpenSSL: For AES-256 encryption/decryption.
CMake: For building the project.
Operating System: Tested on Linux; may require modifications for other platforms.

Installation

Install dependencies:
sudo apt-get install build-essential cmake libboost-all-dev libssl-dev qt5-default

For Qt6, replace qt5-default with the appropriate Qt6 package.

Clone the repository:
git clone https://github.com/yourusername/ransomware-demo.git
cd ransomware-demo


Build the project:
mkdir build && cd build
cmake ..
make



Usage

Run the C2 Server:
./build/c2_server


The server listens on port 8080 for client connections and 8081 for sending decryption commands.
Use the GUI to start the server and monitor connected clients.


Run the Ransomware Client:
./build/ransomware_client


The client encrypts files in the directory /home/unknown/test_ransomware (modify targetDir in main() to change this).
It sends the AES-256 key to the C2 server and waits for a decryption command.


Decryption:

In the C2 server GUI, click the "Decrypt" button to send a decryption command to connected clients.
The client will decrypt files and restore their original names.



Project Structure

c2_server.cpp: Implementation of the C2 server with Qt GUI and Boost.Asio networking.
c2_server.h: Header file for the C2 server.
ui_c2_server.h: Qt-generated UI header for the C2 server GUI.
ransomware_client.cpp: Main ransomware logic for encryption, decryption, and C2 communication.
CMakeLists.txt: CMake configuration for building the project.

Security Warning
This code is for educational purposes only. It demonstrates ransomware behavior, including file encryption and C2 communication. Do not use this code to harm systems or networks. Always test in a controlled, isolated environment (e.g., a virtual machine).
Limitations

The target directory is hardcoded in ransomware_client.cpp.
No authentication or encryption for C2 communication (plain TCP).
Tested only on Linux; Windows/macOS may require adjustments.
The decryption process assumes the original key and IV are available.

Contributing
Contributions are welcome! Please submit a pull request or open an issue for bugs, improvements, or feature requests.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Disclaimer
This software is provided "as is" for educational purposes. The authors are not responsible for any misuse or damage caused by this code.
