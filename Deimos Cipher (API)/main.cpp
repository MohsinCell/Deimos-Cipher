#include "deimos_cipher.h"
#include <iostream>
#include <iomanip>

int main() 
    {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    std::string input;
    char choice;

    // User Decision
    std::cout << "Welcome to Deimos Cipher!\nDo you want to encrypt or decrypt? (E/D): ";
    std::cin >> choice;
    std::cin.ignore();

    if (choice == 'E' || choice == 'e') {
        std::cout << "Enter the plaintext: ";
        std::getline(std::cin, input);
    } else {
        std::cout << "Enter the ciphertext (hex): ";
        std::getline(std::cin, input);
    }

    std::string password;
    std::cout << "Enter the key: ";
    std::getline(std::cin, password);

    std::vector<uint8_t> ciphertext = deimosCipherEncrypt(input, password);

    if (choice == 'E' || choice == 'e') {
        std::cout << "Ciphertext (hex): ";
        for (uint8_t c : ciphertext)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        std::cout << std::endl; }

    else {
        std::vector<uint8_t> ciphertext;
        for (size_t i = 0; i < input.length(); i += 2)
            ciphertext.push_back(std::stoi(input.substr(i, 2), nullptr, 16));
        std::cout << "Plaintext: " << deimosCipherDecrypt(ciphertext, password) << std::endl; }

    return 0;
}
