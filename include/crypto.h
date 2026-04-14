#pragma once
#include <vector>

// Encrypts input plaintext using XSalsa20-Poly1305.
std::vector<unsigned char> encrypt(
    const std::vector<unsigned char> &plaintext,
    const std::string &password);

// Reverts encryption done by the encrypt function.
std::vector<unsigned char> decrypt(
    const std::vector<unsigned char> &ciphertext,
    const std::string &password);

std::vector<unsigned char> deriveKey(
    const std::string &password,
    const std::vector<unsigned char> &salt);