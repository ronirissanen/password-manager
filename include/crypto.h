#pragma once
#include <vector>

// Encrypts input plaintext using XSalsa20-Poly1305.
std::vector<unsigned char> encrypt(
    const vector<unsigned char> &plaintext,
    const string &password);

// Reverts encryption done by the encrypt function.
std::vector<unsigned char> decrypt(
    const vector<unsigned char> &ciphertext,
    const string &password);

std::vector<unsigned char> deriveKey(
    const string &password, const vector<unsigned char> &salt);