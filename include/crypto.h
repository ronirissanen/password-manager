#pragma once
#include <vector>
#include <secret.h>

std::vector<unsigned char> encrypt(
    const Secret &plaintext,
    const Secret &key);

Secret decrypt(const std::vector<unsigned char> &ciphertext, const Secret &key);

Secret deriveKey(const Secret &password, const std::vector<unsigned char> &salt);

std::vector<unsigned char> generateSalt();