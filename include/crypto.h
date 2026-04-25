#pragma once
#include <vector>

std::vector<unsigned char> encrypt(
    const Secret &plaintext,
    const Secret &key);

Secret decrypt(
    const std::vector<unsigned char> &ciphertext,
    const Secret &key);

Secret deriveKey(
    const Secret &password,
    const std::vector<unsigned char> &salt);