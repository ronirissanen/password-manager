#include <sodium.h>
#include <crypto.h>
#include <secret.h>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <cstdint>
#include <cstring>
using std::string;
using std::vector;

Secret deriveKey(
    const Secret &password, const vector<unsigned char> &salt)
{
    Secret key(crypto_secretbox_KEYBYTES);
    if (password.length() == 0)
        throw std::runtime_error("deriveKey: empty password");

    if (crypto_pwhash(
            key.data,
            key.capacity,
            reinterpret_cast<const char *>(password.data),
            password.length(),
            salt.data(),
            crypto_pwhash_OPSLIMIT_MODERATE,    // moderate limits are fine for cli ux
            crypto_pwhash_MEMLIMIT_MODERATE,
            crypto_pwhash_ALG_DEFAULT) != 0)
        throw std::runtime_error("Key derivation failed.");

    return key;
}

vector<unsigned char> generateSalt()
{
    vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

vector<unsigned char> encrypt(const Secret &plaintext, const Secret &key)
{
    // generate a nonce (random number) for each encryption
    vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    // initialize cipher text with extra MAC bytes to detect tampering later
    vector<unsigned char> ciphertext(
        plaintext.length() + crypto_secretbox_MACBYTES);

    // crypto_secretbox_easy -- libsodium function for encryption
    // Generates ciphertext from plaintext using XSalsa20 stream cipher
    // Computes Poly1305 MAC over the ciphertext
    // Prepends the MAC to the ciphertext output
    crypto_secretbox_easy(
        ciphertext.data(),
        plaintext.data,
        plaintext.length(),
        nonce.data(),
        key.data);

    // prepend nonce to ciphertext for storage
    // before: [MAC 16 bytes][ciphertext]
    // after:  [nonce 24 bytes][MAC 16 bytes][ciphertext]
    ciphertext.insert(ciphertext.begin(), nonce.begin(), nonce.end());

    return ciphertext;
}

Secret decrypt(const vector<unsigned char> &ciphertext, const Secret &key)
{
    // if ciphertext is smaller than nonce + MAC
    // anything smaller means nonce or MAC is incomplete
    // => corrupt or truncated data
    if (ciphertext.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
        throw std::runtime_error("Ciphertext too short.");

    // peel nonce for decryption
    vector<unsigned char> nonce(ciphertext.begin(), ciphertext.begin() + crypto_secretbox_NONCEBYTES);
    const unsigned char *actual = ciphertext.data() + crypto_secretbox_NONCEBYTES;
    size_t actual_size = ciphertext.size() - crypto_secretbox_NONCEBYTES;

    Secret plaintext(actual_size - crypto_secretbox_MACBYTES);

    // the decrypt function, returns a zero if it succeeds
    if (crypto_secretbox_open_easy(
            plaintext.data,
            actual,
            actual_size,
            nonce.data(),
            key.data) != 0)
        throw std::runtime_error("Decryption failed. Invalid key or tampered data.");

    plaintext.used = plaintext.capacity;
    return plaintext;
}