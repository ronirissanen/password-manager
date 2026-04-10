#include <sodium.h>
#include <string>
#include <map>
#include <vector>
#include <iostream>
using std::string;
using std::vector;

vector<unsigned char> deriveKey(
    const string &password, const vector<unsigned char> &salt)
{
    vector<unsigned char> key(crypto_secretbox_KEYBYTES);

    if (crypto_pwhash(
            key.data(),
            key.size(),
            password.c_str(),
            password.size(),
            salt.data(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
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

vector<unsigned char> encrypt(
    const vector<unsigned char> &plaintext,
    const string &password)
{
    // human memorable passwords are too weak to be keys
    // derive a real key from the password and a salt instead
    auto salt = generateSalt();
    auto key = deriveKey(password, salt);

    // generate a nonce (random number) for each encryption
    vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    // initialize cipher text with extra MAC bytes to detect tampering later
    vector<unsigned char> ciphertext(
        plaintext.size() + crypto_secretbox_MACBYTES);

    // libsodium function for encryption
    // generates ciphertext from plaintext using XSalsa20 stream cipher
    // Computes Poly1305 MAC over the ciphertext
    // Prepends the MAC to the ciphertext output
    crypto_secretbox_easy(
        ciphertext.data(),
        plaintext.data(),
        plaintext.size(),
        nonce.data(),
        key.data());

    // prepend nonce to ciphertext for storage
    // before: [MAC 16 bytes][ciphertext]
    // after:  [nonce 24 bytes][MAC 16 bytes][ciphertext]
    ciphertext.insert(ciphertext.begin(), nonce.begin(), nonce.end());

    // prepend salt too
    // final layout: [salt][nonce][MAC][cipher]
    ciphertext.insert(ciphertext.begin(), salt.begin(), salt.end());

    return ciphertext;
}

vector<unsigned char> decrypt(
    const vector<unsigned char> &ciphertext,
    const string &password)
{
    // peel salt first
    vector<unsigned char> salt(ciphertext.begin(), ciphertext.begin() + crypto_pwhash_SALTBYTES);
    vector<unsigned char> rest(ciphertext.begin() + crypto_pwhash_SALTBYTES, ciphertext.end());

    auto key = deriveKey(password, salt);

    // if ciphertext is smaller than nonce + MAC
    // anything smaller means nonce or MAC is incomplete
    // => corrupt or truncated data
    if (rest.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
        throw std::runtime_error("Ciphertext too short.");

    // peel nonce for decryption
    vector<unsigned char> nonce(rest.begin(), rest.begin() + crypto_secretbox_NONCEBYTES);
    vector<unsigned char> actual(rest.begin() + crypto_secretbox_NONCEBYTES, rest.end());
    vector<unsigned char> plaintext(actual.size() - crypto_secretbox_MACBYTES);

    // the decrypt function returns a zero if it succeeds
    if (crypto_secretbox_open_easy(
            plaintext.data(),
            actual.data(),
            actual.size(),
            nonce.data(),
            key.data()) != 0)
        throw std::runtime_error("Decryption failed. Invalid key or tampered data.");

    return plaintext;
}