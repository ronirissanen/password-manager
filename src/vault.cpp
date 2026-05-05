#include <vault.h>
#include <crypto.h>
#include <serial.h>
#include <secret.h>
#include <secure_memory.h>
#include <fstream>
#include <sstream>
#include <vector>
using std::string;
using std::vector;

Vault::Vault(const std::string &path, Secret password)
    : path(path), masterPassword(std::move(password)) {}

void Vault::lock()
{
    entries.clear();
}

void Vault::unlock()
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
        return;

    // Read salt from the front of the file
    vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    file.read(reinterpret_cast<char *>(salt.data()), salt.size());
    // If the data size is smaller than the salt size the file is empty or corrupt in some way.
    if (file.gcount() < (std::streamsize)salt.size())
        return;

    // Read remaining ciphertext
    vector<unsigned char> ciphertext(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    Secret derived(deriveKey(masterPassword, salt));
    Secret plaintext(decrypt(ciphertext, derived));
    deserialize(plaintext);
    plaintext.wipe();
}

// Known bug that can affect future code paths;
// if save is called without re-deriving the key in memory won't match the salt on disk.
void Vault::save()
{
    auto salt = generateSalt();
    Secret derived = deriveKey(masterPassword, salt);
    Secret plaintext = serialize();
    vector<unsigned char> ciphertext = encrypt(plaintext, derived);
    plaintext.wipe();

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open())
        throw std::runtime_error("Cannot open vault file for writing.");

    // write [salt][ciphertext]
    file.write(reinterpret_cast<const char *>(salt.data()), salt.size());
    file.write(reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size());
}

void Vault::addEntry(string name, Entry entry)
{
    entries[std::move(name)] = std::move(entry);
}

const Entry *Vault::getEntry(const string &name)
{
    auto it = entries.find(name);
    if (it == entries.end())
        return nullptr;
    return &it->second;
}

void Vault::deleteEntry(const string &name)
{
    entries.erase(name);
}

vector<string> Vault::listEntries()
{
    vector<string> names;
    for (const auto &pair : entries)
    {
        names.push_back(pair.first);
    }
    return names;
}

Secret Vault::serialize()
{
    // Get size
    size_t total = 0;
    for (const auto &[name, e] : entries)
    {
        total += sizeof(uint32_t) + name.size();
        total += sizeof(uint32_t) + e.username.length();
        total += sizeof(uint32_t) + e.password.length();
    }

    Secret buf(total);
    size_t offset = 0;

    for (const auto &[name, e] : entries)
    {
        writeU32(buf.data, offset, (uint32_t)name.size());
        memcpy(buf.data + offset, name.data(), name.size());
        offset += name.size();

        writeU32(buf.data, offset, (uint32_t)e.username.length());
        memcpy(buf.data + offset, e.username.data, e.username.length());
        offset += e.username.length();

        writeU32(buf.data, offset, (uint32_t)e.password.length());
        memcpy(buf.data + offset, e.password.data, e.password.length());
        offset += e.password.length();
    }

    buf.used = offset;
    return buf;
}

void Vault::deserialize(const Secret &plaintext)
{
    entries.clear();
    const unsigned char *src = plaintext.data;
    size_t offset = 0;
    size_t sz = plaintext.length();

    while (offset < sz)
    {
        uint32_t name_len = readU32(src, offset, sz);
        if (offset + name_len > sz)
            throw std::runtime_error("Deserialize: truncated name.");
        string name(reinterpret_cast<const char *>(src + offset), name_len);
        offset += name_len;

        uint32_t uname_len = readU32(src, offset, sz);
        if (offset + uname_len > sz)
            throw std::runtime_error("Deserialize: truncated username");
        Secret username(uname_len ? uname_len : 1);
        memcpy(username.data, src + offset, uname_len);
        username.used = uname_len;
        offset += uname_len;

        uint32_t pass_len = readU32(src, offset, sz);
        if (offset + pass_len > sz)
            throw std::runtime_error("Deserialize: truncated password");
        Secret password(pass_len ? pass_len : 1);
        memcpy(password.data, src + offset, pass_len);
        password.used = pass_len;
        offset += pass_len;

        entries.emplace(std::move(name), Entry(std::move(username), std::move(password)));
    }
}