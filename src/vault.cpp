#include <vault.h>
#include <crypto.h>
#include <secure_memory.h>
#include <fstream>
#include <sstream>
#include <vector>
using std::string;
using std::vector;

Vault::Vault(const std::string &path, Secret password)
    : path(path), key(std::move(password)) {}

void Vault::lock()
{
    entries.clear();
}

void Vault::unlock()
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
        return;

    vector<unsigned char> ciphertext(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    vector<unsigned char> plaintext = decrypt(ciphertext, key);
    string data(plaintext.begin(), plaintext.end());
    deserialize(data);
}

void Vault::save()
{
    string data = serialize();
    vector<unsigned char> plaintext(data.begin(), data.end());
    vector<unsigned char> ciphertext = encrypt(plaintext, key);

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open())
        throw std::runtime_error("Cannot open vault file for writing.");

    file.write((char *)ciphertext.data(), ciphertext.size());
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

string Vault::serialize()
{
    string data;
    for (const auto &pair : entries)
    {
        const Entry &e = pair.second;
        data += e.name + "\x1F" + e.username + "\x1F" + e.password + "\n";
    }
    return data;
}

void Vault::deserialize(const string &data)
{
    entries.clear();
    std::istringstream stream(data);
    string line;

    while (std::getline(stream, line, '\n'))
    {
        if (line.empty())
            continue;

        std::istringstream linestream(line);
        string name, username, password;

        std::getline(linestream, name, '\x1F');
        std::getline(linestream, username, '\x1F');
        std::getline(linestream, password, '\x1F');

        if (name.empty())
            continue;

        Entry e{name, username, password};
        entries[name] = e;
    }
}