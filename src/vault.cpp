#include <vault.h>
#include <crypto.h>
#include <secure_memory.h>
#include <fstream>
#include <sstream>
#include <vector>
using std::string;
using std::vector;

Vault::Vault(const string &path, const string &password)
    : path(path), password(password) {}

void Vault::lock()
{
    for (auto &pair : entries)
    {
        secureZero(pair.second.username.data(), pair.second.username.size());
        secureZero(pair.second.password.data(), pair.second.password.size());
    }
    entries.clear();

    // There are arguments to also zero the password after very operation.
    // I chose not to for usability.
    secureZero(password.data(), password.size());
    password.clear();
}

void Vault::unlock()
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
        return;

    vector<unsigned char> ciphertext(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    vector<unsigned char> plaintext = decrypt(ciphertext, password);
    string data(plaintext.begin(), plaintext.end());
    deserialize(data);
}

void Vault::save()
{
    string data = serialize();
    vector<unsigned char> plaintext(data.begin(), data.end());
    vector<unsigned char> ciphertext = encrypt(plaintext, password);

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open())
        throw std::runtime_error("Cannot open vault file for writing.");

    file.write((char *)ciphertext.data(), ciphertext.size());
}

void Vault::addEntry(const Entry &entry)
{
    entries[entry.name] = entry;
}

Entry Vault::getEntry(const string &name)
{
    return entries[name];
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