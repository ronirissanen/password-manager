#pragma once
#include <string>
#include <map>
#include <vector>


struct Entry
{
    std::string name; // may be redundant with the map key
    std::string username;
    std::string password;
};

class Vault
{
public:
    void unlock();
    void save();
    void lock();

    void addEntry(const Entry &entry);
    Entry getEntry(const std::string &name);
    void deleteEntry(const std::string &name);
    std::vector<std::string> listEntries();

    Vault(const std::string &path, const std::string &password);
    Vault() = default;

private:
    std::string path;
    std::string password;
    std::map<std::string, Entry> entries;

    std::string serialize();
    void deserialize(const std::string &data);
};