#pragma once
#include <string>
#include <map>
#include <vector>
#include <secret.h>

struct Entry
{
    Secret username;
    Secret password;

    Entry(Secret u, Secret p)
        : username(std::move(u)), password(std::move(p)) {}
    Entry() = default;
};

class Vault
{
public:
    void unlock();
    void save();
    void lock();

    void addEntry(std::string name, Entry entry);
    const Entry *getEntry(const std::string &name);
    void deleteEntry(const std::string &name);
    std::vector<std::string> listEntries();

    Vault(const std::string &path, Secret password);
    Vault() = default;

private:
    std::vector<unsigned char> salt;
    std::string path;
    Secret masterPassword;
    std::map<std::string, Entry> entries;

    Secret serialize();
    void deserialize(const Secret &data);
};