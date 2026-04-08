#pragma once
#include <string>
#include <map>
#include <vector>
using std::string;
using std::vector;

struct Entry
{
    string name;        // may be redundant with the map key
    string username;
    string password;
};

class Vault
{
public:
    void load();
    void save();

    void addEntry(const Entry &entry);
    Entry getEntry(const string &name);
    void deleteEntry(const string &name);
    std::map<string, Entry> listEntries();

private:
    std::string path;
    std::vector<unsigned char> key;
    std::map<std::string, Entry> entries;

    string serialize();
    void deserialize(const string &data);
};