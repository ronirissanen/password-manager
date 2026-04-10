#pragma once
#include <string>
#include <map>
#include <vector>
using std::string;
using std::vector;

struct Entry
{
    string name; // may be redundant with the map key
    string username;
    string password;
};

class Vault
{
public:
    void unlock();
    void save();
    void lock();

    void addEntry(const Entry &entry);
    Entry getEntry(const string &name);
    void deleteEntry(const string &name);
    vector<string> listEntries();

private:
    string path;
    string password;
    std::map<string, Entry> entries;

    string serialize();
    void deserialize(const string &data);
};