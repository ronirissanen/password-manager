#include <vault.h>
#include <crypto.h>
#include <fstream>

std::map<string, Entry> entries;

void Vault::load()
{

}

void Vault::save()
{
}

void addEntry(const Entry &entry)
{
    entries[entry.name] = entry;
}

Entry getEntry(const string &name)
{
    return entries[name];
}

void deleteEntry(const string &name)
{
    entries.erase(name);
}

vector<string> listEntries()
{
    vector<string> names;
    for(const auto& pair: entries)
    {
        names.push_back(pair.first);
    }
    return names;
}

string serialize()
{
}
void deserialize(const string &data)
{
}