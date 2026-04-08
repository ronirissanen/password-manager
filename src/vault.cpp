#include <vault.h>
#include <crypto.h>
#include <fstream>

void Vault::load()
{

}

void Vault::save()
{
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
    for(const auto& pair: entries)
    {
        names.push_back(pair.first);
    }
    return names;
}

string Vault::serialize()
{
}
void Vault::deserialize(const string &data)
{
}