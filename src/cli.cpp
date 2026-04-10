#include <cli.h>
#include <vault.h>
#include <sodium.h>
#include <iostream>
using std::cin;
using std::cout;
using std::endl;
using std::string;

void CLI::handleAdd(const string &name)
{
    string username, password;
    cout << "Username: ";
    cin >> username;
    cout << "Password: ";
    cin >> password;

    vault.unlock();
    vault.addEntry({name, username, password});
    vault.save();
}

void CLI::handleGet(const string &name)
{
    vault.unlock();
    Entry entry = vault.getEntry(name);
    cout << "Name: " + entry.name + " Username: " + entry.username + " Password: " + entry.password << endl;
    vault.lock();
}

void CLI::handleList()
{
    vault.unlock();
    vector<string> entries = vault.listEntries();
    for (const string &s : entries)
    {
        cout << s << endl;
    }
    vault.lock();
}

void CLI::handleDelete(const string &name)
{
    vault.unlock();
    vault.deleteEntry(name);
    vault.lock();
}

void CLI::handleGenerate()
{
    const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    const int length = 20;
    string password;

    for (int i = 0; i < length; i++)
    {
        unsigned char random;
        randombytes_buf(&random, 1);
        // avoid modulo bias with randombytes_uniform from sodium
        password += charset[randombytes_uniform(charset.size())];
    }

    cout << password << endl;
}

void CLI::run(int argc, char *argv[])
{
    if (argc < 2)
    {
        printCommands();
        return;
    }

    string command = argv[1];

    if (command == "add")
    {
        if (argc < 3)
            throw std::runtime_error("add requires an entry name.");
        handleAdd(argv[2]);
    }
    else if (command == "get")
    {
        if (argc < 3)
            throw std::runtime_error("get requires an entry name.");
        handleGet(argv[2]);
    }
    else if (command == "list")
    {
        handleList();
    }
    else if (command == "delete")
    {
        if (argc < 3)
            throw std::runtime_error("delete requires an entry name.");
        handleDelete(argv[2]);
    }
    else if (command == "generate")
    {
        handleGenerate();
    }
    else
    {
        printCommands();
    }
}

void CLI::printCommands()
{
    cout << "Commands:" << endl;
    cout << "  pmgr add <name>" << endl;
    cout << "  pmgr get <name>" << endl;
    cout << "  pmgr list" << endl;
    cout << "  pmgr delete <name>" << endl;
    cout << "  pmgr generate" << endl;
}