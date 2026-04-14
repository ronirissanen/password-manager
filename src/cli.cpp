#include <cli.h>
#include <vault.h>
#include <sodium.h>
#include <iostream>
#include <sstream>
#include <limits>
#include <termios.h>
#include <unistd.h>

using std::cin;
using std::cout;
using std::string;
using std::vector;

constexpr char nl = '\n';

string CLI::promptPassword(const string &prompt)
{
    cout << prompt << std::flush;

    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt); // save current settings
    newt = oldt;
    newt.c_lflag &= ~ECHO; // disable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    string password;
    std::getline(cin, password); // read full line

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // restore
    cout << '\n';

    return password;
}

void CLI::init()
{
    // Get master password from user input
    string password;
    cin.clear();
    while (true)
    {
        password = promptPassword("Master password: ");
        if (password.length() >= 12)
            break;

        cout << "Password too short." << nl;
    }
    vault = Vault("pmgr.vault", password);
    vault.unlock();
    vault.save(); // save to make sure a file exists.
}

void CLI::handleAdd(const string &name)
{
    string username, password;
    cout << "Username: ";
    std::getline(cin, username);
    cout << "Password: ";
    std::getline(cin, password);

    vault.addEntry({name, username, password});
    vault.save();
}

void CLI::handleGet(const string &name)
{
    Entry entry = vault.getEntry(name);
    cout << "Name: " + entry.name << nl;
    cout << "Username: " + entry.username << nl;
    cout << "Password: " + entry.password << nl;
}

void CLI::handleList()
{
    vector<string> entries = vault.listEntries();
    for (const string &s : entries)
    {
        cout << s << nl;
    }
}

void CLI::handleDelete(const string &name)
{
    vault.deleteEntry(name);
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

    cout << password << nl;
}

void CLI::run()
{
    init();
    string command = "";
    string value = "";
    string overflow = "";
    while (true)
    {
        cout << "pmgr> ";

        // get and parse input line
        string line;
        getline(cin, line);
        std::istringstream stream(line);
        stream >> command >> value >> overflow;

        if (command == "exit" || command == "quit")
        {
            break;
        }
        else if (overflow.length() > 0)
        {
            printCommands();
            continue;
        }
        else if (command == "help")
        {
            printCommands();
        }
        else if (command == "generate" && value.length() == 0 && overflow.length() == 0)
        {
            handleGenerate();
        }
        else if (command == "list" && value.length() == 0 && overflow.length() == 0)
        {
            handleList();
        }
        else if (value.length() == 0)
        {
            continue;
        }
        else if (command == "add")
        {
            handleAdd(value);
        }
        else if (command == "get")
        {
            handleGet(value);
        }
        else if (command == "delete")
        {
            handleDelete(value);
        }
        else
        {
            cout << "Invalid command. Use help to list valid commands.";
        }

        command = "";
        value = "";
        overflow = "";
    }
    vault.lock();
}

void CLI::printCommands()
{
    cout << "Commands:" << nl;
    cout << "  pmgr add <name>" << nl;
    cout << "  pmgr get <name>" << nl;
    cout << "  pmgr list" << nl;
    cout << "  pmgr delete <name>" << nl;
    cout << "  pmgr generate" << nl;
}