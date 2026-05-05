#include <cli.h>
#include <vault.h>
#include <sodium.h>

#include <iostream>
#include <sstream>
#include <fstream>
#include <termios.h>
#include <unistd.h>
#include <string.h>

using std::string;
using std::vector;

// Write helpers to avoid leaking secrets to memory with std::cout
inline void print(const char *s)
{
    write(STDOUT_FILENO, s, strlen(s));
}

inline void printSecret(const Secret &s)
{
    write(STDOUT_FILENO, s.cdata(), s.length());
}

Secret CLI::promptPassword(const char *prompt)
{
    Secret password;

    // save current settings and disable echo
    termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0)
        throw std::runtime_error("tcgetattr failed");
    newt = oldt;
    newt.c_lflag &= ~ECHO;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0)
        throw std::runtime_error("tcsetattr failed");

    if (write(STDOUT_FILENO, prompt, strlen(prompt)) < 0)
        throw std::runtime_error("write failed");

    // Read input safely into pinned memory
    if (!fgets(password.cdata(), password.capacity, stdin))
    {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        throw std::runtime_error("Failed to read password");
    }

    // restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    write(STDOUT_FILENO, "\n", 1);

    // Remove newline and set used
    password.data[strcspn(password.cdata(), "\n")] = 0;
    password.used = strlen(password.cdata());

    return password;
}

void CLI::init()
{
    Secret password;

    while (true)
    {
        password = std::move(promptPassword("Master password: "));
        if (password.length() >= 16)
            break;
        print("Password too short.\n");
    }

    vault = Vault("pmgr.vault", std::move(password));
    vault.unlock();
    vault.save();
}

void CLI::handleAdd(const string &name)
{
    Secret username, password;

    print("Username: ");
    std::cin.getline(username.cdata(), username.capacity);
    username.used = strlen(username.cdata());

    print("Password ('generate' to randomise): ");
    std::cin.getline(password.cdata(), password.capacity);
    password.used = strlen(password.cdata());

    if (strcmp(password.cdata(), "generate") == 0)
        password = generatePassword();

    vault.addEntry(name, Entry(std::move(username), std::move(password)));
    vault.save();
}

void CLI::handleGet(const string &name)
{
    const Entry *entry = vault.getEntry(name);
    if (!entry)
    {
        print("Entry not found.\n");
        return;
    }

    print("Username: ");
    printSecret(entry->username);
    print("\n");
    print("Password: ");
    printSecret(entry->password);
    print("\n");
}

void CLI::handleList()
{
    vector<string> entries = vault.listEntries();
    for (const string &s : entries)
    {
        print(s.c_str());
        print("\n");
    }
}

void CLI::handleDelete(const string &name)
{
    vault.deleteEntry(name);
    vault.save();
}

vector<string> loadWordlist(const string &path)
{
    vector<string> words;
    std::ifstream file(path);
    if (!file.is_open())
        throw std::runtime_error("Failed to open wordlist.");
    string line;
    while (std::getline(file, line))
    {
        size_t tab = line.find('\t');
        if (tab != std::string::npos)
            words.push_back(line.substr(tab + 1));
    }
    return words;
}

Secret generatePassphrase(const vector<string> &words, int count)
{
    Secret passphrase(128);
    for (int i = 0; i < count; i++)
    {
        const string &word = words[randombytes_uniform((uint32_t)words.size())];
        memcpy(passphrase.data + passphrase.used, word.data(), word.size());
        passphrase.used += word.size();
        if (i < count - 1)
            passphrase.data[passphrase.used++] = '-';
    }
    return passphrase;
}

Secret CLI::generatePassword()
{
    const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    const int length = 20;
    Secret password;

    for (int i = 0; i < length; i++)
        password.append(charset[randombytes_uniform((uint32_t)charset.size())]);

    return password;
}

void CLI::run()
{
    init();
    string command, value, overflow;

    while (true)
    {
        print("pmgr> ");

        string line;
        std::getline(std::cin, line);
        std::istringstream stream(line);
        stream >> command >> value >> overflow;

        if (command == "exit" || command == "quit")
        {
            break;
        }
        else if (overflow.length() > 0)
        {
            printCommands();
        }
        else if (command == "help")
        {
            printCommands();
        }
        else if (command == "generate" && value.empty())
        {
            Secret pw = generatePassword();
            printSecret(pw);
            print("\n");
        }
        else if (command == "list" && value.empty())
        {
            handleList();
        }
        else if (value.empty())
        {
            print("Command requires an argument.\n");
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
            print("Invalid command. Use help to list valid commands.\n");
        }

        command = "";
        value = "";
        overflow = "";
    }

    vault.lock();
}

void CLI::printCommands()
{
    print("Commands:\n");
    print("  pmgr add <name>\n");
    print("  pmgr get <name>\n");
    print("  pmgr list\n");
    print("  pmgr delete <name>\n");
    print("  pmgr generate\n");
}
