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

// The compiler may not inline these due to syscalls write and read,
// I was just lazy with updating the .h file.

// Write helpers to avoid leaking secrets to memory with std::cout
inline void print(const char *s)
{
    write(STDOUT_FILENO, s, strlen(s));
}

inline void printSecret(const Secret &s)
{
    write(STDOUT_FILENO, s.cdata(), s.length());
}

// Read a line from stdin into a Secret without going through buffers
inline void readLine(Secret &s)
{
    s.wipe();
    char c;
    while (s.used < s.capacity - 1)
    {
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n <= 0 || c == '\n')
            break;
        s.append(c);
        sodium_memzero(&c, 1);
    }
}

inline string readString()
{
    string result;
    char c;
    while (read(STDIN_FILENO, &c, 1) == 1 && c != '\n')
        result += c;
    return result;
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

    readLine(password);

    // restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    write(STDOUT_FILENO, "\n", 1);

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
    readLine(username);

    print("Password ('phrase' or 'word' to randomise): ");
    readLine(password);

    // Note: can be fragile since Secret does not formally guarantee a null terminator
    if (strcmp(password.cdata(), "word") == 0)
        password = generatePassword();

    if (strcmp(password.cdata(), "phrase") == 0)
        password = generatePassphrase(wordlist);

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

void CLI::handleList(const string &_)
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

vector<string> CLI::loadWordlist(const string &path)
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

Secret CLI::generatePassphrase(const vector<string> &words, int count)
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

void CLI::printPassword(const string &_)
{
    Secret pw = generatePassword();
    printSecret(pw);
    print("\n");
}

void CLI::printPassphrase(const string &_)
{
    Secret pw = generatePassphrase(wordlist);
    printSecret(pw);
    print("\n");
}

void CLI::run()
{
    init();
    wordlist = loadWordlist("eff_large_wordlist.txt");

    static const Command commands[] = {
        {"add", true, &CLI::handleAdd},
        {"get", true, &CLI::handleGet},
        {"delete", true, &CLI::handleDelete},
        {"list", false, &CLI::handleList},
        {"password", false, &CLI::printPassword},
        {"passphrase", false, &CLI::printPassphrase},
        {"help", false, &CLI::printCommands},
    };

    // Control loop
    while (true)
    {
        print("pmgr> ");

        string line = readString();
        std::istringstream stream(line);
        string command, value, overflow;
        stream >> command >> value >> overflow;

        bool found = false;
        for (const auto &cmd : commands)
        {
            if (command == cmd.name)
            {
                if (cmd.requires_value && value.empty())
                    print("Command requires an argument.\n");
                else
                    (this->*cmd.handler)(value);
                found = true;
                break;
            }
        }
        if (!found)
            print("Invalid command, 'help' for list of commands.\n");
    }

    vault.lock();
}

void CLI::printCommands(const string &_)
{
    print("Commands:\n");
    print("  pmgr add <name>\n");
    print("  pmgr get <name>\n");
    print("  pmgr list\n");
    print("  pmgr delete <name>\n");
    print("  pmgr generate\n");
}
