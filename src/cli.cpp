#include <iostream>
#include <sstream>
#include <fstream>

#include <sodium.h>
#include <sys/wait.h>
#include <signal.h>

#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <cli.h>
#include <vault.h>

using std::string;
using std::vector;

const CLI::Command CLI::commands[] = {
    {"add", true, &CLI::handleAdd},
    {"show", true, &CLI::handleShow},
    {"copy", true, &CLI::handleCopy},
    {"delete", true, &CLI::handleDelete},
    {"list", false, &CLI::handleList},
    //{"password", false, &CLI::printPassword},         --segfault bug with these atm
    //{"passphrase", false, &CLI::printPassphrase},
    {"help", false, &CLI::printCommands},
};

// Write helpers to avoid leaking secrets to memory with std::cout or other buffers
void print(const char *s)
{
    write(STDOUT_FILENO, s, strlen(s));
}

void printSecret(const Secret &s)
{
    write(STDOUT_FILENO, s.cdata(), s.length());
}

// Read a line from stdin into a Secret without going through buffers
void readLine(Secret &s)
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

string readString()
{
    string result;
    char c;
    while (read(STDIN_FILENO, &c, 1) == 1 && c != '\n')
        result += c;
    return result;
}

bool isValidEntryName(const char *buf, size_t len)
{
    // Strict length validation
    if (len == 0 || len > 64)
        return false;

    for (size_t i = 0; i < len; ++i)
    {
        char c = buf[i];
        // Whitelist: Allow only alpha-numeric, underscore, and dash
        if (!isalnum(c) && c != '_' && c != '-')
        {
            return false;
        }
    }
    return true;
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

void CLI::handleShow(const string &name)
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

void CLI::handleCopy(const string &name)
{
    const Entry *entry = vault.getEntry(name);
    if (!entry)
    {
        print("Name not found.");
        return;
    }
    copyToClipboard(entry->username);
    print("Username copied. Press enter to copy password.\n");
    readString(); // readString reads until newline (enter)

    copyToClipboard(entry->password);
    print("Password copied. Press enter to clear clipboard.\n");
    readString();

    clearClipboard();
}

const char *clipCommand()
{
    static const char *cmd = nullptr;
    if (cmd)
        return cmd;

    if (system("which xclip > /dev/null 2>&1") == 0)
        cmd = "xclip -selection clipboard";
    else if (system("which clip.exe > /dev/null 2>&1") == 0)
        cmd = "clip.exe";
    else
        throw std::runtime_error("No clipboard utility found");

    return cmd;
}

void CLI::copyToClipboard(const Secret &s)
{
    // kill previous timer if still running
    if (clipboardTimer > 0)
    {
        kill(clipboardTimer, SIGTERM);
        waitpid(clipboardTimer, nullptr, 0);
    }

    FILE *pipe = popen(clipCommand(), "w");
    if (!pipe)
        throw std::runtime_error("Clipboard not available.");
    fwrite(s.data, 1, s.used, pipe);
    fflush(pipe);
    pclose(pipe);

    clipboardTimer = fork();
    if (clipboardTimer == 0)
    {
        sleep(30);
        clearClipboard();
        exit(0);
    }
}

void CLI::clearClipboard()
{
    FILE *pipe = popen(clipCommand(), "w");
    if (!pipe)
        throw std::runtime_error("Clipboard not available.");
    pclose(pipe); // writes nothing, clears clipboard
}

void CLI::run()
{
    init();
    wordlist = loadWordlist("../data/eff_large_wordlist.txt");
    clipCommand();

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
                else if (cmd.requires_value && !isValidEntryName(value.c_str(), value.size()))
                    print("Invalid entry name.\n");
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
    for (const auto &cmd : commands)
    {
        print("  pmgr ");
        print(cmd.name);
        if (cmd.requires_value)
            print(" <entry name>");
        print("\n");
    }
}
