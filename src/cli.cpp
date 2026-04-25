#include <cli.h>
#include <vault.h>
#include <sodium.h>

#include <iostream>
#include <sstream>
#include <limits>
#include <termios.h>
#include <unistd.h>
#include <string.h>

using std::cin;
using std::cout;
using std::string;
using std::vector;

constexpr char nl = '\n';

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

    // Low level system call to print prompt
    if (write(STDOUT_FILENO, prompt, strlen(prompt)) < 0)
        throw std::runtime_error("write failed");

    // Read input safely
    if (!fgets(password.cdata(), password.capacity, stdin))
    {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        throw std::runtime_error("Failed to read password");
    }

    // restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    write(STDOUT_FILENO, "\nl", 1);

    // Remove new line
    password.data[strcspn(password.cdata(), "\n")] = 0;

    // Move semantics should transfer ownership
    return password;
}

void CLI::init()
{
    cin.clear();
    Secret password;

    while (true)
    {
        password = std::move(promptPassword("Master password: "));
        if (password.length() >= 16)
            break;

        write(STDOUT_FILENO, "Password too short.\n", 20);
    }

    vault = Vault("pmgr.vault", std::move(password));
    vault.unlock();
    vault.save(); // save to make sure a file exists.
}

void CLI::handleAdd(const string &name)
{
    Secret username, password;
    cout << "Username: ";
    // cin.getline to read directly into pinned memory
    cin.getline(username.cdata(), username.capacity);
    username.used = strlen(username.cdata());
    cout << "Password ('generate' to randomise): ";
    cin.getline(password.cdata(), password.capacity);
    password.used = strlen(password.cdata());
    if (strcmp(password.cdata(), "generate"))
        password = generatePassword();

    // vault.addEntry(Secret(value.data(), value.size()));
    vault.save();
}

void CLI::handleGet(const string &name)
{
    const Entry *entry = vault.getEntry(name);
    if (!entry)
    {
        cout << "Entry not found." << nl;
        return;
    }
    cout << "Username: ";
    cout.write(entry->username.cdata(), entry->username.length());
    cout << nl;
    cout << "Password: ";
    cout.write(entry->password.cdata(), entry->password.length());
    cout << nl;
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
    vault.save();
}

Secret CLI::generatePassword()
{
    const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    const int length = 20;
    Secret password;

    for (int i = 0; i < length; i++)
    {
        unsigned char random;
        randombytes_buf(&random, 1);
        // avoid modulo bias with randombytes_uniform from sodium
        password.append(charset[randombytes_uniform(charset.size())]);
    }

    return password;
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
            Secret pw = generatePassword();
            cout.write(pw.cdata(), pw.length());
            cout << nl;
        }
        else if (command == "list" && value.length() == 0 && overflow.length() == 0)
        {
            handleList();
        }
        else if (value.length() == 0)
        {
            cout << "Command requires an argument." << nl;
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