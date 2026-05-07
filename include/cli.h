#pragma once
#include <string>
#include <vault.h>
#include <secret.h>

class CLI
{
public:
    void run();

private:
    struct Command
    {
        const char *name;
        bool requires_value;
        void (CLI::*handler)(const std::string &);
    };
    static const Command commands[];

    pid_t clipboardTimer;
    std::vector<std::string> wordlist;
    Vault vault;
    void init();
    Secret promptPassword(const char *prompt);
    std::vector<std::string> loadWordlist(const std::string &path);
    Secret generatePassphrase(const std::vector<std::string> &words, int count = 4);
    Secret generatePassword();

    void handleList(const std::string &_);
    void handleAdd(const std::string &name);
    void handleShow(const std::string &name);
    void handleDelete(const std::string &name);
    void handleCopy(const std::string &name);
    void copyToClipboard(const Secret &s);
    void clearClipboard();
    void printPassphrase(const std::string &_);
    void printPassword(const std::string &_);
    void printCommands(const std::string &_);
};