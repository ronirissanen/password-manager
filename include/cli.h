#pragma once
#include <string>
#include <vault.h>
#include <secret.h>

class CLI
{
public:
    void run();

private:
    Vault vault;
    void init();
    Secret promptPassword(const char *prompt);
    void handleList();
    void handleAdd(const std::string &name);
    void handleGet(const std::string &name);
    void handleDelete(const std::string &name);
    std::vector<std::string> loadWordlist(const std::string &path);
    Secret generatePassphrase(const std::vector<std::string> &words, int count);
    Secret generatePassword();
    void printCommands();
};