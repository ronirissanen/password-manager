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
    Secret generatePassword();
    void printCommands();
};