#pragma once
#include <string>
#include <vault.h>

class CLI
{
public:
    void run();

private:
    Vault vault;
    void init();
    std::string promptPassword(const std::string &prompt);
    void handleAdd(const std::string &name);
    void handleGet(const std::string &name);
    void handleList();
    void handleDelete(const std::string &name);
    std::string generatePassword();
    void printCommands();
};