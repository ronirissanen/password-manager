#pragma once
#include <string>

class CLI
{
public:
    void run(int argc, char *argv[]);

private:
    Vault vault;
    void handleAdd(const std::string &name);
    void handleGet(const std::string &name);
    void handleList();
    void handleDelete(const std::string &name);
    void handleGenerate();
    void printCommands();
};