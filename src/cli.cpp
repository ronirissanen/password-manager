#include "cli.h"
#include <iostream>

void CLI::handleAdd(const std::string& name)
{
    std::cout << "add: " << name << std::endl;
}

void CLI::handleGet(const std::string& name)
{
    std::cout << "get: " << name << std::endl;
}

void CLI::handleList()
{
    std::cout << "list" << std::endl;
}

void CLI::handleDelete(const std::string& name)
{
    std::cout << "delete: " << name << std::endl;
}

void CLI::handleGenerate()
{
    std::cout << "generate" << std::endl;
}

void CLI::run(int argc, char* argv[])
{
    if (argc < 2)
    {
        printUsage();
        return;
    }

    std::string command = argv[1];

    if (command == "add")
    {
        if (argc < 3)
            throw std::runtime_error("add requires an entry name.");
        handleAdd(argv[2]);
    }
    else if (command == "get")
    {
        if (argc < 3)
            throw std::runtime_error("get requires an entry name.");
        handleGet(argv[2]);
    }
    else if (command == "list")
    {
        handleList();
    }
    else if (command == "delete")
    {
        if (argc < 3)
            throw std::runtime_error("delete requires an entry name.");
        handleDelete(argv[2]);
    }
    else if (command == "generate")
    {
        handleGenerate();
    }
    else
    {
        printUsage();
    }
}

void CLI::printUsage()
{
    std::cout << "Usage:" << std::endl;
    std::cout << "  pmgr add <name>" << std::endl;
    std::cout << "  pmgr get <name>" << std::endl;
    std::cout << "  pmgr list" << std::endl;
    std::cout << "  pmgr delete <name>" << std::endl;
    std::cout << "  pmgr generate" << std::endl;
}