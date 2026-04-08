#include <iostream>
#include "cli.h"
#include "vault.h"
#include "secure_memory.h"

int main(int argc, char *argv[])
{
    setCoreDumpLimits();
    lockMemoryPages();

    try
    {
        CLI cli;
        cli.run(argc, argv);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "Unknown error." << std::endl;
        return 1;
    }

    return 0;
}
