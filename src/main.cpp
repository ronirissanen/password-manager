#include <iostream>
#include "cli.h"
#include "vault.h"
#include "secure_memory.h"

constexpr char nl = '\n';

int main()
{

    if (sodium_init() < 0)
        throw std::runtime_error("libsodium init failed");
    setCoreDumpLimits();
    lockMemoryPages();

    try
    {
        CLI cli;
        cli.run();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal error: " << e.what() << '\n';
        return 1;
    }
    catch (...)
    {
        std::cerr << "Unknown error." << '\n';
        return 1;
    }

    return 0;
}
