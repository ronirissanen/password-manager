#include <iostream>
#include <sys/resource.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
using std::cout;
using std::endl;

void setCoreDumpLimits()
{
    struct rlimit limit;

    // set limits for core dumps to 0
    limit.rlim_cur = 0;
    limit.rlim_max = 0;

    if (setrlimit(RLIMIT_CORE, &limit) != 0)
    {
        throw std::runtime_error("Failed to disable core dumps.");
    }
    cout << "Core dumps disabled." << endl;
}

void lockMemoryPages()
{
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
        throw std::system_error(errno, std::generic_category(),
            "Failed to lock memory pages.");
}

void secureZero(void* addr, size_t size)
{
    explicit_bzero(addr, size);
}