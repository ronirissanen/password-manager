#ifndef SECRET_H
#define SECRET_H

#include <sodium.h>
#include <cstring>
#include <stdexcept>

class Secret
{
public:
    unsigned char *data;
    size_t capacity;
    size_t used;

    explicit Secret(size_t cap = 256) : capacity(cap)
    {
        data = (unsigned char *)sodium_malloc(capacity);
        if (!data)
            throw std::runtime_error("sodium_malloc failed");
        sodium_memzero(data, capacity);
    }

    Secret(const void *src, size_t len) : Secret(len)
    {
        memcpy(data, src, len);
    }

    // Move constructor -- transfers ownership of the memory
    Secret(Secret &&other) noexcept : data(other.data), capacity(other.capacity), used(other.used)
    {
        other.data = nullptr;
        other.capacity = 0;
        other.used = 0;
    }

    // Move assignment
    Secret &operator=(Secret &&other) noexcept
    {
        if (this != &other)
        {
            wipe();
            if (data)
                sodium_free(data);

            data = other.data;
            capacity = other.capacity;
            used = other.used;

            other.data = nullptr;
            other.capacity = 0;
            other.used = 0;
        }
        return *this;
    }

    // Destructor for exceptions and early returns
    // wipes (and unpins) memory
    ~Secret()
    {
        wipe();
        if (data)
            sodium_free(data);
    }

    // Disable copying to prevent accidental leaks into unprotected memory
    Secret(const Secret &) = delete;
    Secret &operator=(const Secret &) = delete;

    void wipe()
    {
        if (data)
            sodium_memzero(data, capacity);
        used = 0;
    }

    void append(char c)
    {
        if (used >= capacity)
            throw std::runtime_error("Secret buffer full");
        data[used++] = c;
    }

    // Returns how many bytes of real content data contains.
    size_t length() const { return used; }

    // A char* accessor. Casts data into char*
    char *cdata() { return reinterpret_cast<char *>(data); }
    const char *cdata() const { return reinterpret_cast<const char *>(data); }
};

#endif