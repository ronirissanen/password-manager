#pragma once
#include <cstdint>
#include <cstring>
#include <stdexcept>

// Write a 4-byte unsigned integer into a raw byte buffer.
inline void writeU32(unsigned char *dst, size_t &offset, uint32_t v)
{
    memcpy(dst + offset, &v, sizeof(v));
    offset += sizeof(v);
}

// Read and return a 4-byte unsigned integer from a raw byte buffer.
inline uint32_t readU32(const unsigned char *src, size_t &offset, size_t limit)
{
    if (offset + 4 > limit)
        throw std::runtime_error("readU32: buffer overrun");
    uint32_t v;
    memcpy(&v, src + offset, sizeof(v));
    offset += sizeof(v);
    return v;
}