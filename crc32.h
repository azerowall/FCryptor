#ifndef CRC32_H
#define CRC32_H

#include <cstdint>

class Crc32
{
public:
    static uint32_t GetHash(const char * data, size_t dataSize);
};

#endif // CRC32_H
