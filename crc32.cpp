#include "crc32.h"

uint32_t Crc32::GetHash(const char *data, size_t dataSize)
{
    const uint32_t POLY = 0x82f63b78;
    int k;
    uint32_t crc = 0;

    crc = ~crc;
    while (dataSize--) {
        crc ^= *data++;
        for (k = 0; k < 8; k++)
            crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    }
    return ~crc;
}
