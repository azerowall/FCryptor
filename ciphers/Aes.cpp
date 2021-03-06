#include "Aes.h"

const uint8_t Aes::SBox[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
const uint8_t Aes::InvSBox[256] = {
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};
const uint8_t Aes::Rcon[44] =
{
	0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00,
	0x10, 0x00, 0x00, 0x00,
	0x20, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00,
	0x80, 0x00, 0x00, 0x00,
	0x1b, 0x00, 0x00, 0x00,
	0x36, 0x00, 0x00, 0x00
};


inline uint8_t rj_xtime(uint8_t x)
{
	return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1);
}

// ============================= operations with state =============================

void Aes::SubBytes(uint8_t * state) const
{
	for (register uint8_t * p = state, *end = p + 16; p != end; p++)
		*p = SBox[*p];
}

void Aes::InvSubBytes(uint8_t * state) const
{
	for (register uint8_t * p = state, *end = p + 16; p != end; p++)
		*p = InvSBox[*p];
}

void Aes::ShiftRows(uint8_t * state) const
{
	register uint8_t temp1, temp2, temp3;

	// row 1
	temp1 = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = temp1;

	// row 2
	temp2 = state[6];
	state[6] = state[14];
	state[14] = temp2;
	temp2 = state[2];
	state[2] = state[10];
	state[10] = temp2;

	// row 3
	temp3 = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = state[3];
	state[3] = temp3;
}

void Aes::InvShiftRows(uint8_t * state) const
{
	register uint8_t temp1, temp2, temp3;

	// row 1
	temp1 = state[13];
	state[13] = state[9];
	state[9] = state[5];
	state[5] = state[1];
	state[1] = temp1;

	// row 2
	temp2 = state[6];
	state[6] = state[14];
	state[14] = temp2;
	temp2 = state[2];
	state[2] = state[10];
	state[10] = temp2;

	// row 3
	temp3 = state[3];
	state[3] = state[7];
	state[7] = state[11];
	state[11] = state[15];
	state[15] = temp3;
}

void Aes::MixColumns(uint8_t * state) const
{
	register uint8_t i, a, b, c, d, e;

	for (i = 0; i < 16; i += 4)
	{
		a = state[i];
		b = state[i + 1];
		c = state[i + 2];
		d = state[i + 3];

		e = a ^ b ^ c ^ d;

		state[i] ^= e ^ rj_xtime(a^b);
		state[i + 1] ^= e ^ rj_xtime(b^c);
		state[i + 2] ^= e ^ rj_xtime(c^d);
		state[i + 3] ^= e ^ rj_xtime(d^a);
	}
}

void Aes::InvMixColumns(uint8_t * state) const
{
	register uint8_t i, a, b, c, d, e, x, y, z;

	for (i = 0; i < 16; i += 4)
	{
		a = state[i];
		b = state[i + 1];
		c = state[i + 2];
		d = state[i + 3];

		e = a ^ b ^ c ^ d;
		z = rj_xtime(e);
		x = e ^ rj_xtime(rj_xtime(z^a^c));  y = e ^ rj_xtime(rj_xtime(z^b^d));

		state[i] ^= x ^ rj_xtime(a^b);
		state[i + 1] ^= y ^ rj_xtime(b^c);
		state[i + 2] ^= x ^ rj_xtime(c^d);
		state[i + 3] ^= y ^ rj_xtime(d^a);
	}
}

void Aes::AddRoundKey(uint8_t * state, const uint8_t * roundKey) const
{
	// т.к. blocksize всегда = 4, то мы можем рассматривать столбцы как uint32_t
	*(uint32_t *)state ^= *(uint32_t *)roundKey;
	*((uint32_t *)state + 1) ^= *((uint32_t *)roundKey + 1);
	*((uint32_t *)state + 2) ^= *((uint32_t *)roundKey + 2);
	*((uint32_t *)state + 3) ^= *((uint32_t *)roundKey + 3);
}


// ============================= operations with key =============================

void Aes::KeyExpansion(const uint8_t * key, uint32_t * exKey) const
{
	for (int i = Nk * 8; i >= 0; i--)
		((uint8_t *)exKey)[i] = key[i];

	uint32_t temp;
	int end = Nb * (Nr + 1);
	for (int i = Nk; i < end; i++)
	{
		temp = exKey[i - 1];
		if (i % Nk == 0)
			temp = SubWord((temp << 8) | (temp >> 24)) ^ Rcon[i / Nk];
		else if (Nk > 6 && i % Nk == 4)	// для AES-256
			temp = SubWord(temp);

		exKey[i] = exKey[i - Nk] ^ temp;
	}
}

uint32_t Aes::SubWord(uint32_t word) const
{
	*((uint8_t *)&word    ) = SBox[*((uint8_t *)&word    )];
	*((uint8_t *)&word + 1) = SBox[*((uint8_t *)&word + 1)];
	*((uint8_t *)&word + 2) = SBox[*((uint8_t *)&word + 2)];
	*((uint8_t *)&word + 3) = SBox[*((uint8_t *)&word + 3)];
	return word;
}


// ============================= encrypting and decrypting =============================

void Aes::Cipher(uint8_t * block) const
{
	uint8_t * state = block;

	AddRoundKey(state, (uint8_t *)roundKey);

	for (uint8_t round = 1; round < Nr; round++)
	{
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, (uint8_t *)(roundKey + round * Nb));
	}

	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, (uint8_t *)(roundKey + Nr * Nb));
}

void Aes::InvCipher(uint8_t * block) const
{
	uint8_t * state = block;

	AddRoundKey(state, (uint8_t *)(roundKey + Nr * Nb));

	for (uint8_t round = Nr - 1; round > 0; round--)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, (uint8_t *)(roundKey + round * Nb));
		InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, (uint8_t *)roundKey);

}

////////////////////////////////////////////////////////

void Aes::EncryptBlock(uint8_t * block) const
{
	Cipher(block);
}

void Aes::DecryptBlock(uint8_t * enc_block) const
{
	InvCipher(enc_block);
}