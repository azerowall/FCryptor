#pragma once

#include "SymmetricBlockCipher.h"

/*
	KeyExpansion производится при каждом задании ключа (size = Nb * (Nr + 1) * 4 bytes)
	keyExp = 4 * 15 * 4 = 240 bytes (для AES-256)
*/

class Aes : public SymmetricBlockCipher
{
private:

	static const uint8_t SBox[256];
	static const uint8_t InvSBox[256];
	static const uint8_t Rcon[44];

	static const uint16_t Nb = 4;
	uint16_t Nk, Nr;

	uint32_t * roundKey;

public:
    Aes(uint32_t keySize) : SymmetricBlockCipher()
	{
        Nk = keySize / (8 * 4);
		switch (Nk)
		{
		case 4: Nr = 10; break;
		case 6: Nr = 12; break;
		case 8: Nr = 14; break;
		}

        key = new uint8_t[Nk * 4];
        ivec = new uint8_t[Nb * 4];
		roundKey = new uint32_t[Nb * (Nr + 1)];
	}
	~Aes()
	{
		SafeSetZero((uint8_t *)roundKey, Nb * (Nr + 1) * sizeof(uint32_t));
        SafeSetZero(key, Nk * 4);
		delete[] roundKey;
        delete[] key;
        delete[] ivec;
	}

	void SetKey(const uint8_t * key) override {
		SymmetricBlockCipher::SetKey(key);
		KeyExpansion(key, roundKey);
	}

	//uint32_t BlockSize() override { return 128; }
	//uint32_t KeySize() override { return Nk * 8 * 4; }

	uint32_t BlockSizeInBytes() const override { return 16; }
	uint32_t KeySizeInBytes() const override { return Nk * 4; }

	static void InitTables();

protected:
	void EncryptBlock(uint8_t * block) const override;
	void DecryptBlock(uint8_t * enc_block) const override;



private:

	void SubBytes(uint8_t * state) const;
	void InvSubBytes(uint8_t * state) const;

	void ShiftRows(uint8_t * state) const;
	void InvShiftRows(uint8_t * state) const;

	void MixColumns(uint8_t * state) const;
	void InvMixColumns(uint8_t * state) const;

	void AddRoundKey(uint8_t * state, const uint8_t * roundKey) const;

	uint32_t SubWord(uint32_t word) const;
	void KeyExpansion(const uint8_t * key, uint32_t * exKey) const;

	void Cipher(uint8_t * block) const;
	void InvCipher(uint8_t * block) const;
};
