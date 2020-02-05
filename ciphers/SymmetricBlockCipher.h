#pragma once

#include <cstdint>
#include <vector>
#include <iostream>

class SymmetricBlockCipher
{
public:
	enum ModeType
	{
		ECB, CBC, PCBC, CFB, OFB, CTR
	};
	enum PaddingType
	{
		X923, PKCS7, ISO10126
	};

protected:

	// количество блоков, выделяемых при шифровании потоков
	// crypt buffer size = BlockSizeInBytes * blocksCountForBuffer
	uint32_t blocksCountForBuffer;

	ModeType cipherMode;
	PaddingType paddingMode;

	uint8_t * key;			// size == KeySizeInBytes

	uint8_t * ivec;			// size == BlockSizeInBytes

public:


    SymmetricBlockCipher();

    virtual ~SymmetricBlockCipher();


	// возвращает размер блока в битах
	virtual uint32_t BlockSize() const { return BlockSizeInBytes() * 8; }

	// возвращает размер ключа в битах
    virtual uint32_t KeySize() const { return KeySizeInBytes() * 8; }

	// возвращает размер блока в байтах
	virtual uint32_t BlockSizeInBytes() const = 0;

	// возвращает размер ключа в байтах
	virtual uint32_t KeySizeInBytes() const = 0;

	ModeType GetCipherMode() const { return cipherMode; }
	void SetCipherMode(ModeType m) { cipherMode = m; }

	PaddingType GetPaddingMode() const { return paddingMode; }
	void SetPaddingMode(PaddingType p) { paddingMode = p; }

	// размер key == длине ключа в байтах
	virtual void SetKey(const uint8_t * key);

	// размер key == длине ключа в байтах
	void GetKey(uint8_t * key) const;

	// размер iv == длине блока в байтах
	void SetIV(const uint8_t * iv);

	// размер iv == длине блока в байтах
	void GetIV(uint8_t * iv) const;

	// размер в байтах; будет выровнен по размеру блока в меньшую сторону;
	// минимальный размер - 2 * BlockSizeInBytes()
	void SetBufferSizeForStreamCryption(size_t size);

public:

	// вектор инициализации в выходной поток не добавляется
    void Encrypt(std::istream & data, std::ostream & enc_data) const;

    void Decrypt(std::istream & enc_data, std::ostream & data) const;

	void Encrypt(std::vector<char> & data) const;

	void Decrypt(std::vector<char> & enc_data) const;
	


protected:

	// размер block == длине блока в байтах
	virtual void EncryptBlock(uint8_t * block) const = 0;

	// размер block == длине блока в байтах
	virtual void DecryptBlock(uint8_t * enc_block) const = 0;

	void SafeSetZero(uint8_t * mem, size_t memsize);
	//void XorBuf(uint8_t * mem1, uint8_t * mem2, size_t memsize);

private:

	/*
	Шифрует первый блок используя вектор инициализации
	Вектор инициализации НЕ добавляется в виде отдельного блока
	*/
	void EncryptStart(uint8_t * data)const;

	/*
	Шифрует промежуточные блоки
	Шифрование начинается со второго блока: т.к. в некоторых режимах
	предыдущий блок используется для шифрования последующего

	IN data - данные для шифрования
	IN blocksCount - кол-во блоков (начиная со второго) для шифрования в data
	IN dataPrevBlock - не зашифрованные данные предыдущего блока
	*/
	void EncryptNext(uint8_t * data, uint32_t blocksCount, uint8_t * dataPrevBlock)const;


	// расшифровка начала данных
	void DecryptStart(uint8_t * enc_data)const;

	/*
	Расшифровывает промежуточные блоки
	Расшифровка начинается со второго блока: т.к. в некоторых режимах
	предыдущий блок используется для шифрования последующего

	IN enc_data - зашифрованные данные для расшифровки
	IN blocksCount - кол-во блоков (начиная со второго) для расшифровки в data
	IN enc_dataPrevBlock - зашифрованные данные предыдущего блока
	*/
	void DecryptNext(uint8_t * enc_data, uint32_t blocksCount, uint8_t * enc_dataPrevBlock)const;


	/*
	IN occupedSize - длина используемых данных, которая должна быть выровнена
	В случае если occupedSize кратен размеру блока - размер паддинга будет равен размеру блока
	т.е. будет добавлен еще один блок

	RETURN - выровненная длина используемых данных
	*/
	size_t SetPadding(uint8_t * data, size_t occupedSize)const;

	/*
	RETURN - длина данных, которая была до выравнивания
	*/
	size_t RemovePadding(uint8_t * data, size_t occupedSize)const;
};
