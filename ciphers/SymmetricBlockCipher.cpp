#include "SymmetricBlockCipher.h"
#include <iostream>

SymmetricBlockCipher::SymmetricBlockCipher()
{
	blocksCountForBuffer = 2;
	paddingMode = X923;
	cipherMode = ECB;
}
SymmetricBlockCipher::~SymmetricBlockCipher()
{}

void SymmetricBlockCipher::SetBufferSizeForStreamCryption(size_t size)
{
	blocksCountForBuffer = size / BlockSizeInBytes();
	if (blocksCountForBuffer < 2)
		blocksCountForBuffer = 2;
}

void SymmetricBlockCipher::SetKey(const uint8_t * k)
{
	uint32_t keySize = KeySizeInBytes();
	for (int i = 0; i < keySize; i++)
		key[i] = k[i];
}
void SymmetricBlockCipher::GetKey(uint8_t * k) const
{
	uint32_t keySize = KeySizeInBytes();
	for (int i = 0; i < keySize; i++)
		k[i] = key[i];
}


void SymmetricBlockCipher::SetIV(const uint8_t * v)
{
	uint32_t blockSize = BlockSizeInBytes();
	for (int i = 0; i < blockSize; i++)
		ivec[i] = v[i];
}
void SymmetricBlockCipher::GetIV(uint8_t * v) const
{
	uint32_t blockSize = BlockSizeInBytes();
	for (int i = 0; i < blockSize; i++)
		v[i] = ivec[i];
}

////////////////////////////////////////////////////////////////////////////////
// ENCRYPT

void SymmetricBlockCipher::Encrypt(std::istream & data, std::ostream & enc_data) const
{
	uint32_t bufferSize = BlockSizeInBytes() * blocksCountForBuffer;
	uint8_t * buffer = new uint8_t[bufferSize];
	uint32_t blockSize = BlockSizeInBytes();
	uint32_t sizeWithPadding;

    //size_t encryptedSize = 0;

	uint8_t * block_buffer = new uint8_t[blockSize * 2];
	uint8_t * p_prev = block_buffer, *p_cur = block_buffer + blockSize, *p_temp;

	if (data.read((char *)buffer, blockSize))
	{
		memcpy(p_prev, buffer, blockSize);
		EncryptStart(buffer);
		enc_data.write((char *)buffer, blockSize);

        //encryptedSize += blockSize;
        //if (callback) callback(encryptedSize);
	}
	else
	{
		memcpy(p_prev, buffer, blockSize);
		sizeWithPadding = SetPadding(buffer, data.gcount());
		EncryptStart(buffer);
		enc_data.write((char *)buffer, blockSize);

        //encryptedSize += data.gcount();
        //if (callback) callback(encryptedSize);

		delete[] buffer;
		delete[] block_buffer;
		return;
	}

	while (data.read((char *)buffer + blockSize, bufferSize - blockSize))
	{
		memcpy(p_cur, buffer + bufferSize - blockSize, blockSize);

		EncryptNext(buffer, blocksCountForBuffer - 1, p_prev);

		memcpy(buffer, buffer + bufferSize - blockSize, blockSize);

		enc_data.write((char *)buffer + blockSize, bufferSize - blockSize);

		p_temp = p_prev;
		p_prev = p_cur;
		p_cur = p_temp;

        //encryptedSize += bufferSize - blockSize;
        //if (callback) callback(encryptedSize);
	}

	sizeWithPadding = SetPadding(buffer + blockSize, data.gcount());
	EncryptNext(buffer, sizeWithPadding / blockSize, p_prev);
	enc_data.write((char *)buffer + blockSize, sizeWithPadding);

    //encryptedSize += data.gcount();
    //if (callback) callback(encryptedSize);

	delete[] buffer;
	delete[] block_buffer;
}


////////////////////////////////////////////////////////////////////////////////
// DECRYPT

void SymmetricBlockCipher::Decrypt(std::istream & enc_data, std::ostream & data) const
{
	uint32_t bufferSize = BlockSizeInBytes() * blocksCountForBuffer;
	uint8_t * buffer = new uint8_t[bufferSize];
	uint32_t blockSize = BlockSizeInBytes();
	uint32_t sizeWithoutPadding;

    //size_t decryptedSize = 0;

	uint8_t * block_buffer = new uint8_t[blockSize * 2];
	uint8_t * p_prev = block_buffer, *p_cur = block_buffer + blockSize, *p_temp;

	if (enc_data.read((char *)buffer, blockSize * 2))
	{
		memcpy(p_prev, buffer, blockSize);
		DecryptStart(buffer);
		data.write((char *)buffer, blockSize);

		memcpy(p_cur, buffer + blockSize, blockSize);
		DecryptNext(buffer, 1, p_prev);
		memcpy(buffer, buffer + blockSize, blockSize);

		p_temp = p_prev;
		p_prev = p_cur;
		p_cur = p_temp;

        //decryptedSize += blockSize;
        //if (callback) callback(decryptedSize);
	}
	else
	{
		// значит считали только один блок

		DecryptStart(buffer);
		sizeWithoutPadding = RemovePadding(buffer, blockSize);
		data.write((char *)buffer, sizeWithoutPadding);

        //decryptedSize += blockSize;
        //if (callback) callback(decryptedSize);

		delete[] block_buffer;
		delete[] buffer;
		return;
	}

	while (enc_data.read((char *)buffer + blockSize, bufferSize - blockSize))
	{
		memcpy(p_cur, buffer + bufferSize - blockSize, blockSize);

		DecryptNext(buffer, blocksCountForBuffer - 1, p_prev);

		data.write((char *)buffer, bufferSize - blockSize);

		memcpy(buffer, buffer + bufferSize - blockSize, blockSize);

		p_temp = p_prev;
		p_prev = p_cur;
		p_cur = p_temp;

        //decryptedSize += bufferSize - blockSize;
        //if (callback) callback(decryptedSize);
	}

	DecryptNext(buffer, enc_data.gcount() / blockSize, p_prev);
	sizeWithoutPadding = RemovePadding(buffer, blockSize + enc_data.gcount());
	data.write((char *)buffer, sizeWithoutPadding);

    //decryptedSize += sizeWithoutPadding;
    //if (callback) callback(decryptedSize);

	delete[] block_buffer;
	delete[] buffer;
}


void SymmetricBlockCipher::Encrypt(std::vector<char> & data) const
{
	size_t occupedSize = data.size();
	size_t fullSize = occupedSize + (BlockSizeInBytes() - occupedSize % BlockSizeInBytes());
	uint8_t * buf = new uint8_t[BlockSizeInBytes()];

	data.resize(fullSize);
	SetPadding((uint8_t *)data.data(), occupedSize);

	memcpy(buf, data.data(), BlockSizeInBytes());

	EncryptStart((uint8_t *)data.data());
	EncryptNext((uint8_t *)data.data(), (fullSize / BlockSizeInBytes()) - 1, buf);

	delete[] buf;
}

void SymmetricBlockCipher::Decrypt(std::vector<char> & data) const
{
	uint8_t * buf = new uint8_t[BlockSizeInBytes()];

	memcpy(buf, data.data(), BlockSizeInBytes());
	DecryptStart((uint8_t *)data.data());
	if (data.size() > BlockSizeInBytes())
		DecryptNext((uint8_t *)data.data(), (data.size() / BlockSizeInBytes()) - 1, buf);

	data.resize( RemovePadding((uint8_t *)data.data(), data.size()) );
	delete[] buf;
}








///////////////////////////////////////////////////////////////////////

void SymmetricBlockCipher::EncryptStart(uint8_t * data) const
{
	switch (cipherMode)
	{
	case ECB:
		EncryptBlock(data);

		break;

	case CBC:
		for (int i = 0; i < BlockSizeInBytes(); i++)
			data[i] ^= ivec[i];
		EncryptBlock(data);

		break;
	}
}
void SymmetricBlockCipher::EncryptNext(uint8_t * data, uint32_t blocksCount, uint8_t * dataPrevBlock) const
{
	uint32_t bSize = BlockSizeInBytes();

	switch (cipherMode)
	{
	case ECB:
		for (uint32_t curBlock = bSize, endBlock = curBlock + blocksCount * bSize; curBlock != endBlock; curBlock += bSize)
			EncryptBlock(data + curBlock);

		break;
	case CBC:
		for (uint32_t curBlock = bSize, endBlock = curBlock + blocksCount * bSize; curBlock != endBlock; curBlock += bSize)
		{
			for (uint32_t j = 0; j < bSize; j++)
				data[curBlock + j] ^= data[curBlock - bSize + j];
			EncryptBlock(data + curBlock);
		}

		break;
	}
}


void SymmetricBlockCipher::DecryptStart(uint8_t * enc_data) const
{
	switch (cipherMode)
	{
	case ECB:
		DecryptBlock(enc_data);

		break;

	case CBC:
		DecryptBlock(enc_data);

		for (int i = 0; i < BlockSizeInBytes(); i++)
			enc_data[i] ^= ivec[i];

		break;
	}
}
void SymmetricBlockCipher::DecryptNext(uint8_t * enc_data, uint32_t blocksCount, uint8_t * enc_dataPrevBlock) const
{
	uint32_t blockSize = BlockSizeInBytes();

	switch (cipherMode)
	{
	case ECB:
		for (uint32_t curBlock = blockSize, endBlock = (curBlock + blocksCount * blockSize); curBlock != endBlock; curBlock += blockSize)
			DecryptBlock(enc_data + curBlock);

		break;
	case CBC:
		uint8_t *buffer = new uint8_t[blockSize * 2];
		uint8_t *p_prev = buffer, *p_cur = buffer + blockSize, *temp;

		// p_prev - указатель на предыдущий зашифрованный блок
		// p_cur - указатель на текущий зашифрованный блок

		memcpy(p_prev, enc_dataPrevBlock, blockSize);

		for (uint32_t curBlock = blockSize, endBlock = (curBlock + blocksCount * blockSize); curBlock != endBlock; curBlock += blockSize)
		{
			memcpy(p_cur, &enc_data[curBlock], blockSize);

			DecryptBlock(enc_data + curBlock);
			for (uint32_t j = 0; j < blockSize; j++)
				enc_data[curBlock + j] ^= p_prev[j];

			// текущий зашифрованный блок становится предыдущим
			temp = p_prev;
			p_prev = p_cur;
			p_cur = temp;
		}

		delete[] buffer;

		break;
	}
}


size_t SymmetricBlockCipher::SetPadding(uint8_t * data, size_t occupedSize) const
{
	uint8_t paddingSize = BlockSizeInBytes() - (occupedSize % BlockSizeInBytes());

	switch (paddingMode)
	{
	case X923:
		for (uint32_t i = occupedSize, end = i + paddingSize - 1; i != end; i++)
			data[i] = 0;
		data[occupedSize + paddingSize - 1] = paddingSize;

		break;

	case PKCS7:
		for (uint32_t i = occupedSize, end = occupedSize + paddingSize; i != end; i++)
			data[i] = paddingSize;

		break;

	case ISO10126:
		for (uint32_t i = occupedSize, end = occupedSize + paddingSize - 1; i != end; i++)
			data[i] = rand() % (0xff + 1);
		data[occupedSize + paddingSize - 1] = paddingSize;

		break;
	}

	return occupedSize + paddingSize;
}
size_t SymmetricBlockCipher::RemovePadding(uint8_t * data, size_t occupedSize) const
{
	uint8_t paddingSize = data[occupedSize - 1];
	return occupedSize - paddingSize;
}


void SymmetricBlockCipher::SafeSetZero(uint8_t * mem, size_t memsize)
{
	for (uint8_t * end = mem + memsize; mem != end; mem++)
		*mem = 0;
}
