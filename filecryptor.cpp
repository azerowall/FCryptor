#include "filecryptor.h"

#include <fstream>

#include <QFile>
#include <QFileInfo>
#include <QUrl>
#include <QDataStream>
#include <QDateTime>
#include <QCryptographicHash>
#include <QException>

#include "ciphers/Aes.h"
#include "crc32.h"



QStringList FileCryptor::legalCiphers = {"AES-128", "AES-192", "AES-256"};
QStringList FileCryptor::legalCipherModes = {"ECB", "CBC"};

FileCryptor::FileCryptor(QString cipherName, QObject *parent) : QObject(parent)
{
    int keysize;
    if (cipherName == legalCiphers[0])
        keysize = 128;
    else if (cipherName == legalCiphers[1])
        keysize = 192;
    else if (cipherName == legalCiphers[2])
        keysize = 256;
    else
        keysize = 128;

    cipher = new Aes(keysize);

    cipher->SetBufferSizeForStreamCryption(1024 * 500);    // 500 кб
}

FileCryptor::~FileCryptor()
{
    delete cipher;
}

void FileCryptor::SetCipherMode(QString cipherMode)
{
    if (cipherMode == legalCipherModes[0])
        cipher->SetCipherMode(SymmetricBlockCipher::ECB);
    else if (cipherMode == legalCipherModes[1])
        cipher->SetCipherMode(SymmetricBlockCipher::CBC);
    else
        cipher->SetCipherMode(SymmetricBlockCipher::ECB);
}

void FileCryptor::SetKey(QByteArray newKey)
{
    newKey = QCryptographicHash::hash(newKey, QCryptographicHash::Sha256);
    cipher->SetKey((uint8_t *)newKey.data());
}

void FileCryptor::GenerateIV()
{
    qsrand(QDateTime::currentMSecsSinceEpoch() / 1000);
    QByteArray arr(cipher->BlockSizeInBytes(), 0);
    for (QByteArray::iterator it = arr.begin(); it != arr.end(); ++it)
        *it = qrand() % 256;
    cipher->SetIV((uint8_t *)arr.data());
}

void FileCryptor::Encrypt(QString inputFileName, QString dir)
{
    QFileInfo inpInfo(inputFileName);
    if (dir.length() == 0)
        dir = inpInfo.absolutePath();
    QString outputFileName = dir + "/" + inpInfo.baseName();
    if (QFileInfo::exists(outputFileName + ".enc"))
    {
        QRegExp reg("(.*)\\([0-9]+\\)$");
        if (reg.exactMatch(outputFileName))
            outputFileName = reg.cap(1);

        for (int i = 1; i < 0xffff; i++)
            if (!QFileInfo::exists(outputFileName + "(" + QString::number(i) + ")" + ".enc"))
            {
                outputFileName = outputFileName + "(" + QString::number(i) + ")" + ".enc";
                break;
            }
    }
    else outputFileName += ".enc";


    std::ifstream fin(QFile::encodeName(inputFileName).toStdString(), std::ios::binary);
    if (!fin.is_open())
    {
        emit CryptionFinished();
        throw FCException("Не удается открыть входной файл");
    }
    std::ofstream fout(QFile::encodeName(outputFileName).toStdString(), std::ios::binary);
    if (!fout.is_open())
    {
        fin.close();
        emit CryptionFinished();
        throw FCException("Не удается создать результирующий файл");
    }

    // генерация вектора инициализации
    GenerateIV();
    QByteArray iv(cipher->BlockSizeInBytes(), 0);
    cipher->GetIV((uint8_t *)iv.data());

    fin.seekg(0);
    uint32_t crc = Crc32::GetHash(iv.data(), cipher->BlockSizeInBytes());
    // записываем контрольную сумму вектора инициализации
    fout.write((char *)&crc, 4);
    // записываем вектор инициализации
    fout.write(iv.data(), cipher->BlockSizeInBytes());
    // записываем прежнее расширение
    {
        std::string ext = QFile::encodeName(inpInfo.completeSuffix()).toStdString();
        uint32_t extLen = ext.length();
        fout.write((char *)&extLen, 4);
        for (auto it = ext.begin(); it != ext.end(); ++it)
        {
            char ch = *it;
            fout.write(&ch, 1);
        }
    }
    cipher->Encrypt(fin, fout);

    fin.close();
    fout.close();

    emit CryptionFinished();
}

void FileCryptor::Decrypt(QString inputFileName, QString dir)
{
    std::ifstream fin(QFile::encodeName(inputFileName).toStdString(), std::ios::binary);
    if (!fin.is_open())
    {
        emit CryptionFinished();
        throw FCException("Не удается открыть входной файл");
    }
    if (!IsEncrypted(fin))
    {
        fin.close();
        emit CryptionFinished();
        throw FCException("Входной файл не был зашифрован");
    }

    fin.seekg(4);

    QByteArray iv(cipher->BlockSizeInBytes(), 0);
    // считываем вектор инициализации
    fin.read(iv.data(), cipher->BlockSizeInBytes());
    // считываем старое расширение
    std::string sExt;
    uint32_t extLen;
    char ch;
    fin.read((char *)&extLen, 4);
    for (int i = 0; i < extLen; i++)
    {
        fin.read(&ch, 1);
        sExt += ch;
    }

    cipher->SetIV((uint8_t *)iv.data());

    QString ext = "." + QFile::decodeName(sExt.c_str());
    QFileInfo inpInfo(inputFileName);
    if (dir.length() == 0)
        dir = inpInfo.absolutePath();
    QString outputFileName = dir + "/" + inpInfo.baseName();
    if (QFileInfo::exists(outputFileName + ext))
    {
        QRegExp reg("(.*)\\([0-9]+\\)$");
        if (reg.exactMatch(outputFileName))
            outputFileName = reg.cap(1);

        for (int i = 1; i < 0xffff; i++)
            if (!QFileInfo::exists(outputFileName + "(" + QString::number(i) + ")" + ext))
            {
                outputFileName = outputFileName + "(" + QString::number(i) + ")" + ext;
                break;
            }
    }
    else outputFileName += ext;


    std::ofstream fout(QFile::encodeName(outputFileName).toStdString(), std::ios::binary);
    if (!fout.is_open())
    {
        fin.close();
        emit CryptionFinished();
        throw FCException("Не удается создать результирующий файл");
    }


    cipher->Decrypt(fin, fout);

    fin.close();
    fout.close();

    emit CryptionFinished();
}

bool FileCryptor::IsEncrypted(std::ifstream &fin)
{
    std::ifstream::pos_type prevPos = fin.tellg();
    fin.seekg(0);

    uint32_t crc;
    fin.read((char *)&crc, 4);

    QByteArray iv(cipher->BlockSizeInBytes(), 0);
    fin.read(iv.data(), cipher->BlockSizeInBytes());

    fin.seekg(prevPos);

    return crc == Crc32::GetHash(iv.data(), cipher->BlockSizeInBytes());
}
