#ifndef FILECRYPTOR_H
#define FILECRYPTOR_H

#include <QObject>
#include <QException>

#include "ciphers/SymmetricBlockCipher.h"

class FileCryptor : public QObject
{
    Q_OBJECT
private:
    static QStringList legalCiphers;
    static QStringList legalCipherModes;

    SymmetricBlockCipher * cipher;

public:
    explicit FileCryptor(QString cipherName, QObject *parent = nullptr);
    ~FileCryptor();

    /*
        Возвращает список имен поддерживаемых алгоритмов
    */
    static QStringList LegalCipherNames()
    {
        return legalCiphers;
    }

    /*
        Возвращает список поддерживаемых режимов шифрования
    */
    static QStringList LegalCipherModes()
    {
        return legalCipherModes;
    }

    /*
        Устанавливает режим шифрования
    */
    void SetCipherMode(QString cipherMode);

    /*
        Устанавливает ключ шифрования
        newKey может быть произвольного размера
    */
    void SetKey(QByteArray newKey);

    /*
        Шифрование файла
    */
    void Encrypt(QString inputFileName, QString dir);

    /*
        Дешифрование файла
    */
    void Decrypt(QString inputFileName, QString dir);

private:

    /*
        Генерирует псевдослучайный вектор инициализации
    */
    void GenerateIV();

    /*
        Проверяет зашифрован ли файл
    */
    bool IsEncrypted(std::ifstream &file);

signals:
    /*
        Сигнал, вызываемый, когда шифрование файла окончено
    */
    void CryptionFinished();
};


// исключения для FileCryptor
class FCException : public QException
{
private:
    std::string msg;
public:
    void raise() const { throw *this; }
    FCException *clone() const { return new FCException(*this); }
    FCException(const char *m) {
        msg = m;
    }
    const char * what() const noexcept
    {
        return msg.c_str();
    }
};

#endif // FILECRYPTOR_H
