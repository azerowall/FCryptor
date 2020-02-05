#include "fcworker.h"
#include "filecryptor.h"
#include "filecryptorwidget.h"

#include <QFileInfo>
#include <QThread>
#include <QException>

FCWorker::FCWorker(QObject * parent) : QObject(parent)
{
}

void FCWorker::setCipher(QString c)
{
    cipher = c;
}

void FCWorker::setCipherMode(QString m)
{
    mode = m;
}

void FCWorker::setKey(QByteArray k)
{
    key = k;
}

void FCWorker::setFiles(QStringList input, QString outDir)
{
    filesIn = input;
    resultDir = outDir;
}

void FCWorker::processEncrypt()
{
    FileCryptor * fc = new FileCryptor(cipher);
    fc->SetCipherMode(mode);
    fc->SetKey(key);

    for (int i = 0; i < filesIn.length(); i++)
    {
        try
        {
            fc->Encrypt(filesIn[i], resultDir);

            emit status(i, FileCryptorWidget::StatusOk, "");
        }
        catch (const QException &e)
        {
            emit status(i, FileCryptorWidget::StatusError, e.what());
        }

        emit progress(((i + 1) * 100) / filesIn.length());
    }

    delete fc;

    emit finished();
}

void FCWorker::processDecrypt()
{
    FileCryptor * fc = new FileCryptor(cipher);
    fc->SetCipherMode(mode);
    fc->SetKey(key);

    for (int i = 0; i < filesIn.length(); i++)
    {
        try
        {
            fc->Decrypt(filesIn[i], resultDir);

            emit status(i, FileCryptorWidget::StatusOk, "");
        }
        catch (const QException &e)
        {
            emit status(i, FileCryptorWidget::StatusError, QString::fromStdString(e.what()));
        }

        emit progress(((i + 1) * 100) / filesIn.length());
    }

    delete fc;

    emit finished();
}
