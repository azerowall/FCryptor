#ifndef FCWORKER_H
#define FCWORKER_H

#include <QObject>

class FCWorker : public QObject
{
    Q_OBJECT
private:
    QStringList filesIn;
    QString resultDir;

    QString cipher;
    QString mode;
    QByteArray key;

public:
    enum {StatusOk, StatusError};

    explicit FCWorker(QObject * parent = nullptr);

    void setCipher(QString);
    void setCipherMode(QString);
    void setKey(QByteArray);
    void setFiles(QStringList input, QString outDir);

signals:

    // в процентах
    void progress(int percentages);
    void status(int id, int stat, QString message);
    void finished();

public slots:
    void processEncrypt();
    void processDecrypt();

};

#endif // FCWORKER_H
