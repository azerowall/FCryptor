#ifndef FILELISTWIDGET_H
#define FILELISTWIDGET_H

#include <QListWidgetItem>

class FileItem : public QListWidgetItem
{
public:
    enum {
        FilePathRole = Qt::UserRole
    };
private:
    QString filePath;
public:
    explicit FileItem(QString text, QListWidget *parent = nullptr);
    explicit FileItem(QListWidget *parent = nullptr);

    QVariant data(int role) const;
    void setData(int role, const QVariant & value);
};

#endif // FILELISTWIDGET_H
