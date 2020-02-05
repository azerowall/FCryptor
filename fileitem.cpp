#include "fileitem.h"

FileItem::FileItem(QString text, QListWidget *parent) : QListWidgetItem(text, parent)
{
}
FileItem::FileItem(QListWidget *parent) : QListWidgetItem(parent)
{
}

QVariant FileItem::data(int role) const
{
    if (role == FileItem::FilePathRole)
        return filePath;
    else
        return QListWidgetItem::data(role);
}

void FileItem::setData(int role, const QVariant & value)
{
    if (role == FileItem::FilePathRole)
        filePath = value.toString();
    else
        QListWidgetItem::setData(role, value);
}
