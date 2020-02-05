#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "filecryptorwidget.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

    FileCryptorWidget * fcwgt;
public:
    explicit MainWindow(QWidget *parent = nullptr);

signals:

private slots:
    void about();
};

#endif // MAINWINDOW_H
