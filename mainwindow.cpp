#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>

#include "mainwindow.h"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{

    QMenu * about = menuBar()->addMenu("&Справка");
    about->addAction("&О программе", this, SLOT(about()));


    fcwgt = new FileCryptorWidget;
    setCentralWidget(fcwgt);
}

void MainWindow::about()
{
    QMessageBox::about(this, "О программе",
        "Программа: 'FCryptor' - программа для шифрования файлов с использованием симметричного алгоритма AES\n"
        "Версия: 1.0\n"
        "Год издания: 2017\n"
        "Автор: azerowall");
}
