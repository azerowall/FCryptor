#include <QApplication>

#include "mainwindow.h"

#include <QPushButton>
#include <QWidget>
#include <QVBoxLayout>
#include <QLabel>
#include <QStyleFactory>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    a.setStyle(QStyleFactory::create("fusion"));

    MainWindow wnd;
    wnd.show();

    return a.exec();
}

