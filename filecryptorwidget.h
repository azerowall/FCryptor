#ifndef FILECRYPTORWIDGET_H
#define FILECRYPTORWIDGET_H

#include <QWidget>
#include <QLineEdit>
#include <QListWidget>
#include <QComboBox>
#include <QProgressBar>
#include <QStackedWidget>
#include <QCheckBox>
#include <QPushButton>

#include "fileitem.h"
#include "filecryptor.h"

class FileCryptorWidget : public QWidget
{
    Q_OBJECT
private:
    enum {
        CryptionSettingsMode, CryptionMode, CryptionReportMode
    };

    QListWidget * fileListWgt;
    QLineEdit * lineKey;
    QComboBox * cmbCipher;
    QComboBox * cmbCipherMode;
    QProgressBar * progressBar;
    QStackedWidget * stackedWgt;
    QTabWidget * tabs;

    QCheckBox * cbSaveToDir;
    QLineEdit * lineResultDir ;

    QPushButton * btnCryptCancelOk;
    int workmode;

    const QColor colorSuccess = QColor(0xee, 0xff, 0xee);
    const QColor colorWarning = QColor(0xff, 0xee, 0xee);
public:
    enum {
        StatusDefault, StatusOk, StatusError
    };

    explicit FileCryptorWidget(QWidget *parent = nullptr);



private:

    /* work with ui */

    QWidget * uiSettingsPanel();
    QWidget * uiListPanel();
    QWidget * uiStartupPanel();
    void setMode(int mode);
    int getMode();
    bool checkFormAndSetWarnings();

    /* work with list */

    bool contains(QString path);
    void addToList(QString path);
    void addToList(QStringList paths);
    void addToList(QList<QUrl> paths);
    QStringList getInputFileNames();

protected:
    void dragEnterEvent(QDragEnterEvent * event);
    void dragLeaveEvent(QDragLeaveEvent * event);
    void dragMoveEvent(QDragLeaveEvent * event);
    void dropEvent(QDropEvent * event);

//signals:

private slots:
    void removeItem(QListWidgetItem * item);
    void setStatus(int index, int status, QString);
    void addFilesFromFileDialog();
    void setResultDirFromFileDialog();
    void Encrypt();
    void Decrypt();

    void onBtnCryptCancelClicked();

    void CryptionFinished();
};

#endif // FILECRYPTORWIDGET_H
