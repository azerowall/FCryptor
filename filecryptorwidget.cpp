#include "filecryptorwidget.h"

#include <QtGui>
#include <QtCore>

#include <QVBoxLayout>
#include <QFormLayout>
#include <QPushButton>
#include <QComboBox>
#include <QStackedWidget>

#include <QFileDialog>

#include <QFileInfo>
#include <QProgressBar>
#include <QHeaderView>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>
#include <QMessageBox>

#include "fcworker.h"

FileCryptorWidget::FileCryptorWidget(QWidget *parent) : QWidget(parent)
{
    QVBoxLayout * mainLayout = new QVBoxLayout;
    mainLayout->addWidget(uiSettingsPanel());
    mainLayout->addWidget(uiListPanel());
    mainLayout->addWidget(uiStartupPanel());

    setLayout(mainLayout);
    setAcceptDrops(true);
    workmode = CryptionSettingsMode;
}

QWidget * FileCryptorWidget::uiSettingsPanel()
{
    lineKey = new QLineEdit;
    cmbCipher = new QComboBox;
    cmbCipherMode = new QComboBox;

    cmbCipher->addItems(FileCryptor::LegalCipherNames());
    cmbCipherMode->addItems(FileCryptor::LegalCipherModes());

    QPushButton * btnSelectDir = new QPushButton("...");
    cbSaveToDir = new QCheckBox("Сохранить в директорию");
    lineResultDir = new QLineEdit;

    lineResultDir->setDisabled(true);
    lineResultDir->setReadOnly(true);
    btnSelectDir->setDisabled(true);
    btnSelectDir->setMaximumWidth(50);

    connect(cbSaveToDir, SIGNAL(toggled(bool)), lineResultDir, SLOT(setEnabled(bool)));
    connect(cbSaveToDir, SIGNAL(toggled(bool)), btnSelectDir, SLOT(setEnabled(bool)));
    connect(btnSelectDir, SIGNAL(clicked()), this, SLOT(setResultDirFromFileDialog()));

    QHBoxLayout * hboxSaveToDir = new QHBoxLayout;
    hboxSaveToDir->addWidget(lineResultDir, 1);
    hboxSaveToDir->addWidget(btnSelectDir);

    // панель с параметрами сохранения результата
    QFormLayout * resultSettingsForm = new QFormLayout;
    resultSettingsForm->addRow(cbSaveToDir);
    resultSettingsForm->addRow(hboxSaveToDir);
    QWidget * wgtTabResult = new QWidget;
    wgtTabResult->setLayout(resultSettingsForm);

    // панель с параметрами шифрования
    QFormLayout * cipherSettingsForm = new QFormLayout;
    cipherSettingsForm->addRow("Ключ", lineKey);
    cipherSettingsForm->addRow("Шифр", cmbCipher);
    cipherSettingsForm->addRow("Режим", cmbCipherMode);
    QWidget * wgtTabCipher = new QWidget;
    wgtTabCipher->setLayout(cipherSettingsForm);

    tabs = new QTabWidget;
    tabs->addTab(wgtTabCipher, "Шифр");
    tabs->addTab(wgtTabResult, "Результат");
    tabs->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);

    return tabs;
}
QWidget * FileCryptorWidget::uiListPanel()
{
    fileListWgt = new QListWidget;
    fileListWgt->setSelectionMode(QAbstractItemView::SingleSelection);

    connect(fileListWgt, SIGNAL(itemDoubleClicked(QListWidgetItem*)),
            this, SLOT(removeItem(QListWidgetItem*)));

    return fileListWgt;
}
QWidget * FileCryptorWidget::uiStartupPanel()
{
    progressBar = new QProgressBar;
    progressBar->setMinimum(0);
    progressBar->setMaximum(100);

    QPushButton * btnSelectFile = new QPushButton;
    QPushButton * btnRemoveAllItems = new QPushButton;
    btnCryptCancelOk = new QPushButton("Ок");
    QPushButton * btnEncrypt = new QPushButton(" Зашифровать");
    QPushButton * btnDecrypt = new QPushButton(" Дешифровать");

    btnSelectFile->setIcon(QIcon(":/icons/plus-symbol.png"));
    btnRemoveAllItems->setIcon(QIcon(":/icons/letter-x.png"));
    btnEncrypt->setIcon(QIcon(":/icons/padlock.png"));
    btnDecrypt->setIcon(QIcon(":/icons/open-lock.png"));

    connect(btnSelectFile, SIGNAL(clicked()), this, SLOT(addFilesFromFileDialog()));
    connect(btnRemoveAllItems, SIGNAL(clicked()), fileListWgt, SLOT(clear()));
    connect(btnEncrypt, SIGNAL(clicked()), this, SLOT(Encrypt()));
    connect(btnDecrypt, SIGNAL(clicked()), this, SLOT(Decrypt()));
    connect(btnCryptCancelOk, SIGNAL(clicked()), this, SLOT(onBtnCryptCancelClicked()));

    // нижняя панель с кнопками
    QHBoxLayout * hboxBtns = new QHBoxLayout;
    hboxBtns->addWidget(btnSelectFile);
    hboxBtns->addWidget(btnRemoveAllItems);
    hboxBtns->addWidget(btnDecrypt, 1, Qt::AlignRight);
    hboxBtns->addWidget(btnEncrypt);
    hboxBtns->setMargin(0);
    QWidget * wgtNonCrypting = new QWidget;
    wgtNonCrypting->setLayout(hboxBtns);

    QHBoxLayout * hboxProgress = new QHBoxLayout;
    hboxProgress->addWidget(progressBar);
    hboxProgress->addWidget(btnCryptCancelOk);
    hboxProgress->setMargin(0);
    QWidget * wgtCrypting = new QWidget;
    wgtCrypting->setLayout(hboxProgress);

    stackedWgt = new QStackedWidget;
    stackedWgt->setLayoutDirection(Qt::LeftToRight);
    stackedWgt->addWidget(wgtNonCrypting);
    stackedWgt->addWidget(wgtCrypting);
    stackedWgt->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);

    return stackedWgt;
}
void FileCryptorWidget::setMode(int mode)
{
    switch (mode) {
    case CryptionSettingsMode:
        stackedWgt->setCurrentIndex(0);
        for (int i = 0; i < fileListWgt->count(); i++)
            setStatus(i, StatusDefault, "");
        break;
    case CryptionMode:
        stackedWgt->setCurrentIndex(1);
        btnCryptCancelOk->setDisabled(true);
        break;
    case CryptionReportMode:
        btnCryptCancelOk->setEnabled(true);
        break;
    }
    workmode = mode;
}
int FileCryptorWidget::getMode()
{
    return workmode;
}

void FileCryptorWidget::addFilesFromFileDialog()
{
    addToList(QFileDialog::getOpenFileUrls(this));
}
void FileCryptorWidget::setResultDirFromFileDialog()
{
    QString dir = QFileDialog::getExistingDirectory(this);
    lineResultDir->setText(dir);
}

bool FileCryptorWidget::contains(QString path)
{
    for (int i = 0; i < fileListWgt->count(); i++)
        if (fileListWgt->item(i)->data(FileItem::FilePathRole).toString() == path)
            return true;
    return false;
}
void FileCryptorWidget::addToList(QString path)
{
    QFileInfo fInfo(path);

    if (!fInfo.isFile())
        return;

    if (contains(path))
        return;

    if (getMode() != CryptionSettingsMode)
        return;

    FileItem * item = new FileItem(fInfo.fileName());
    item->setIcon(style()->standardIcon(QStyle::SP_FileIcon));
    item->setData(FileItem::FilePathRole, fInfo.filePath());
    fileListWgt->addItem(item);
}
void FileCryptorWidget::addToList(QStringList paths)
{
    foreach (QString str, paths) {
        addToList(str);
    }
}
void FileCryptorWidget::addToList(QList<QUrl> paths)
{
    foreach (QUrl url, paths) {
        addToList(url.toLocalFile());
    }
}
void FileCryptorWidget::removeItem(QListWidgetItem * item)
{
    if (getMode() == CryptionSettingsMode)
       delete item;
}
QStringList FileCryptorWidget::getInputFileNames()
{
    QStringList result;

    for (int i = 0; i < fileListWgt->count(); i++)
        result << fileListWgt->item(i)->data(FileItem::FilePathRole).toString();

    return result;
}

void FileCryptorWidget::dragEnterEvent(QDragEnterEvent * event)
{
    event->accept();
}
void FileCryptorWidget::dragLeaveEvent(QDragLeaveEvent * event)
{
    event->accept();
}
void FileCryptorWidget::dragMoveEvent(QDragLeaveEvent * event)
{
    event->accept();
}
void FileCryptorWidget::dropEvent(QDropEvent * event)
{
    if (event->mimeData()->hasUrls())
    {
        addToList(event->mimeData()->urls());
    }
    event->acceptProposedAction();
}


bool FileCryptorWidget::checkFormAndSetWarnings()
{
    if (fileListWgt->count() == 0) return false;
    if (lineKey->text().isEmpty())
    {
        QMessageBox::warning(this, "Предупреждение", "Поле 'Ключ' пусто");
        return false;
    }
    if (cbSaveToDir->isChecked() && lineResultDir->text().isEmpty())
    {
        QMessageBox::warning(this, "Предупреждение", "Поле 'Директория для результата' пусто");
        return false;
    }

    return true;
}
void FileCryptorWidget::setStatus(int index, int status, QString msg)
{
    QColor color;
    if (status == StatusOk)
        color = colorSuccess;
    else if (status == StatusError)
        color = colorWarning;
    else
        color = QColor(0xff, 0xff, 0xff);

    QListWidgetItem * item = fileListWgt->takeItem(index);
    item->setBackgroundColor(color);
    item->setToolTip(msg);
    item->setStatusTip(msg);
    item->setWhatsThis(msg);
    fileListWgt->insertItem(index, item);
}

void FileCryptorWidget::Encrypt()
{
    if (!checkFormAndSetWarnings())
        return;

    progressBar->setValue(0);
    setMode(CryptionMode);

    QThread * thread = new QThread;
    FCWorker * worker = new FCWorker;

    worker->setCipher(cmbCipher->currentText());
    worker->setCipherMode(cmbCipherMode->currentText());
    worker->setKey(lineKey->text().toUtf8());
    worker->setFiles(getInputFileNames(), cbSaveToDir->isChecked() ? lineResultDir->text() : "");
    worker->moveToThread(thread);

    connect(thread, SIGNAL(started()), worker, SLOT(processEncrypt()));
    connect(worker, SIGNAL(progress(int)), progressBar, SLOT(setValue(int)));
    connect(worker, SIGNAL(status(int,int,QString)), this, SLOT(setStatus(int,int,QString)));
    connect(worker, SIGNAL(finished()), this, SLOT(CryptionFinished()));

    //connect(btnCryptCancelOk, SIGNAL(clicked()), worker, SLOT(cancel()));

    connect(worker, SIGNAL(finished()), thread, SLOT(quit()));
    connect(worker, SIGNAL(finished()), worker, SLOT(deleteLater()));
    connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));

    thread->start();
}

void FileCryptorWidget::Decrypt()
{
    if (!checkFormAndSetWarnings())
        return;

    progressBar->setValue(0);
    setMode(CryptionMode);

    QThread * thread = new QThread;
    FCWorker * worker = new FCWorker;

    worker->setCipher(cmbCipher->currentText());
    worker->setCipherMode(cmbCipherMode->currentText());
    worker->setKey(lineKey->text().toUtf8());
    worker->setFiles(getInputFileNames(), cbSaveToDir->isChecked() ? lineResultDir->text() : "");
    worker->moveToThread(thread);

    connect(thread, SIGNAL(started()), worker, SLOT(processDecrypt()));
    connect(worker, SIGNAL(progress(int)), progressBar, SLOT(setValue(int)));
    connect(worker, SIGNAL(status(int,int,QString)), this, SLOT(setStatus(int,int,QString)));
    connect(worker, SIGNAL(finished()), this, SLOT(CryptionFinished()));

    //connect(btnCryptCancelOk, SIGNAL(clicked()), worker, SLOT(cancel()));

    connect(worker, SIGNAL(finished()), thread, SLOT(quit()));
    connect(worker, SIGNAL(finished()), worker, SLOT(deleteLater()));
    connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater()));

    thread->start();
}

void FileCryptorWidget::CryptionFinished()
{
    progressBar->setValue(100);
    setMode(CryptionReportMode);
}
void FileCryptorWidget::onBtnCryptCancelClicked()
{
    if (getMode() == CryptionReportMode)
        setMode(CryptionSettingsMode);
}
