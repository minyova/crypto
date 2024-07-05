#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QProcess>
#include <QLabel>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_selectFileButton_clicked();
    void on_generateKeysButton_clicked();
    void on_processButton_clicked();

private:
    Ui::MainWindow *ui;
    QString selectedFilePath;
    QProcess process;

    void updateImage(QLabel *label, const QString &imagePath);
    void runOpenSSLCommand(const QString &command);

    void handleErrors();
    EVP_PKEY* loadKey(const char* filename, bool isPublic);
    bool signData(EVP_PKEY* publicKey, const unsigned char* data, size_t dataSize, unsigned char*& signature, size_t& signatureSize);
    bool verifySignature(EVP_PKEY* privateKey, const unsigned char* data, size_t dataSize, const unsigned char* signature, size_t signatureSize);
    bool encryptAES(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, const unsigned char* iv, unsigned char*& ciphertext, int& ciphertext_len);
    bool decryptAES(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, const unsigned char* iv, unsigned char*& plaintext, int& plaintext_len);
    void processImage();
    QByteArray encryptPixelData(const QByteArray& pixelData, const unsigned char* key, const unsigned char* iv);
    QByteArray decryptPixelData(const QByteArray& encryptedData, const unsigned char* key, const unsigned char* iv);
    void encryptAndSend();
    void receiveAndDecrypt();

    const int AES_KEYLENGTH = 256;
    const int AES_BLOCK_SIZE = 16;
};

#endif // MAINWINDOW_H
