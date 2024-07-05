#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QPixmap>
#include <fstream>
#include <iostream>
#include <QImage>
#include <QBuffer>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <QDir>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_selectFileButton_clicked()
{
    // Выбор файла изображения
    selectedFilePath = QFileDialog::getOpenFileName(this, "Выберите изображение", "", "Images (*.png *.jpg *.bmp)");
    if (!selectedFilePath.isEmpty()) {
        // Обновление отображения исходного изображения
        updateImage(ui->originalImage, selectedFilePath);
    }
}

void MainWindow::on_generateKeysButton_clicked()
{
    // Путь к текущей директории
    QString keyPath = QDir::currentPath();

    // Выполнение команд OpenSSL в терминале
    runOpenSSLCommand("cd " + keyPath);
    runOpenSSLCommand("openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048");
    runOpenSSLCommand("openssl rsa -pubout -in private.pem -out public.pem");
    qDebug() << keyPath;
    // Информационное сообщение об успешной генерации ключей
    QMessageBox::information(this, "Генерация ключей", "Ключи успешно сгенерированы");
}

void MainWindow::on_processButton_clicked()
{
    // Проверка выбора файла изображения
    if (selectedFilePath.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Выберите файл изображения");
        return;
    }

    // Запуск обработки изображения
    processImage();
}

void MainWindow::updateImage(QLabel *label, const QString &imagePath)
{
    // Загрузка и отображение изображения
    QPixmap pixmap(imagePath);
    if (!pixmap.isNull()) {
        label->setPixmap(pixmap.scaled(label->size(), Qt::KeepAspectRatio, Qt::SmoothTransformation));
    } else {
        label->setText("Невозможно отобразить изображение");
    }
}

void MainWindow::runOpenSSLCommand(const QString &command)
{
    // Выполнение команды OpenSSL в терминале
    QProcess process;
    process.start("sh", QStringList() << "-c" << command.toStdString().c_str());
    process.waitForFinished();

    // Проверка результата выполнения команды
    if (process.exitCode() != 0) {
        qDebug() << "Ошибка при выполнении команды openssl: " << process.errorString();
    }
}

void MainWindow::handleErrors()
{
    // Вывод сообщений об ошибках OpenSSL
    ERR_print_errors_fp(stderr);
}

EVP_PKEY* MainWindow::loadKey(const char* filename, bool isPublic)
{
    // Загрузка ключа (публичного или приватного) из файла
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        std::cerr << "Не удалось открыть файл " << filename << ": " << strerror(errno) << std::endl;
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    if (isPublic) {
        pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    } else {
        pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    }

    fclose(fp);
    if (!pkey) {
        std::cerr << "Не удалось загрузить ключ из файла " << filename << std::endl;
    }
    return pkey;
}

bool MainWindow::signData(EVP_PKEY* publicKey, const unsigned char* data, size_t dataSize, unsigned char*& signature, size_t& signatureSize)
{
    // Подпись данных с помощью публичного ключа
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        handleErrors();

    if (1 != EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, publicKey))
        handleErrors();

    if (1 != EVP_DigestSignUpdate(mdctx, data, dataSize))
        handleErrors();

    if (1 != EVP_DigestSignFinal(mdctx, nullptr, &signatureSize))
        handleErrors();

    signature = (unsigned char*)OPENSSL_malloc(signatureSize);
    if (!signature)
        handleErrors();

    if (1 != EVP_DigestSignFinal(mdctx, signature, &signatureSize))
        handleErrors();

    EVP_MD_CTX_free(mdctx);
    return true;
}

bool MainWindow::verifySignature(EVP_PKEY* privateKey, const unsigned char* data, size_t dataSize, const unsigned char* signature, size_t signatureSize)
{
    // Проверка подписи с помощью приватного ключа
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        handleErrors();

    if (1 != EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, privateKey))
        handleErrors();

    if (1 != EVP_DigestVerifyUpdate(mdctx, data, dataSize))
        handleErrors();

    int result = EVP_DigestVerifyFinal(mdctx, signature, signatureSize);
    EVP_MD_CTX_free(mdctx);
    return (result == 0);
}

bool MainWindow::encryptAES(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, const unsigned char* iv, unsigned char*& ciphertext, int& ciphertext_len)
{
    // Шифрование данных с помощью AES-256 в режиме CBC
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv))
        handleErrors();

    ciphertext = (unsigned char*)OPENSSL_malloc(plaintext_len + AES_BLOCK_SIZE);
    if (!ciphertext)
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len))
        handleErrors();

    int len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len))
        handleErrors();

    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool MainWindow::decryptAES(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, const unsigned char* iv, unsigned char*& plaintext, int& plaintext_len)
{
    // Расшифровка данных с помощью AES-256 в режиме CBC
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv))
        handleErrors();

    plaintext = (unsigned char*)OPENSSL_malloc(ciphertext_len);
    if (!plaintext)
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len))
        handleErrors();

    int len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len))
        handleErrors();

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

QByteArray MainWindow::encryptPixelData(const QByteArray& pixelData, const unsigned char* key, const unsigned char* iv)
{
    // Шифрование данных
    unsigned char* ciphertext = nullptr;
    int ciphertext_len = 0;
    if (!encryptAES(reinterpret_cast<const unsigned char*>(pixelData.data()), pixelData.size(), key, iv, ciphertext, ciphertext_len)) {
        handleErrors();
        return QByteArray();
    }

    QByteArray encryptedData(reinterpret_cast<char*>(ciphertext), ciphertext_len);
    OPENSSL_free(ciphertext);
    return encryptedData;
}

QByteArray MainWindow::decryptPixelData(const QByteArray& encryptedData, const unsigned char* key, const unsigned char* iv)
{
    // Расшифровка данных
    unsigned char* plaintext = nullptr;
    int plaintext_len = 0;
    if (!decryptAES(reinterpret_cast<const unsigned char*>(encryptedData.data()), encryptedData.size(), key, iv, plaintext, plaintext_len)) {
        handleErrors();
        return QByteArray();
    }

    QByteArray decryptedData(reinterpret_cast<char*>(plaintext), plaintext_len);
    OPENSSL_free(plaintext);
    return decryptedData;
}

void MainWindow::processImage()
{
    // Вызов функций для шифрования и отправки, а также получения и расшифровки
    encryptAndSend();
    receiveAndDecrypt();
}

void MainWindow::encryptAndSend()
{
    // Шифрование и отправка данных
    QString cwd = QDir::currentPath();
    QString publicKeyPath = cwd + "/public.pem";

    // Загрузка публичного ключа для подписи
    EVP_PKEY* publicKey = loadKey(publicKeyPath.toStdString().c_str(), true);
    if (!publicKey)
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось загрузить публичный ключ");
        return;
    }

    // Чтение файла изображения
    QImage originalImage(selectedFilePath);
    if (originalImage.isNull())
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть файл изображения");
        EVP_PKEY_free(publicKey);
        return;
    }

    // Преобразование изображения в байтовый массив
    QByteArray imageData;
    QBuffer buffer(&imageData);
    buffer.open(QIODevice::WriteOnly);
    originalImage.save(&buffer, "PNG");
    buffer.close();

    // Подпись данных
    unsigned char* signature = nullptr;
    size_t signatureSize = 0;
    if (!signData(publicKey, reinterpret_cast<const unsigned char*>(imageData.data()), imageData.size(), signature, signatureSize))
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось подписать данные");
        EVP_PKEY_free(publicKey);
        return;
    }

    // Генерация ключа AES и вектора инициализации (IV)
    unsigned char aesKey[AES_KEYLENGTH / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(aesKey, sizeof(aesKey)) || !RAND_bytes(iv, sizeof(iv)))
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось сгенерировать ключ AES/IV");
        EVP_PKEY_free(publicKey);
        OPENSSL_free(signature);
        return;
    }

    // Шифрование изображения
    QByteArray encryptedPixelData = encryptPixelData(imageData, aesKey, iv);
    if (encryptedPixelData.isEmpty())
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось зашифровать данные");
        EVP_PKEY_free(publicKey);
        OPENSSL_free(signature);
        return;
    }

    // Имитация отправки зашифрованных данных по сети (сохранение в файл)
    std::ofstream encryptedFile((cwd + "/encrypted_image.bin").toStdString(), std::ios::binary);
    encryptedFile.write(encryptedPixelData.data(), encryptedPixelData.size());
    encryptedFile.close();

    // Имитация отправки подписи по сети (сохранение в файл)
    std::ofstream signatureFile((cwd + "/signature.bin").toStdString(), std::ios::binary);
    signatureFile.write(reinterpret_cast<char*>(signature), signatureSize);
    signatureFile.close();

    // Имитация отправки ключа AES и IV
    std::ofstream keyFile((cwd + "/key.bin").toStdString(), std::ios::binary);
    keyFile.write(reinterpret_cast<char*>(aesKey), sizeof(aesKey));
    keyFile.write(reinterpret_cast<char*>(iv), sizeof(iv));
    keyFile.close();

    // Создание изображения с шумом из зашифрованных данных
    QImage encryptedImage(originalImage.width(), originalImage.height(), QImage::Format_Grayscale8);
    for (int y = 0; y < encryptedImage.height(); ++y)
    {
        for (int x = 0; x < encryptedImage.width(); ++x)
        {
            int index = y * encryptedImage.width() + x;
            if (index < encryptedPixelData.size())
            {
                encryptedImage.setPixelColor(x, y, QColor::fromRgb(encryptedPixelData[index], encryptedPixelData[index], encryptedPixelData[index]));
            } else
            {
                encryptedImage.setPixelColor(x, y, QColor::fromRgb(0, 0, 0)); // заполнение черным, если будет выход за пределы
            }
        }
    }
    encryptedImage.save(cwd + "/encrypted_image_noise.png");

    // Обновление интерфейса
    updateImage(ui->originalImage, selectedFilePath);
    updateImage(ui->encryptedImage, cwd + "/encrypted_image_noise.png");

    // Освобождение ресурсов
    EVP_PKEY_free(publicKey);
    OPENSSL_free(signature);

    QMessageBox::information(this, "Отправка данных", "Данные успешно зашифрованы и отправлены");
}

void MainWindow::receiveAndDecrypt()
{
    // Получение и расшифровка данных
    QString cwd = QDir::currentPath();
    QString privateKeyPath = cwd + "/private.pem";

    // Загрузка приватного ключа для проверки подписи
    EVP_PKEY* privateKey = loadKey(privateKeyPath.toStdString().c_str(), false);
    if (!privateKey)
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось загрузить приватный ключ");
        return;
    }

    // Имитация получения зашифрованных данных по сети (чтение из файла)
    std::ifstream encryptedFile((cwd + "/encrypted_image.bin").toStdString(), std::ios::binary);
    std::vector<char> encryptedData((std::istreambuf_iterator<char>(encryptedFile)), std::istreambuf_iterator<char>());
    encryptedFile.close();

    // Имитация получения подписи по сети (чтение из файла)
    std::ifstream signatureFile((cwd + "/signature.bin").toStdString(), std::ios::binary);
    std::vector<char> signatureData((std::istreambuf_iterator<char>(signatureFile)), std::istreambuf_iterator<char>());
    signatureFile.close();

    // Преобразование std::vector<char> в QByteArray
    QByteArray encryptedPixelData = QByteArray::fromRawData(encryptedData.data(), encryptedData.size());
    QByteArray signatureByteArray = QByteArray::fromRawData(signatureData.data(), signatureData.size());

    // Имитация получения ключа AES и IV
    unsigned char aesKey[AES_KEYLENGTH / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    std::ifstream keyFile((cwd + "/key.bin").toStdString(), std::ios::binary);
    keyFile.read(reinterpret_cast<char*>(aesKey), sizeof(aesKey));
    keyFile.read(reinterpret_cast<char*>(iv), sizeof(iv));
    keyFile.close();

    // Расшифровка данных
    QByteArray decryptedData = decryptPixelData(encryptedPixelData, aesKey, iv);
    if (decryptedData.isEmpty())
    {
        QMessageBox::critical(this, "Ошибка", "Не удалось расшифровать данные");
        EVP_PKEY_free(privateKey);
        return;
    }

    // Проверка подписи
    if (!verifySignature(privateKey, reinterpret_cast<const unsigned char*>(decryptedData.data()), decryptedData.size(),
                         reinterpret_cast<const unsigned char*>(signatureByteArray.data()), signatureByteArray.size()))
    {
        QMessageBox::warning(this, "Предупреждение", "Проверка подписи не пройдена");
    } else
    {
        QMessageBox::information(this, "Успех", "Проверка подписи прошла успешно");
    }

    // Сохранение расшифрованного изображения
    QImage decryptedImage = QImage::fromData(decryptedData, "PNG");
    decryptedImage.save(cwd + "/decrypted_image.png");

    // Обновление интерфейса
    updateImage(ui->decryptedImage, cwd + "/decrypted_image.png");

    // Обновление информации о размерах файлов
    ui->sizeLabel->setText(QString("Размеры файлов:\nИсходный: %1 байт\nЗашифрованный: %2 байт\nРасшифрованный: %3 байт\nПодпись: %4 байт")
                               .arg(decryptedData.size()).arg(encryptedPixelData.size()).arg(decryptedData.size()).arg(signatureByteArray.size()));

    EVP_PKEY_free(privateKey);

    QMessageBox::information(this, "Получение данных", "Данные успешно получены, расшифрованы и проверены");
}
