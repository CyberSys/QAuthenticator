/*
 * hotp.cpp
 *
 * [RFC 4226] HOTP: An HMAC-Based One-Time Password Algorithm Implementation
 *
 * Created on: 03-Sep-2017
 * Author: Jaseem V V
 * Website: https://www.qlambda.com
 */

#include "hotp.h"
#include "sbreturn.h"
#include "hugse56.h"

#include <QDebug>

using namespace std;

/** Initialize HOTP and BlackBerry Cryptographic library */
HOTP::HOTP()
{
    int rc = SB_SUCCESS;
    rc = hu_GlobalCtxCreateDefault(&sbCtx);  // Create default global context for the security builder context
    rc = hu_RegisterSbg56(sbCtx);  // Register all algorithms from the BlackBerry Cryptographic Kernel v5.6 (SB-GSE-56)
    rc = hu_InitSbg56(sbCtx);  // Initialize crypto provider. Should be called only once in the lifetime of the application
    hmacContext = NULL;
}

/**
 * Calculates checksum using credit card algorithm
 *
 * @param num the number to calculate the checksum for
 * @param digits number of significant places in the number
 *
 * @return the checksum of num
 */
int HOTP::calcChecksum(long num, int digits) {
    int doubleDigits[] = {0, 2, 4, 6, 8, 1, 3, 5, 7, 9};
    bool doubleDigit = true;
    int total = 0;
    while (0 < digits--) {
        int digit = (int) (num % 10);
        num /= 10;
        if (doubleDigit) {
            digit = doubleDigits[digit];
        }
        total += digit;
        doubleDigit = !doubleDigit;
    }
    int result = total % 10;
    if (result > 0) {
        result = 10 - result;
    }
    return result;
}

/**
 * Return the moving factor put into a byte array
 *
 * @param counter The moving factor
 *
 */
QByteArray HOTP::getMovingFactor(long counter) {
    QByteArray text;
    int size = 8;
    text.resize(size);
    for (int i = size - 1; i >= 0; i--) {
        text[i] = counter & 0xff;
        counter >>= 8;
    }
    return text;
}

/**
 * Performs dynamic truncation by extracting 4-byte dynamic binary code from a 20 byte (160 bit) HMAC-SHA1 result
 *
 * @param digest The HMAC-SHA1 digest byte array
 * @param truncationOffset Offset to which the truncation should begin if in range
 *
 * @return The truncated integer
 */
int HOTP::truncate(QByteArray *digest, int truncationOffset) {
    int digestLen = digest->capacity();
    int offset = digest->at(digestLen - 1) & 0xf;
    if ((0 <= truncationOffset) && (truncationOffset < (digestLen - 4))) {
        offset = truncationOffset;
    }
    return (digest->at(offset) & 0x7f) << 24 | (digest->at(offset+1) & 0xff) << 16 | (digest->at(offset+2) & 0xff) << 8 | (digest->at(offset+3) & 0xff);
}

/**
 * Generate HOTP for the given secret and moving factor
 *
 * @param secret The shared secret
 * @param movingFactor Counter, time, or other value that changes on a per use basis
 * @param codeDigits The number of digits in the OTP not including the checksum if any
 * @param addChecksum If checksum should be appended to the OTP
 * @param truncationOffset The offset into the HMAC result to being truncation. If the value is out of range of 0..15, then dynamic truncation will be used
 *
 * @return The HOTP integer value
 */
int HOTP::generateHOTP(QString secret, long movingFactor, int codeDigits, bool addChecksum, int truncationOffset) {
                      // 0 1  2   3    4     5      6       7        8
    int digitsPower[] = {1,10,100,1000,10000,100000,1000000,10000000,100000000};
    qDebug() << "generateHOTP";
    QByteArray counter = getMovingFactor(movingFactor);
    qDebug() << counter.toHex();
    QByteArray* digest = generateHMACSHA1(secret, counter);
    qDebug() << "HS: " << digest->toHex();
    int snum = truncate(digest, truncationOffset);
    qDebug() << "Snum: " << snum;
    int otp = snum % digitsPower[codeDigits];
    qDebug() << "OTP: " << otp;
    int hotp = addChecksum ? (otp * 10) + calcChecksum(otp, codeDigits) : otp;
    qDebug() << "HOTP: " << hotp;
    return hotp;
}

/**
 * Generates HMAC-SHA1 digest for the given shared secret and input text
 *
 * @param sharedKey The shared secret
 * @param counter The moving factor
 *
 * @return The digest byte array
 */
QByteArray* HOTP::generateHMACSHA1(QString sharedKey, QByteArray counter) {
    int rc = SB_SUCCESS;
    QByteArray key_ba = sharedKey.toUtf8();
    const unsigned char *key = reinterpret_cast<const unsigned char *>(key_ba.data());
    unsigned char *counter_blk = reinterpret_cast<unsigned char *>(counter.data());
    unsigned char messageDigestHMAC[SB_HMAC_SHA1_160_TAG_LEN];

    qDebug() << "key_ba length: " << (size_t)key_ba.length();
    rc = hu_HMACSHA1Begin((size_t)key_ba.length(), key, NULL, &hmacContext, sbCtx);  // Initialize HMAC-SHA1 with key and context
    rc = hu_HMACSHA1Hash(hmacContext, counter.length(), counter_blk, sbCtx);  // Provide the input message
    rc = hu_HMACSHA1End(&hmacContext, SB_HMAC_SHA1_160_TAG_LEN, messageDigestHMAC, sbCtx);  // Generate the digest
    return new QByteArray(reinterpret_cast<const char *>(messageDigestHMAC), SB_HMAC_SHA1_160_TAG_LEN);
}

/** Converts binary string to corresponding HEX */
QString HOTP::binToHex(unsigned char *message) {
    QString digest;
    for (int i = 0; i < SB_HMAC_SHA1_160_TAG_LEN; ++i) {
        digest.append(QString("%1").arg(QString::number((uint)message[i], 16), 2, QChar('0')));
    }
    qDebug() << digest;
    return digest;
}

HOTP::~HOTP()
{
    hu_GlobalCtxDestroy(&sbCtx);
}

