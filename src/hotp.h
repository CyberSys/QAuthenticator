/*
 * hotp.h
 *
 * [RFC 4226] HOTP: An HMAC-Based One-Time Password Algorithm Implementation
 *
 * Created on: 03-Sep-2017
 * Author: Jaseem V V
 * Website: https://www.qlambda.com
 */

#ifndef HOTP_H_
#define HOTP_H_

#include "huctx.h"
#include "husha1.h"

#include <QObject>

class HOTP {
public:
    HOTP();
    int generateHOTP(QString secret, long movingFactor, int codeDigits, bool addChecksum, int truncationOffset);
    virtual ~HOTP();
private:
    sb_GlobalCtx sbCtx;
    sb_Context hmacContext;
    QByteArray* generateHMACSHA1(QString sharedKey, QByteArray counter);
    int calcChecksum(long num, int digits);
    QByteArray getMovingFactor(long counter);
    int truncate(QByteArray *digest_ba, int truncationOffset);
    QString binToHex(unsigned char *messageDigestHMAC);
};

#endif /* HOTP_H_ */
