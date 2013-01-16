#include "qauthenticatorrealm.h"

QAuthenticatorRealm::QAuthenticatorRealm(QString name, QObject *parent) :
    QObject(parent)
{
    this->setObjectName(name);
}

QStringList QAuthenticatorRealm::getUsernameAndPassword(QString cred)
{
    QByteArray plain_cred = cred.toLatin1();
    QByteArray decoded_cred_byte = QByteArray::fromBase64(plain_cred);
    QString decoded_cred = QString::fromLatin1(decoded_cred_byte);

    QStringList credentials = decoded_cred.split(",", QString::SkipEmptyParts);
    if (credentials.size() <= 1 || credentials.size() > 2) { //No Element or multi elements parsed
        QStringList empty;
        return empty;
    }

    return credentials;
}

bool QAuthenticatorRealm::authenticateUserBasic(QString cred)
{
    QStringList credentials = this->getUsernameAndPassword(cred);

    if (credentials.size() <= 1 || credentials.size() > 2) //No Element or multi elements parsed
        return false;

    QString username = credentials.at(0);
    QString password = credentials.at(1);

    QHash<QString,QString>::const_iterator i = m_credentials.constBegin();
    while (i != m_credentials.constEnd()) {
        if (username == i.key() && password == i.value())
            return true; // User found
    }
    return false;
}

bool QAuthenticatorRealm::addCredential(QString username, QString password)
{
    if (m_credentials.contains(username)) {
        return false;
    } else {
      m_credentials.insert(username, password);
      return true;
    }
}

bool QAuthenticatorRealm::removeCredential(QString username)
{
    int retval = m_credentials.remove(username);
    if (retval > 0) {
        return true;
    } else {
        return false;
    }
}
