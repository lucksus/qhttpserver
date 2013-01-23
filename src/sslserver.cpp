#include <QSsl>
#include <QSslSocket>
#include <QDebug>
#include "sslserver.h"

SslServer::SslServer(const QSslCertificate cert, const QSslKey key, QObject *parent) :
    QTcpServer(parent),
    m_sslCertificate(cert),
    m_sslKey(key)
{
}

void SslServer::incomingConnection(qintptr handle)
{
    QSslSocket* sock = new QSslSocket(this);
    if (sock->setSocketDescriptor(handle)) {
        sock->setPrivateKey(m_sslKey);
        sock->setLocalCertificate(m_sslCertificate);
        sock->startServerEncryption();
        connect(sock, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(sslSocket_sslErrors(QList<QSslError>)));
        connect(sock, SIGNAL(encrypted()), this, SLOT(sslSocket_encrypted()));
        connect(this, SIGNAL(ignoreSslErrors()), sock, SLOT(ignoreSslErrors()));
        addPendingConnection(sock);
    } else {
        qWarning() << "Failed to init QSslSocket with handle: " << handle << "!";
        delete sock;
    }
}

void SslServer::sslSocket_encrypted()
{
}

void SslServer::sslSocket_sslErrors(const QList<QSslError> &sslErrors)
{
}
