#ifndef SSLSERVER_H
#define SSLSERVER_H

#include <QTcpServer>
#include <QSsl>
#include <QSslCertificate>
#include <QSslKey>

class SslServer : public QTcpServer
{
    Q_OBJECT
public:
    explicit SslServer(const QSslCertificate cert, const QSslKey key, QObject *parent = 0);
    
signals:
    void ignoreSslErrors();
public slots:
    void incomingConnection(qintptr handle);
    void sslSocket_encrypted();
    void sslSocket_sslErrors(const QList<QSslError>& sslErrors);
    
private:
    QSslCertificate m_sslCertificate;
    QSslKey m_sslKey;
};

#endif // SSLSERVER_H
