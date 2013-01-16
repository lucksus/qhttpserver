#ifndef QAUTHENTICATORREALM_H
#define QAUTHENTICATORREALM_H

#include <QObject>
#include <QHash>
#include <QStringList>

class QAuthenticatorRealm : public QObject
{
    Q_OBJECT
public:
    explicit QAuthenticatorRealm(QString name, QObject *parent = 0);

    QStringList getUsernameAndPassword(QString cred);
    bool authenticateUserBasic(QString cred);
signals:
    
public slots:
    bool addCredential(QString username, QString password);
    bool removeCredential(QString username);
private:
    QHash<QString,QString> m_credentials;
    
};

#endif // QAUTHENTICATORREALM_H
