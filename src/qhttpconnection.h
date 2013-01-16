/*
 * Copyright 2011 Nikhil Marathe <nsm.nikhil@gmail.com>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE. 
 */

#ifndef Q_HTTP_CONNECTION
#define Q_HTTP_CONNECTION

#include <QObject>
#include <QHash>

#include <http_parser.h>


class QTcpSocket;

class QHttpRequest;
class QHttpResponse;
class QAuthenticatorRealm;

typedef QHash<QString, QString> HeaderHash;

class QHttpConnection : public QObject
{
    Q_OBJECT

public:
    QHttpConnection(QTcpSocket *socket, QAuthenticatorRealm *realm = 0, QObject *parent = 0);
    virtual ~QHttpConnection();

    void write(const QByteArray &data);
    void flush();

    QAuthenticatorRealm* getRealm();

public slots:
    void dissonectFromHost();

signals:
    void newRequest(QHttpRequest*, QHttpResponse*);

private slots:
    void parseRequest();
    void socketDisconnected();

private:
    static int MessageBegin(http_parser *parser);
    static int Url(http_parser *parser, const char *at, size_t length);
    static int HeaderField(http_parser *parser, const char *at, size_t length);
    static int HeaderValue(http_parser *parser, const char *at, size_t length);
    static int HeadersComplete(http_parser *parser);
    static int Body(http_parser *parser, const char *at, size_t length);
    static int MessageComplete(http_parser *parser);
    static int checkAuthentication(QAuthenticatorRealm *realm, QHttpRequest* request, QHttpResponse* response);
    static int requestAuthenticationFromClient(QString realmName, QHttpRequest* request, QHttpResponse* response);
    static int refuseUnauthenticatedConnection(QHttpRequest* request, QHttpResponse* response);

private:
    QTcpSocket *m_socket;
    http_parser_settings m_parserSettings;
    http_parser *m_parser;

    // since there can only be one request at any time
    // even with pipelining
    QHttpRequest *m_request;

    // the ones we are reading in from the parser
    HeaderHash m_currentHeaders;
    QString m_currentHeaderField;
    QString m_currentHeaderValue;
    QAuthenticatorRealm* m_realm;
    bool m_authorized;
};

#endif
