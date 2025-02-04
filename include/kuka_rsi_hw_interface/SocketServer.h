//
// Created by muellerm on 31.10.16.
//

#ifndef KUKA_RSI_HW_INTERFACE_SOCKETSERVER_H
#define KUKA_RSI_HW_INTERFACE_SOCKETSERVER_H

#include <string>

#define BUFFER_SIZE 2048

class SocketServer {
public:
    virtual ssize_t send(std::string &buffer) = 0;
    virtual ssize_t recv_block(std::string &buffer) = 0;
    virtual ssize_t recv_nonblocking(std::string &buffer, int timeout) = 0;
    virtual bool set_timeout(int millisecs) = 0;
    virtual void start() = 0;
    virtual void start_nonblocking() = 0;
};


#endif //KUKA_RSI_HW_INTERFACE_SOCKETSERVER_H
