/*********************************************************************
 * Software License Agreement (BSD License)
 *
 *  Copyright (c) 2014 Norwegian University of Science and Technology
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Norwegian University of Science and
 *     Technology, nor the names of its contributors may be used to
 *     endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *  COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 *  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *********************************************************************/

/*
 * Author: Markus Mueller <markus.mueller@scs.ch>
 */

#ifndef KUKA_RSI_HARDWARE_INTERFACE_TCP_SERVER_
#define KUKA_RSI_HARDWARE_INTERFACE_TCP_SERVER_

#include "SocketServer.h"
#include <chrono>

#include <iostream>
#include <string>

// Select includes
#include <sys/time.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <cstdlib>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cerrno>

# include <fcntl.h>
#if HAVE_STROPTS_H
#include <stropts.h>
#endif

#include <poll.h>

class TCPServer : public SocketServer {
public:
    TCPServer(std::string host, unsigned short port) : local_host_(host), local_port_(port), timeout_(false) {

    }

    ~TCPServer() {
        close(connSockFd_);
        close(sockfd_);
    }

    virtual void start() {

        sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_ < 0) {
            std::cout << "ERROR opening socket" << std::endl;
        }
        optval = 1;
        setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(int));
        memset(&serveraddr_, 0, sizeof(serveraddr_));
        serveraddr_.sin_family = AF_INET;
        // serveraddr_.sin_addr.s_addr = inet_addr(local_host_.c_str());
        serveraddr_.sin_addr.s_addr = htonl(INADDR_ANY);
        serveraddr_.sin_port = htons(local_port_);
        if (bind(sockfd_, (struct sockaddr *) &serveraddr_, sizeof(serveraddr_)) < 0) {
            // ROS_ERROR_STREAM("ERROR on binding socket[" << errno << "] " << strerror(errno));
            std::cout << "ERROR on binding socket[" << errno << "] " << strerror(errno) << std::endl;
        }
        clientlen_ = sizeof(clientaddr_);
        // ROS_INFO_NAMED("TCPSocket", "Waiting for connection...");
        // std::cout << "Waiting for connection" << std::endl;
        listen(sockfd_, 1); // listen for 1 connection
        // std::cout << "Listened" << std::endl;
        connSockFd_ = accept(sockfd_, (struct sockaddr *) &clientaddr_, &clientlen_);
        if (connSockFd_ < 0) {
            // ROS_ERROR_STREAM("Error on accept [" << errno << "] " << strerror(errno));
            std::cout << "Error on accept [" << errno << "] " << strerror(errno) << std::endl;
            return;
        }
        set_timeout(0);

        // disable "Nagle Algorithm"
        int flag = 1;
        int result = setsockopt(connSockFd_, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
        if (result < 0)
        {
            // ROS_ERROR("Failed to set TCP_NODELAY");
            std::cout << "Failed to set TCP_NODELAY" << std::endl;
        }
        // ROS_INFO_STREAM_NAMED("TCPSocket", "Connection from " << inet_ntoa(clientaddr_.sin_addr));
    }

    virtual void start_nonblocking() {

        sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_ < 0) {
            std::cout << "ERROR opening socket" << std::endl;
        }

        int flags = fcntl(sockfd_, F_GETFL, 0);
        if (flags == -1) {
            perror("fcntl(F_GETFL) failed");
            close(sockfd_);
            return;
        }

        flags |= O_NONBLOCK;
        if (fcntl(sockfd_, F_SETFL, flags) == -1) {
            perror("fcntl(F_SETFL) failed");
            close(sockfd_);
            return;
        }

        optval = 1;
        setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(int));
        memset(&serveraddr_, 0, sizeof(serveraddr_));
        serveraddr_.sin_family = AF_INET;
        // serveraddr_.sin_addr.s_addr = inet_addr(local_host_.c_str());
        serveraddr_.sin_addr.s_addr = htonl(INADDR_ANY);
        serveraddr_.sin_port = htons(local_port_);
        if (bind(sockfd_, (struct sockaddr *) &serveraddr_, sizeof(serveraddr_)) < 0) {
            // ROS_ERROR_STREAM("ERROR on binding socket[" << errno << "] " << strerror(errno));
            std::cout << "ERROR on binding socket[" << errno << "] " << strerror(errno) << std::endl;
        }
        clientlen_ = sizeof(clientaddr_);
        // ROS_INFO_NAMED("TCPSocket", "Waiting for connection...");
        // std::cout << "Waiting for connection" << std::endl;
        listen(sockfd_, 1); // listen for 1 connection
        // std::cout << "Listened" << std::endl;
        std::cout << "Connecting..." << std::endl;
        while (true) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sockfd_, &readfds);

            struct timeval timeout = {0, 100000};  // Wait for up to 100ms

            // Check if the socket is ready to accept a connection
            int ret = select(sockfd_ + 1, &readfds, NULL, NULL, &timeout);

            if (ret < 0) {
                std::cerr << "select() failed: " << strerror(errno) << std::endl;
                return;
            } else if (ret == 0) {
                // No connection available, continue with other tasks
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            if (FD_ISSET(sockfd_, &readfds)) {
                connSockFd_ = accept(sockfd_, (struct sockaddr *) &clientaddr_, &clientlen_);
                if (connSockFd_ < 0) {
                    std::cerr << "Error on accept: " << strerror(errno) << std::endl;
                    return;
                }
                std::cout << "Connection established!" << std::endl;
                // Proceed with setting up the socket and handling communication
                break;
            }
        }
        // Nonblocking connSockFd_
        int flags_client = fcntl(connSockFd_, F_GETFL, 0);
        if (flags_client == -1) {
        perror("fcntl(F_GETFL) failed on connSockFd_");
        close(connSockFd_);
        return;
        }
        flags_client |= O_NONBLOCK;
        if (fcntl(connSockFd_, F_SETFL, flags_client) == -1) {
        perror("fcntl(F_SETFL) failed on connSockFd_");
        close(connSockFd_);
        return;
        }
        // if (connSockFd_ < 0) {
        //     // ROS_ERROR_STREAM("Error on accept [" << errno << "] " << strerror(errno));
        //     std::cout << "Error on accept [" << errno << "] " << strerror(errno) << std::endl;
        //     return;
        // }
        std::cout << "Connected!" << std::endl;

        set_timeout(0);

        // disable "Nagle Algorithm"
        int flag = 1;
        int result = setsockopt(connSockFd_, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
        if (result < 0)
        {
            // ROS_ERROR("Failed to set TCP_NODELAY");
            std::cout << "Failed to set TCP_NODELAY" << std::endl;
        }
        // ROS_INFO_STREAM_NAMED("TCPSocket", "Connection from " << inet_ntoa(clientaddr_.sin_addr));
    }




    virtual bool set_timeout(int millisecs) {
        if (millisecs < 0) {
            throw std::runtime_error("Unable to set timeout to a negative number");
        }
        tv_.tv_sec = millisecs / 1000;
        tv_.tv_usec = (millisecs % 1000) * 1000;
        int err = setsockopt(connSockFd_, SOL_SOCKET, SO_RCVTIMEO, (const void *) &tv_, sizeof(tv_));
        if (err < 0) {
            // ROS_ERROR_STREAM("Error setting read timeout");
            std::cout << "ERROR: setting read timeout" << std::endl;
        }
        err = setsockopt(connSockFd_, SOL_SOCKET, SO_SNDTIMEO, (const void *) &tv_, sizeof(tv_));
        if (err < 0) {
            // ROS_ERROR_STREAM("Error setting send timeout");
            std::cout << "ERROR: setting send timeout" << std::endl;
        }

        timeout_ = millisecs != 0;
        return timeout_;

    }


    virtual ssize_t send(std::string &buffer) {
        ssize_t bytes = 0;
        bytes = write(connSockFd_, buffer.c_str(), buffer.size());
        if (bytes < 0) {
            std::cout << "ERROR in sendto[" << errno << "] " << strerror(errno) << std::endl;
            // ROS_INFO_STREAM("ERROR in sendto[" << errno << "] " << strerror(errno));
        }

        // std::cout << "Bytes from send fnc in TCP Server: " << bytes << std::endl;

        return bytes;
    }


    virtual ssize_t recv_block(std::string &buffer) {
        ssize_t bytes = 0;
        memset(buffer_, 0, BUFFER_SIZE);

        auto current_time = std::chrono::steady_clock::now();
        // from yassir to see how long ago since last receive last_recv_time_ is set to time now when server started and is updated only when artificial timeout should be produced
        auto elapsed_time = std::chrono::duration_cast<std::chrono::seconds>(current_time - last_recv_time_).count();


        // check if wre have set a timeout i.e the read funcxtion is not blocking and returns even when no data in the buffer
        if (timeout_) {
            // std::cout << "Timeout in tcp_server.cpp recv()" << std::endl;
            // something's weird if a timeout != 0 is set: it sometimes gives error EINTR: 'Interrupted system call'.
            // apparently it's ok to just retry....
            int count = 0;
            do {
                // question: after reading is the data cleared i.e read after read returns null or the same as before
                // 0: Indicates end-of-file (EOF) if the file descriptor refers to a file and there is no more data to read. -1: Indicates an error occurred, and errno is set to specify the error.
                bytes = read(connSockFd_, buffer_, BUFFER_SIZE);


                // DEBUG LOGS
                // errno = 11: EAGAIN, EWOULDBLOCK (timeout)

                if (bytes == -1){
                    buffer = std::string(buffer_);
                    /*
                    ROS_INFO_STREAM("in recv normal operation with timeout on socket option: read done");
                    ROS_INFO_STREAM("in recv normal operation with timeout on socket option: bytes: " << bytes);
                    ROS_INFO_STREAM("in recv normal operation with timeout on socket option: errno: " << errno);
                    ROS_INFO_STREAM("in recv normal operation: buffer_size = " << buffer.size());
                    */

                    std::cout << "in recv normal operation with timeout on socket option: read done" << std::endl;
                    std::cout << "in recv normal operation with timeout on socket option: bytes: " << bytes << std::endl;
                    std::cout << "in recv normal operation with timeout on socket option: errno: " << errno << std::endl;
                    std::cout << "in recv normal operation: buffer_size = " << buffer.size() << std::endl;

                }/*else{
                    ROS_INFO_STREAM("in recv normal operation with. bytes = " << bytes << ", buffer.size = " << buffer.size());
                }*/


                if(++count > 10) {
                    // ROS_ERROR_STREAM("Read interrupted " << count << "times.");
                    throw std::runtime_error("Read interrupted");
                }
                // errno gets EWOULDBLOCK when no data for 20ms in the read and read returns -1 because of this
                // errno =EWOULDBLOCK means Operation (read) would have been blocking if we would not have set the tinmeout
                // errno=EINTR means Interrupted system call, then we tzry 10x (200ms) until wo proceed 
            } while (bytes < 0 && errno == EINTR);
        } else {
        
            bytes = read(connSockFd_, buffer_, BUFFER_SIZE);
            // ROS_INFO_STREAM("in recv normal operation without timeout on socket option: read done");
        }

        // Yassir suspects: IF PROGRAM CRASHES WHEN REAL TIME OUT HAPPENS IT IS BECAUSE OF THIS LINE
        // what are we getting when there is a timeout ? probably zeros
        
        // std::cout << "Buffer before String: " << buffer_ << std::endl;
        buffer = std::string(buffer_);


        // Uncomment this to generate artificial timeout

        /*
        if (elapsed_time >= 20 && elapsed_time < 20.05) {
            // Artificial timeout reached
            // ROS_INFO_STREAM("Artificial timeout reached. No data received for 20 miliseconds.");
            ROS_INFO_STREAM("Artificial timeout ongoingi.e returning -1 in recv");
            // last_recv_time_ = current_time;
            return -1;}
        */

        /*
        if (elapsed_time >= 20.05) {
            // Artificial timeout reached
            ROS_INFO_STREAM("Artificial timeout finished returning last time -1 in recv");
            last_recv_time_ = current_time;
            return -1;}
        */
   
        
        //WHEN A TIMEOUT HAPPENS WE GO THROUGH HERE 
        if (bytes < 0 and false) {
            if (errno == EWOULDBLOCK) {
            // ROS_INFO_STREAM("read returned bytes = -1 with errno == EWOULDBLOCK (timeout)");
            // ros::shutdown(); // COMMENT THIS LINE SO THAT ROS DOESN'T SHUT DOWN WHEN THERE IS A TIMEOUT
                return -1;
            }
        }

        //WHEN A TIMEOUT HAPPENS WE GO THROUGH HERE 
        if (bytes < 0) {
            if (errno != EWOULDBLOCK) {
            // ROS_INFO_STREAM("read returned bytes = -1 with errno != EWOULDBLOCK (different from timeout)");
            // ros::shutdown(); // COMMENT THIS LINE SO THAT ROS DOESN'T SHUT DOWN WHEN THERE IS A TIMEOUT
                return -1;
            }
        }
        
        
        return bytes;
    }

    // virtual ssize_t recv(std::string &buffer) {
    //     ssize_t bytes = 0;
    //     memset(buffer_, 0, BUFFER_SIZE);

    //     auto current_time = std::chrono::steady_clock::now();
    //     // from yassir to see how long ago since last receive last_recv_time_ is set to time now when server started and is updated only when artificial timeout should be produced
    //     auto elapsed_time = std::chrono::duration_cast<std::chrono::seconds>(current_time - last_recv_time_).count();

    //     bytes = read(connSockFd_, buffer_, BUFFER_SIZE);

    //     buffer = std::string(buffer_);

    //     //WHEN A TIMEOUT HAPPENS WE GO THROUGH HERE 
    //     if (bytes < 0) {
    //         if (errno != EWOULDBLOCK) {
    //         // ROS_INFO_STREAM("read returned bytes = -1 with errno != EWOULDBLOCK (different from timeout)");
    //         // ros::shutdown(); // COMMENT THIS LINE SO THAT ROS DOESN'T SHUT DOWN WHEN THERE IS A TIMEOUT
    //             return -1;
    //         }
    //     }
        
        
    //     return bytes;
    // }


    // virtual ssize_t recv_nonblocking(std::string &buffer, int timeout_ms) {
    //     ssize_t bytes = 0;
    //     // Polling structure
    //     struct pollfd pfd;
    //     pfd.fd = connSockFd_;       // File descriptor for the socket
    //     pfd.events = POLLIN;        // Wait for readiness to read
    //     memset(buffer_, 0, BUFFER_SIZE);

    //     // Poll with timeout
    //     int poll_ret = poll(&pfd, 1, 1000); // 1 socket, timeout in milliseconds
    //     if (poll_ret == -1) {
    //         throw std::runtime_error("poll() failed with error: " + std::string(strerror(errno)));
    //     } else if (poll_ret == 0) {
    //         // Timeout occurred
    //         std::cerr << "poll() timed out, no data available." << std::endl;
    //         return -1; // Indicate no data was read
    //     }

    //     // Check if the socket is ready for reading
    //     if (pfd.revents & POLLIN) {
    //         // Perform the read
    //         bytes = read(connSockFd_, buffer_, BUFFER_SIZE);
    //         if (bytes > 0) {
    //             // Successfully read data
    //             buffer = std::string(buffer_);
    //             return bytes;
    //         } else if (bytes == 0) {
    //             // Socket closed by the remote end
    //             std::cerr << "Socket closed by the peer." << std::endl;
    //             return 0; // Indicate closed socket
    //         } else {
    //             // Error occurred
    //             if (errno == EAGAIN || errno == EWOULDBLOCK) {
    //                 std::cerr << "Non-blocking read: no data available right now." << std::endl;
    //                 return -1; // No data available
    //             } else {
    //                 std::cerr <<  "read() failed with error: " << std::string(strerror(errno));
    //                 return -1; // No data available
    //             }
    //         }
    //     }
    //     return -1; // should not get here. If it does return -1 to indicate error
    // }

    virtual ssize_t recv_nonblocking(std::string &buffer, int timeout_ms) {

        char new_buffer[BUFFER_SIZE];

        memset(new_buffer, 0, BUFFER_SIZE);

        ssize_t bytes = recv(connSockFd_, new_buffer, BUFFER_SIZE, 0);

        if (bytes > 0) buffer = std::string(new_buffer);
        
        return bytes;
    }



private:
    std::string local_host_;
    unsigned short local_port_;
    bool timeout_;
    struct timeval tv_;

    int sockfd_;
    int connSockFd_;
    socklen_t clientlen_;
    struct sockaddr_in serveraddr_;
    struct sockaddr_in clientaddr_;
    char buffer_[BUFFER_SIZE];
    int optval;
    std::chrono::steady_clock::time_point last_recv_time_ = std::chrono::steady_clock::now()+ std::chrono::seconds(30);
    std::chrono::steady_clock::time_point current_time_;

};

#endif

