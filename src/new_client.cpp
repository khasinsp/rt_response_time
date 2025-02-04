#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <linux/net_tstamp.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>

#define SERVER_IP "172.29.3.18"
#define PORT 6008
#define BUFFER_SIZE 2048

std::vector<unsigned long long> hist;

//CPU Affinity
void set_CPU(size_t cpu)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);

    CPU_SET(cpu, &mask);

    // pid = 0 means "calling process"
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1)
    {
        std::cerr << "Error setting CPU affinity: "
                  << std::strerror(errno) << std::endl;
    }
}

// RT Priority
void set_realtime_priority(int priority)
{
    struct sched_param schedParam;
    schedParam.sched_priority = priority;

    // Set the thread to real-time FIFO scheduling
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &schedParam) != 0)
    {
        perror("Failed to set real-time priority");
        exit(EXIT_FAILURE);
    }
}

// User space Timestamp
std::string get_current_time()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::ostringstream oss;
    oss << std::put_time(std::localtime(&now_time), "%d.%m.%Y %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << now_ms.count();
    return oss.str();
}

void disable_nagle(int &sock) {
    int flag = 1;
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
        perror("setsockopt(TCP_NODELAY) failed");
        close(sock);
        return;
    }
}

void enable_timestamping(int &sock) {
    int flags =
        SOF_TIMESTAMPING_TX_HARDWARE |  
        SOF_TIMESTAMPING_RX_HARDWARE |  
        SOF_TIMESTAMPING_SOFTWARE |
        SOF_TIMESTAMPING_TX_SOFTWARE |  
        SOF_TIMESTAMPING_RX_SOFTWARE |
        SOF_TIMESTAMPING_RAW_HARDWARE;

    if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0) {
        perror("setsockopt SO_TIMESTAMPING failed");
        exit(EXIT_FAILURE); // Stop execution if it fails
    }
}


void setup_connection(int &sock) {

    struct sockaddr_in serv_addr, local_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation error");
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "enp0s25", IFNAMSIZ);

    struct hwtstamp_config hwconfig;
    memset(&hwconfig, 0, sizeof(hwconfig));
    hwconfig.tx_type = HWTSTAMP_TX_ON;          // Hardware-TX an
    hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;   // Alle RX-Pakete stempeln

    ifr.ifr_data = (caddr_t)&hwconfig;

    if (ioctl(sock, SIOCSHWTSTAMP, &ifr) < 0) {
        perror("SIOCSHWTSTAMP");
        // Fehlerbehandlung
    }

    // disable_nagle(sock);
    enable_timestamping(sock);

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = 0;
    if (inet_pton(AF_INET, "172.29.3.3", &local_addr.sin_addr) <= 0) {
        perror("Invalid local address");
        return;
    }

    if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind failed");
        return;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0)
    {
        perror("Invalid address/Address not supported");
        return;
    }

    std::cout << "Connecting ..." << std::endl;
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        close(sock);
        return;
    }

    std::cout << "Connected" << std::endl;

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags & O_NONBLOCK) {
        std::cerr << "Warning: Socket is in non-blocking mode." << std::endl;
    }
    else {
        std::cout << "Socket is in blocking mode" << std::endl;
    }

}

void add_to_hist(std::vector<unsigned long long> &vec, int t) {
    hist[t]++;
}

unsigned long long get_timestamp(struct msghdr *msg) {
    
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
            struct timespec *ts = (struct timespec *) CMSG_DATA(cmsg);
            return (unsigned long long)ts[2].tv_sec * 1000000ULL + ts[2].tv_nsec / 1000ULL;
        }
    }
    return 0; // Return 0 if no valid timestamp is found
    
}

void hist_to_csv(std::ofstream *csv_ptr, std::vector<unsigned long long> *vec_ptr) {
    set_CPU(1);
    set_realtime_priority(99);
    while (true) {
        for (int i = 0; i < (*vec_ptr).size(); i++) {
            (*csv_ptr) << (*vec_ptr)[i];
            if (i < (*vec_ptr).size() - 1) (*csv_ptr) << ",";
        }
        (*csv_ptr) << "\n";
        (*csv_ptr).flush();

        std::this_thread::sleep_for(std::chrono::seconds(300));
    }
}

void main_loop() {
    set_CPU(0);

    ssize_t bytes_sent;
    ssize_t bytes_received;

    unsigned long period = 1000; //us

    char state_buffer[BUFFER_SIZE] = R"(<Rob Type="KUKA">
	<Dat TaskType="b">
		<ComStatus>continuous</ComStatus>
		<RIst X="93.9531" Y="-347.9674" Z="1844.9703" A="-126.9460" B="24.9226" C="-28.2871"/>
		<RSol X="93.9542" Y="-347.9674" Z="1844.9702" A="-126.9459" B="24.9224" C="-28.2874"/>
		<AIPos A1="74.8478" A2="-128.7977" A3="75.8236" A4="102.2260" A5="0.0987" A6="-56.5347"/>
		<ASPos A1="74.8478" A2="-128.7977" A3="75.8236" A4="102.2260" A5="0.0983" A6="-56.5347"/>
		<EIPos E1="226966.9326" E2="0.0000" E3="0.0000" E4="0.0000" E5="0.0000" E6="0.0000"/>
		<ESPos E1="226966.9375" E2="0.0000" E3="0.0000" E4="0.0000" E5="0.0000" E6="0.0000"/>
		<MACur A1="0.1143" A2="-1.5825" A3="-0.5625" A4="0.0793" A5="-0.0178" A6="0.0437"/>
		<MECur E1="-0.0005" E2="0.0000" E3="0.0000" E4="0.0000" E5="0.0000" E6="0.0000"/>
		<IPOC>680309708</IPOC>
		<BMode>3</BMode>
		<IPOStat>65</IPOStat>
		<Tech x="1" p6="0.0000" p7="0.0000" p8="0.0000" p6x1="0.0000" p7x1="0.0000" p8x1="0.0000" p6x2="0.0000" p7x2="0.0000" p8x2="0.0000" p6x3="0.0000" p7x3="0.0000" p8x3="0.0000"/>
		<RGH X="0" Y="0" Z="0" A="0" B="0" C="0" T="00000"/>
		<DiI>0</DiI>
		<Tick>0000000000000000</Tick>
		<RWMode>C</RWMode>
	</Dat>
</Rob>
)";

    char command_buffer[BUFFER_SIZE];
    char ccommand_buffer[BUFFER_SIZE];
    struct msghdr msg_hdr{};
    memset(&msg_hdr, 0, sizeof(msg_hdr));

    struct iovec iov[1];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    iov[0].iov_base = command_buffer;
    iov[0].iov_len = sizeof(command_buffer);
    msg_hdr.msg_name = &src_addr;
    msg_hdr.msg_namelen = addr_len;
    msg_hdr.msg_iov = iov;
    msg_hdr.msg_iovlen = 1;
    msg_hdr.msg_control = ccommand_buffer;
    msg_hdr.msg_controllen = sizeof(ccommand_buffer);

    int sock = 0;
    setup_connection(sock);

    set_realtime_priority(99);

    while (true) {
        auto start = std::chrono::high_resolution_clock::now();

        bytes_sent = send(sock, state_buffer, BUFFER_SIZE, 0);
        if (bytes_sent < 0) {
            perror("sendto");
            close(sock);
            return;
        }
        bytes_received = recvmsg(sock, &msg_hdr, MSG_ERRQUEUE);
        if (bytes_received < 0) {
            perror("recvmsg (TX Timestamp)");
            std::cerr << "errno: " << errno << " (" << strerror(errno) << ")" << std::endl;
            close(sock);
            return;
        }
        unsigned long long rt_ts_start = get_timestamp(&msg_hdr);

        bytes_received = recvmsg(sock, &msg_hdr, 0);
        if (bytes_received < 0) {
            perror("recvmsg (RX Timestamp)");
            close(sock);
            return;
        }
        unsigned long long rt_ts_end = get_timestamp(&msg_hdr);

        int rt = rt_ts_end - rt_ts_start;
        add_to_hist(hist, rt);

        auto end = std::chrono::high_resolution_clock::now();
        double loop_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        if (loop_time - period > 0) {
            int sleep_time = loop_time - period;
            std::this_thread::sleep_for(std::chrono::microseconds(sleep_time));
        }
    }

    close(sock);
    return;
}

int main() {
    
    std::ofstream hist_csv("/home/urc/response_times/30_01_3/hist.csv");
    if (!hist_csv.is_open()) {
        std::cerr << "Histogram CSV could not be opened" << std::endl;
    }
    for (int i = 0; i < hist.size(); i++) {
        hist_csv << i;
        if (i < hist.size() - 1) hist_csv << ",";
    }
    hist_csv << "\n";
    hist_csv.flush();

    std::thread main_(main_loop);
    std::thread hist_(hist_to_csv, &hist_csv, &hist);

    main_.join();
    hist_.join();

    return 0;

}