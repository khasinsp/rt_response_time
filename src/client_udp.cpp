#include <bits/stdc++.h>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "../include/kuka_rsi_hw_interface/AxesMapper.h"
#include "../include/kuka_rsi_hw_interface/rsi_command.h"
#include "../include/kuka_rsi_hw_interface/tcp_server.h"


#define SERVER_IP "172.29.3.25" // The IP address of the server (VM)
#define PORT 6008
#define BUFFER_SIZE 2048
#define RUNTIME 1000
#define RT_THRESHOLD RUNTIME/2
#define PRINT_THRESHOLD RUNTIME
#define DELTA_T_THRESHOLD 40

std::vector<unsigned long long> hist(RUNTIME, 0);
std::vector<unsigned long long> delta_t_hist(1000, 0);

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

void sigxcpu_handler(int signum) {
    // Use thread-local storage or other mechanisms to identify the thread
    // For example, using pthread_self()
    std::cerr << "Runtime overrun detected: Task exceeded allocated runtime" << std::endl;
}

void setup_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = sigxcpu_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGXCPU, &sa, NULL) != 0) {
        perror("Failed to set SIGXCPU handler");
        exit(EXIT_FAILURE);
    }
}

struct sched_attr {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
};

void set_realtime_deadline(unsigned long runtime, unsigned long deadline, unsigned long period)
{
    struct sched_attr attr;
    int ret;

    // Zero out the structure
    memset(&attr, 0, sizeof(attr));

    // Set the scheduling policy to SCHED_DEADLINE
    attr.size = sizeof(attr);
    attr.sched_policy = SCHED_DEADLINE;
    attr.sched_runtime = runtime;
    attr.sched_deadline = deadline;
    attr.sched_period = period;

    // Enable Overrun detection
    attr.sched_flags |= SCHED_FLAG_DL_OVERRUN;

    // Use syscall to set the scheduling policy and parameters
    ret = syscall(SYS_sched_setattr, gettid(), &attr, 0);
    if (ret != 0)
    {
        perror("Failed to set SCHED_DEADLINE");
        exit(EXIT_FAILURE);
    }
}

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

void setup_connection(int &sock) {

    struct sockaddr_in serv_addr, local_addr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Socket creation error");
        return;
    }

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = 0;
    if (inet_pton(AF_INET, "172.29.3.28", &local_addr.sin_addr) <= 0) {
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

    std::cout << "Waiting for Connection... " << std::endl;

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        if (errno == EINPROGRESS) {
            std::cout << "Connection in progress (non-blocking)..." << std::endl;

            // 6) Use select() to wait until the socket is writable or until timeout
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);

            // Set a timeout (e.g., 5 seconds)
            struct timeval tv;
            tv.tv_sec = 5;
            tv.tv_usec = 0;

            int ret = select(sock + 1, nullptr, &writefds, nullptr, &tv);
            if (ret < 0) {
                perror("select() error");
                close(sock);
                return;
            }
            else if (ret == 0) {
                // Timeout
                std::cerr << "Connection timed out" << std::endl;
                close(sock);
                return;
            }
            else {
                // 7) Check if the socket is actually writable
                if (FD_ISSET(sock, &writefds)) {
                    // 8) Check the socket for errors
                    int err = 0;
                    socklen_t len = sizeof(err);
                    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
                        perror("getsockopt(SO_ERROR) failed");
                        close(sock);
                        return;
                    }

                    if (err != 0) {
                        // connect() error
                        std::cerr << "Connection failed: " << strerror(err) << std::endl;
                        close(sock);
                        return;
                    }
                    // If err == 0, connection succeeded
                    std::cout << "Connection established (after waiting)!" << std::endl;
                }
            }
        }
        else {
            // Some other error
            perror("connect() failed immediately");
            close(sock);
            return;
        }
    }
    else {
        // connect() succeeded immediately (rare in non-blocking mode, but can happen)
        std::cout << "Connected immediately!" << std::endl;
    }

}


void hist_to_csv(std::ofstream* csv_ptr, std::vector<unsigned long long> *vec_ptr) {

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


void add_to_hist(std::vector<unsigned long long> &vec, double t, double res) {
    int idx = t / res;
    if (idx >= 0 && idx < vec.size()) vec[idx]++;
}


bool check_command(std::string str) {
    if (str.size() < 10) return false;

    return (str.compare(str.size() - 6, 6, "</Sen>") == 0 && str.compare(0, 4, "<Sen") == 0);
}

void main_loop() {

    set_CPU(0);

    std::chrono::high_resolution_clock::time_point rt_ts_start;
    std::chrono::high_resolution_clock::time_point rt_ts_end;
    double rt;

    std::vector<std::chrono::high_resolution_clock::time_point> recv_ts_start(2);
    std::chrono::high_resolution_clock::time_point recv_ts_end;
    double delta_t;
    bool measure_again;
    bool log_rt;

    ssize_t bytes_received;

    std::string buffer = "";

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

    char in_buffer[BUFFER_SIZE];

    int sock = 0;
    setup_connection(sock);

    unsigned long runtime =   RUNTIME * 1000;     // ns
    unsigned long deadline =  RUNTIME * 1000;
    unsigned long period =    RUNTIME * 1000;

    setup_signal_handler();
    set_realtime_deadline(runtime, deadline, period);

    while (true) {

        measure_again = true;
        log_rt = true;

        // auto start_loop = std::chrono::high_resolution_clock::now();

        // std::thread recv_nonBlocking(receive_nb, sock);
        // std::cout << "Sending..." << std::endl;
        ssize_t bytes_sent = send(sock, state_buffer, BUFFER_SIZE, 0);
        if (bytes_sent <= 0) {
            perror("Error sending data");
            close(sock);
            return;
        }

        rt_ts_start = std::chrono::high_resolution_clock::now();

        unsigned long long i = 0;
        // std::cout << "Receiving ..." << std::endl;
        while (!check_command(buffer)) {
            memset(in_buffer, 0, BUFFER_SIZE);
            bytes_received = recv(sock, in_buffer, BUFFER_SIZE, MSG_DONTWAIT);
            if (bytes_received < 0 && measure_again) {
                recv_ts_start[i % 2] = std::chrono::high_resolution_clock::now();
            }
            if (bytes_received > 0) {
                buffer = buffer + in_buffer;
                if (measure_again) recv_ts_end = std::chrono::high_resolution_clock::now();
                measure_again = false;
            }
            else if (bytes_received == 0) {
                perror("Error receiving data");
                close(sock);
                return;
            }
            if (!measure_again) {
                delta_t = std::chrono::duration_cast<std::chrono::microseconds>(recv_ts_end - recv_ts_start[(i % 2)]).count();
            }
            i++;
        }

        buffer = "";

        rt_ts_end = std::chrono::high_resolution_clock::now();
        rt = std::chrono::duration_cast<std::chrono::microseconds>(rt_ts_end - rt_ts_start).count();

        if (rt > RT_THRESHOLD) std::cout << "RTT," << get_current_time() << "," << rt << "," << delta_t  << std::endl;
        if (delta_t > DELTA_T_THRESHOLD) {
            std::cout << "DET," << get_current_time() << "," << rt << "," << delta_t << std::endl;
            log_rt = false;
        }
        if (rt > PRINT_THRESHOLD || delta_t > 1000) std::cout << "OUT," << get_current_time() << "," << rt << "," << delta_t << std::endl;

        if (log_rt) add_to_hist(hist, rt, 1.0);
        add_to_hist(delta_t_hist, delta_t, 1.0);

        sched_yield();

    }

    close(sock);
    return;
}




int main() {

    // RTT
    std::ofstream hist_csv("/home/urc/response_times/PCI_tests/11_03_1/hist.csv");
    if (!hist_csv.is_open()) {
        std::cerr << "Histogram CSV could not be opened" << std::endl;
    }
    for (int i = 0; i < hist.size(); i++) {
        hist_csv << i;
        if (i < hist.size() - 1) hist_csv << ",";
    }
    hist_csv << "\n";
    hist_csv.flush();

    // Delta T
    std::ofstream delta_csv("/home/urc/response_times/PCI_tests/11_03_1/delta.csv");
    if (!delta_csv.is_open()) {
        std::cerr << "Delta histogram CSV could not be opened" << std::endl;
    }
    for (int i = 0; i < delta_t_hist.size(); i++) {
        delta_csv << i;
        if (i < delta_t_hist.size() - 1) delta_csv << ",";
    }
    delta_csv << "\n";
    delta_csv.flush();

    std::thread main_(main_loop);
    std::thread hist_1(hist_to_csv, &hist_csv, &hist);
    std::thread hist_2(hist_to_csv, &delta_csv, &delta_t_hist);

    main_.join();
    hist_1.join();
    hist_2.join();

    return 0;

}