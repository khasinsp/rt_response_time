#include <iostream>
#include <thread>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <fcntl.h>
#include <bits/stdc++.h>

#include "../include/kuka_rsi_hw_interface/tcp_server.h"
#include "../include/kuka_rsi_hw_interface/AxesMapper.h"
#include "../include/kuka_rsi_hw_interface/kuka_hardware_interface.h"
#include "../include/kuka_rsi_hw_interface/KukaAxes.h"
#include "../include/kuka_rsi_hw_interface/rsi_state.h"

#include <sensor_msgs/JointState.h>
#include <std_msgs/Bool.h>
#include <std_msgs/String.h>
#include <std_msgs/Float32.h>
#include <ros/ros.h>

// RSI
#include <kuka_rsi_hw_interface/rsi_state.h>

#define SERVER_IP "127.0.0.1"
#define PORT 6009
#define BUFFER_SIZE 2048

#define PRINT_TIME 10 * 60 // seconds

// Function to set thread priority and policy
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

void init_sock(int &sock) {

    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation error");
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0)
    {
        perror("Invalid address/Address not supported");
        return;
    }

    std::cout << "Waiting for Connection... " << std::endl;

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Connection failed");
        return;
    }

    std::cout << "Connected!" << std::endl;
}

std::string command_noCorrection(unsigned long long ipoc) {
    kuka_rsi_hw_interface::KukaAxes axes = kuka_rsi_hw_interface::KukaAxes();

    for (int i = 0; i < kuka_rsi_hw_interface::KukaAxes::MAX_INTERNAL_AXES; ++i)
    {
        axes.getInternalAxes()[i] = 0;
    }
    for (int i = 0; i < kuka_rsi_hw_interface::KukaAxes::MAX_EXTERNAL_AXES; ++i)
    {
        axes.getExternalAxes()[i] = 0;
    }

    kuka_rsi_hw_interface::RSICommand rsi_command = kuka_rsi_hw_interface::RSICommand(axes, ipoc);

    std::string out_buffer = rsi_command.xml_doc;

    return out_buffer;

}

class CommandHandler {
    private:
    ros::Subscriber robot_cmd_sub;
    ros::NodeHandle nh;
    kuka_rsi_hw_interface::KukaHardwareInterface* kuka_rsi_hw_interface;

    public:
    CommandHandler(ros::NodeHandle node_handle) {
        nh = node_handle;
        kuka_rsi_hw_interface = nullptr;
        robot_cmd_sub = nh.subscribe<sensor_msgs::JointState>("/robot/command", 1000, &CommandHandler::robot_cmd_callback, this);
        packet_loss_ack_sub = nh.subscribe<std_msgs::Bool>("/packet_loss_ack", 1000, &CommandHandler::packet_loss_ack_callback, this);
        joint_states_pub = nh.advertise<sensor_msgs::JointState>("/joint_states", 10); // short queue to avoid delay in joint state the client receives
        packet_loss_event_pub = nh.advertise<std_msgs::String>("/packet_loss_hardware_interface", 1000);
        seconds_since_timeout_pub = nh.advertise<std_msgs::Float32>("/URC/seconds_since_timeout", 1000);
    }

    ros::Subscriber packet_loss_ack_sub;
    ros::Publisher packet_loss_event_pub;
    ros::Publisher joint_states_pub;
    ros::Publisher seconds_since_timeout_pub;
    sensor_msgs::JointState message = sensor_msgs::JointState();
    bool initialized = false;
    bool packet_loss = false;
    bool packet_loss_ack = false;
    int cmd_count = 0;

    void setKukaRsiHwInterface(kuka_rsi_hw_interface::KukaHardwareInterface& hw_interface) {
        kuka_rsi_hw_interface = &hw_interface;
    }

    //Acknowledge that sample took care of the packet loss
    void packet_loss_ack_callback(const std_msgs::Bool::ConstPtr& msg) {
        ROS_INFO_STREAM(msg->data);
        if (msg->data) {
            ROS_INFO_STREAM("Packet loss Event acknowledge");
            // Handle acknowledgment (e.g., log, update state, etc.)
            packet_loss_ack = true;
        }
    }
    
    // Switch sampler to hold state when packet loss
    void publish_packet_loss_event(std::string string_cmd) {
        std_msgs::String event_msg;
        event_msg.data = string_cmd;
        packet_loss_event_pub.publish(event_msg);
        ROS_INFO_STREAM("published_zab");
    }

    // publish seconds since timeout
    void publish_seconds_since_timeout(float seconds_cmd) {
        std_msgs::Float32 event_msg;
        event_msg.data = seconds_cmd;
        seconds_since_timeout_pub.publish(event_msg);
    }


    void robot_cmd_callback(const sensor_msgs::JointState::ConstPtr& msg) {
        if ( (!msg->name.empty() || !msg->position.empty()) && (kuka_rsi_hw_interface != nullptr) ) {
            message = *msg;
            kuka_rsi_hw_interface->updateSetpoint(message);
            initialized = true;
            cmd_count++;
        }
    }
};

void set_CPU(size_t cpu1)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);

    CPU_SET(cpu1, &mask);

    // pid = 0 means "calling process"
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1)
    {
        std::cerr << "Error setting CPU affinity: "
                  << std::strerror(errno) << std::endl;
    }
}

bool check_state(std::string str) {
    if (str.size() < 4) return false;

    return (str.compare(0, 4, "<Rob") == 0);
}

int main(int argc, char **argv)
{

    set_realtime_priority(99);
    set_CPU(1);

    ros::init(argc, argv, "kuka_rsi_hardware_interface");

    if (argc < 3) {
        std::string error_msg = "Args missing, usage: kuka_hardware_interface_node num_internal_axes num_external_axes";
        ROS_ERROR_STREAM(error_msg);
        throw std::runtime_error(error_msg);
    }

    ros::AsyncSpinner spinner(1);
    spinner.start();

    ros::NodeHandle nh;
    std::vector<std::string> joint_names = {"joint_a1", "joint_a2", "joint_a3", "joint_a4", "joint_a5", "joint_a6", "joint_e1"};

    CommandHandler cmd_handler(nh);

    // if (!nh.getParam("controller_joint_names", joint_names)) {
    //     ROS_ERROR("Cannot find required parameter 'controller_joint_names' on the parameter server.");
    //     throw std::runtime_error("Cannot find required parameter 'controller_joint_names' on the parameter server.");
    // } else {
        std::stringstream names;
        names << "[ ";
        for (int i = 0; i < joint_names.size(); ++i) {
            names << joint_names[i] << " ";
        }
        names << "]";
        ROS_INFO_STREAM_NAMED("hardware_interface", "Found Joints " << names.str());
    // }

    // kuka_rsi_hw_interface::KukaHardwareInterface kuka_rsi_hw_interface(
    //     joint_names, std::stoi(argv[1]), std::stoi(argv[2])
    // );

    kuka_rsi_hw_interface::AxesMapper *mapper =
        new kuka_rsi_hw_interface::AxesMapper(6, 1);

    // kuka_rsi_hw_interface.configure(socketServer, axesMapper, correctionCalculator, realtimePublisher);

    int sock = 0;
    init_sock(sock);

    std::string buffer_str;
    char in_buffer[BUFFER_SIZE];

    int state;
    int prev_state = 1;
    int read_state;

    while (true)
    {

        // Receive response
        ssize_t bytes_received = recv(sock, in_buffer, BUFFER_SIZE, 0);

        buffer_str = std::string(in_buffer);

        if (!check_state(buffer_str)) {
            std::cout << "State Check failed ... Continuing" << std::endl;
            // std::cout << "Received State: \n" << buffer_str << std::endl;
            continue;
        }

        auto state = kuka_rsi_hw_interface::RSIState(buffer_str);

        sensor_msgs::JointState joint_state_msg;

        std::vector<double> joint_positions(7, 0.0);
        std::vector<double> joint_setpoint_positions(7, 0.0);
        std::vector<double> joint_velocities(7, 0.0);
        std::vector<double> joint_effort(7, 0.0);

        unsigned long long ipoc = state.ipoc;

        joint_state_msg.header.stamp = ros::Time::now();
        joint_state_msg.name = joint_names;
        mapper->copyToJointPositions(state.positions, joint_positions);
        mapper->copyToJointPositions(state.setpoint_positions, joint_setpoint_positions);
        joint_state_msg.position = joint_positions;
        joint_state_msg.velocity = joint_velocities;
        joint_state_msg.effort = joint_effort;
        cmd_handler.joint_states_pub.publish(joint_state_msg);

        if (joint_positions[0] < 1.0) {
            std::cout << "Got Wrong Joint State: \n" << buffer_str << std::endl;
        }

        char buffer[BUFFER_SIZE] = "Hello from Client!";
        // buffer_str = command_noCorrection();
        // for (auto i = 0; i < buffer_str.size(); ++i) {
        //     buffer[i] = buffer_str[i];
        // }
        ssize_t bytes_sent = send(sock, buffer, strlen(buffer), 0);
        if (bytes_sent <= 0)
        {
            perror("Error sending data");
            close(sock);
            return -1;
        }

    }

    spinner.stop();
    close(sock);
    return 0;
}
