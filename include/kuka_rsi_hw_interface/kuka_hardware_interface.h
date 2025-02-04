
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
 * Author: Lars Tingelstad
 */

#ifndef KUKA_RSI_HARDWARE_INTERFACE_KUKA_HARDWARE_INTERFACE_
#define KUKA_RSI_HARDWARE_INTERFACE_KUKA_HARDWARE_INTERFACE_

// STL
#include <vector>
#include <string>
#include <queue>

// // ROS
// #include <ros/ros.h>
// #include <std_msgs/String.h>
// #include <std_msgs/Float32.h>

// // ros_control
// #include <realtime_tools/realtime_publisher.h>

// Timers
#include <chrono>

// UDP server
#include "SocketServer.h"
// #include <kuka_rsi_hw_interface/udp_server.h>
// #include <kuka_rsi_hw_interface/tcp_server.h>
// #include <sensor_msgs/JointState.h>

// RSI
#include "rsi_state.h"
#include "rsi_command.h"

#include "KukaAxes.h"
#include "AxesMapper.h"
// #include <kuka_rsi_hw_interface/CorrectionCalculator.h>

// Diagnostics
#include "DataLogger.h"

#define ENABLE_FILE_LOGGING

namespace kuka_rsi_hw_interface
{

    class KukaHardwareInterface
    {

    private:
        // std::unique_ptr<realtime_tools::RealtimePublisher<std_msgs::String>> rt_rsi_pub_;

        std::unique_ptr<SocketServer> server_;
        std::string in_buffer_;
        std::string out_buffer_;

        // axes mapping
        int num_internal_axes_;
        int num_external_axes_;
        std::shared_ptr<AxesMapper> mapper_;
        // std::shared_ptr<CorrectionCalculator> correctionCalculator_;

        std::vector<std::string> joint_names_;
        std::vector<double> joint_positions_;
        std::vector<double> joint_setpoint_positions_;
        std::vector<double> joint_velocities_;
        std::vector<double> joint_efforts_;
        std::vector<double> joint_position_command_;
        std::vector<double> joint_velocity_command_;
        std::vector<double> joint_effort_command_;
        KukaAxes correction;
        // ros::Time last_lag_time_;

        std::queue<std::vector<double>> setpoint_queue;
        std::vector<double> last_setpoint;

#ifdef ENABLE_FILE_LOGGING
        std::unique_ptr<Diagnostic::DataLogger<KukaAxes>> outLogger_;
        std::unique_ptr<Diagnostic::DataLogger<KukaAxes>> outCmdLogger_;
        std::unique_ptr<Diagnostic::DataLogger<KukaAxes>> inIstLogger_;
        std::unique_ptr<Diagnostic::DataLogger<KukaAxes>> inSollLogger_;
#endif

        // RSI

        RSICommand rsi_command_;
        unsigned long long ipoc_;

        // ros::Time time_last_packet;

    public:
        // ros::Time read_ts_1;
        // ros::Time read_ts_2;
        // ros::Time read_ts_3;
        // std::chrono::duration<std::chrono::milliseconds> read_ts_1;
        // std::chrono::duration<std::chrono::milliseconds> read_ts_2;
        // std::chrono::duration<std::chrono::milliseconds> read_ts_3;

        RSIState rsi_state_;
        KukaHardwareInterface(const std::vector<std::string> &joint_names, int num_internal_axes, int num_external_axes);

        ~KukaHardwareInterface();

        void start(int timeout, bool non_blocking_read);

        // void configure(SocketServer *socketServer, AxesMapper *axesMapper, CorrectionCalculator *calculator,
        //                realtime_tools::RealtimePublisher<std_msgs::String> *realtime_publisher);

        std::vector<double> fetchNextSetpointFromQueue();

        void populateSetpointQueue(int queue_size);

        int read(int timeout_ms, bool non_blocking_read);

        bool write();

        int getQueueSize();

        void removeFromQueue(int n);

        bool write_no_correction();

        // void getJointStateMessage(sensor_msgs::JointState &joint_state_msg) const;

        int getNumInternalAxes() const;

        int getNumExternalAxes() const;

        // void updateSetpoint(const sensor_msgs::JointState state);

        void configureFileLogging(Diagnostic::DataLogger<KukaAxes> *inIst,
                                  Diagnostic::DataLogger<KukaAxes> *inSoll,
                                  Diagnostic::DataLogger<KukaAxes> *out,
                                  Diagnostic::DataLogger<KukaAxes> *outCmd);

        // functions used to perform direct trajectories
        void updateSetpointFromFiles(const std::vector<std::string> &joint_commands_files, const std::vector<std::string> &timestamps_files);
        void loadAllFiles(const std::vector<std::string> &joint_commands_files, const std::vector<std::string> &timestamps_files);
        void loadFiles(const std::string &joint_commands_file, const std::string &timestamps_file, std::vector<std::vector<double>> &joint_commands, std::vector<double> &timestamps);

    private:
        void logOutMessages(const KukaAxes &target, const KukaAxes &correction) const;

        void logInMessages(const KukaAxes &setpoint, const KukaAxes &actual) const;
    };

} // namespace kuka_rsi_hw_interface
#endif

// Overload the << operator for std::vector<double>
std::ostream &operator<<(std::ostream &os, const std::vector<double> &vec)
{
    os << "[";
    for (size_t i = 0; i < vec.size(); ++i)
    {
        os << vec[i];
        if (i < vec.size() - 1)
        {
            os << ", ";
        }
    }
    os << "]";
    return os;
}