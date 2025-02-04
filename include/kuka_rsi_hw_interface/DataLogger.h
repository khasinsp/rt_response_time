//
// Created by muellerm on 02.11.16.
//

#ifndef KUKA_RSI_HW_INTERFACE_DATALOGGER_H
#define KUKA_RSI_HW_INTERFACE_DATALOGGER_H

#include <iostream>
#include <fstream>

#include "KukaAxes.h"

#define SSTR(x) static_cast< std::ostringstream & >( \
        ( std::ostringstream() << std::dec << x ) ).str()

//#define DISABLE_LOGGING

namespace Diagnostic {

    template<class T>
    class DataFormatter {
    public:
        virtual std::string format(const T &obj) = 0;
    };


    class KukaAxesFormatter : public DataFormatter<kuka_rsi_hw_interface::KukaAxes> {
    public:
        virtual std::string format(const kuka_rsi_hw_interface::KukaAxes &obj) {
            std::stringstream s;
            const std::vector<double> &internalAxes = obj.getInternalAxes();
            for (int i = 0; i < internalAxes.size(); ++i) {
                s << std::fixed << std::setw(11) << std::setprecision(6) << internalAxes[i] << "\t";
            }
            const std::vector<double> &externalAxes = obj.getExternalAxes();
            for (int i = 0; i < 1; ++i) {
                s << std::fixed << std::setw(11) << std::setprecision(6) << externalAxes[i] << "\t";
            }
            return s.str();
        }
    };

    template<class T>
    class DataLogger {
    public:
        DataLogger(std::string filename, std::shared_ptr<DataFormatter<T>> formatter) {
#ifndef DISABLE_LOGGING
            formatter_ = formatter;
            file_.open(filename, std::ios::out | std::ios::trunc);
            if (!file_.is_open()) {
                std::cerr << "Failed to open file '" << filename << "'" << std::endl;
            }
#endif
        }

        void log(T obj) {
            log(formatter_->format(obj));
        }

        void log(std::string prefix, T obj) {
            log(prefix, formatter_->format(obj));
        }

        void log(std::string str) {
            log("", str);
        }

        void log(std::string prefix, std::string str) {
#ifndef DISABLE_LOGGING
            std::string p = prefix.empty() ? "" : "{" + prefix + "}\t";
            file_ << timestamp<std::chrono::nanoseconds>() << "\t" << p << str << std::endl;
#endif
        }


        template <typename RESOLUTION>
        long timestamp() {
            return std::chrono::duration_cast<RESOLUTION>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
        }


    private:
        std::shared_ptr<DataFormatter<T>> formatter_;
        std::ofstream file_;
    };
}

#endif //KUKA_RSI_HW_INTERFACE_DATALOGGER_H
