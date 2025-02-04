//
// Created by muellerm on 01.11.16.
//

#ifndef KUKA_RSI_HW_INTERFACE_KUKAAXES_H
#define KUKA_RSI_HW_INTERFACE_KUKAAXES_H

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

namespace kuka_rsi_hw_interface {

    class KukaAxes {
    public:
        static const int MAX_INTERNAL_AXES = 6;
        static const int MAX_EXTERNAL_AXES = 6;

        KukaAxes() : internal_axes_(MAX_INTERNAL_AXES, 0.0), external_axes_(MAX_EXTERNAL_AXES, 0.0) {}

        KukaAxes(const std::vector<double> &internal, const std::vector<double> &external)
                : internal_axes_(MAX_INTERNAL_AXES, 0.0), external_axes_(MAX_EXTERNAL_AXES, 0.0) {
            setAxes(internal, external);
        }

        void setAxes(const std::vector<double> &internal_axes, const std::vector<double> &external_axes) {
            for (int i = 0; i < internal_axes.size(); ++i) {
                internal_axes_[i] = internal_axes[i];
            }
            for (int i = 0; i < external_axes.size(); ++i) {
                external_axes_[i] = external_axes[i];
            }
        }

        const std::vector<double> &getInternalAxes() const {
            return internal_axes_;
        }

        const std::vector<double> &getExternalAxes() const {
            return external_axes_;
        }

        std::vector<double> &getInternalAxes() {
            return internal_axes_;
        }

        std::vector<double> &getExternalAxes() {
            return external_axes_;
        }

        KukaAxes add(const KukaAxes & other) const {
            KukaAxes result;
            for (int i = 0; i < MAX_INTERNAL_AXES; ++i) {
                result.internal_axes_[i] = this->internal_axes_[i] + other.internal_axes_[i];
            }
            for (int i = 0; i < MAX_EXTERNAL_AXES; ++i) {
                result.external_axes_[i] = this->external_axes_[i] + other.external_axes_[i];
            }
            return result;
        }

        KukaAxes subtract(const KukaAxes & other) const {
            KukaAxes result;
            for (int i = 0; i < MAX_INTERNAL_AXES; ++i) {
                result.internal_axes_[i] = this->internal_axes_[i] - other.internal_axes_[i];
            }
            for (int i = 0; i < MAX_EXTERNAL_AXES; ++i) {
                result.external_axes_[i] = this->external_axes_[i] - other.external_axes_[i];
            }
            return result;
        }

        void scale(const double factor) {
            for (int i = 0; i < MAX_INTERNAL_AXES; ++i) {
                internal_axes_[i] = this->internal_axes_[i] * factor;
            }
            for (int i = 0; i < MAX_EXTERNAL_AXES; ++i) {
                external_axes_[i] = this->external_axes_[i] * factor;
            }
        }

        std::string toString() const {
            std::stringstream s;
            s << "[ ";
            for (int i = 0; i < MAX_INTERNAL_AXES; ++i) {
                s << std::fixed << std::setw(11) << std::setprecision(6) << internal_axes_[i] << " ";
            }
            s << "] [ ";
            for (int i = 0; i < MAX_EXTERNAL_AXES; ++i) {
                s << std::fixed << std::setw(11)<< std::setprecision(6) << external_axes_[i] << " ";
            }
            s << "]";
            return s.str();
        }

    private:
        std::vector<double> internal_axes_;
        std::vector<double> external_axes_;
    };

}

#endif //KUKA_RSI_HW_INTERFACE_KUKAAXES_H
