//
// Created by muellerm on 31.10.16.
//

#ifndef KUKA_RSI_HW_INTERFACE_AXESMAPPER_H
#define KUKA_RSI_HW_INTERFACE_AXESMAPPER_H

#include "KukaAxes.h"

#include <vector>
#include <stdio.h>
#include <memory> // for shared_ptr

#include <assert.h>

namespace kuka_rsi_hw_interface {


    class KukaToJointValueConverter {
    private:
        // conversion for internal rotational joints
        static constexpr double RAD2DEG = 57.295779513082323;
        static constexpr double DEG2RAD = 0.017453292519943295;
        // conversion  for external prismatic joints
        static constexpr double DEGMM2METER = DEG2RAD / 1000;
        static constexpr double METER2DEGMM = RAD2DEG * 1000;

    public:
        virtual double convertFromInternal(double v) const {
            return v * DEG2RAD;
        }

        virtual double convertFromExternal(double v) const {
            return v * DEGMM2METER;
        }

        virtual double convertToInternal(double v) const {
            return v * RAD2DEG;
        }

        virtual double convertToExternal(double v) const {
            return v * METER2DEGMM;
        }

    };

    class AxesMapper {
    public:
        AxesMapper(int n_internal, int n_external) : num_internal_axes_(n_internal), num_external_axes_(n_external) {
            converter.reset(new KukaToJointValueConverter());
        }

        int getNumberOfInternalAxes() const { return num_internal_axes_; }

        int getNumberOfExternalAxes() const { return num_external_axes_; }

        void copyToJointPositions(KukaAxes axes, std::vector<double> &joint_values) const {
            assert(joint_values.size() == num_internal_axes_ + num_external_axes_);

            int n_internal_axes = getNumberOfInternalAxes();
            int n_external_axes = getNumberOfExternalAxes();
            int n_joints = n_internal_axes + n_external_axes;

            for (int i = 0; i < n_internal_axes; ++i) {
                joint_values[i] = converter->convertFromInternal(axes.getInternalAxes()[i]);
            }

            for (int j = 0; j < n_external_axes; ++j) {
                joint_values[j + n_internal_axes] = converter->convertFromExternal(axes.getExternalAxes()[j]);
            }
        }

        KukaAxes convertFromJointValues(std::vector<double> joint_values) const {
            KukaAxes axes;
            for (int i = 0; i < num_internal_axes_; ++i) {
                axes.getInternalAxes()[i] = converter->convertToInternal(joint_values[i]);
            }
            for (int j = 0; j < num_external_axes_; ++j) {
                axes.getExternalAxes()[j] = converter->convertToExternal(joint_values[num_internal_axes_ + j]);
            }
            return axes;
        }

    private:
        std::shared_ptr<KukaToJointValueConverter> converter;
        int num_internal_axes_;
        int num_external_axes_;
    };

}
#endif //KUKA_RSI_HW_INTERFACE_KUKAAXES_H
