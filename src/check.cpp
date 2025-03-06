#include <bits/stdc++.h>

#include "../include/kuka_rsi_hw_interface/KukaAxes.h"
#include "../include/kuka_rsi_hw_interface/rsi_command.h"

std::string write_noCorrection()
{

    kuka_rsi_hw_interface::KukaAxes axes = kuka_rsi_hw_interface::KukaAxes();

    for (int i = 0; i < kuka_rsi_hw_interface::KukaAxes::MAX_INTERNAL_AXES; ++i)
    {
        axes.getInternalAxes()[i] = 0;
    }
    for (int i = 0; i < kuka_rsi_hw_interface::KukaAxes::MAX_EXTERNAL_AXES; ++i)
    {
        axes.getExternalAxes()[i] = 0;
    }

    kuka_rsi_hw_interface::RSICommand rsi_command = kuka_rsi_hw_interface::RSICommand(axes, 123456789101112);

    std::string out_buffer = rsi_command.xml_doc;

    return out_buffer;
}


int main() {
    
    std::string state_buffer = write_noCorrection();

    std::cout << sizeof(state_buffer[0]) * state_buffer.size() << std::endl;

}