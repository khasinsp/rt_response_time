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
 *   * Neither the name of the Univ of CO, Boulder nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
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
 * Author: Lars Tingelstad <lars.tingelstad@ntnu.no>
*/

#ifndef KUKA_RSI_HW_INTERFACE_RSI_STATE_
#define KUKA_RSI_HW_INTERFACE_RSI_STATE_

#include <string>
#include <vector>
#include <tinyxml.h>
#include "KukaAxes.h"

namespace kuka_rsi_hw_interface {

    class RSIState {

    private:
        std::string xml_doc_;

    public:
        RSIState() :
                cart_position(6, 0.0),
                initial_cart_position(6, 0.0) {
            xml_doc_.resize(1024);
        }

        RSIState(std::string xml_doc);

        // AIPOS
        KukaAxes positions;
        KukaAxes setpoint_positions;
        // RIst
        std::vector<double> cart_position;
        // RSol
        std::vector<double> initial_cart_position;
        // IPOC
        unsigned long long ipoc;
        std::string com_status;

    };

    RSIState::RSIState(std::string xml_doc) :
            xml_doc_(xml_doc),
            cart_position(6, 0.0),
            initial_cart_position(6, 0.0) {
        // Parse message from robot
        TiXmlDocument bufferdoc;
        bufferdoc.Parse(xml_doc_.c_str());
        // Get the Rob node:
        TiXmlElement *rob = bufferdoc.FirstChildElement("Rob");
        // get the Dat node:
        TiXmlElement *dat = rob->FirstChildElement("Dat");

        TiXmlElement *comStatus = dat->FirstChildElement("ComStatus");
        com_status = comStatus->GetText();

        // Extract axis specific actual position
        TiXmlElement *AIPos_el = dat->FirstChildElement("AIPos");
        AIPos_el->Attribute("A1", &positions.getInternalAxes()[0]);
        AIPos_el->Attribute("A2", &positions.getInternalAxes()[1]);
        AIPos_el->Attribute("A3", &positions.getInternalAxes()[2]);
        AIPos_el->Attribute("A4", &positions.getInternalAxes()[3]);
        AIPos_el->Attribute("A5", &positions.getInternalAxes()[4]);
        AIPos_el->Attribute("A6", &positions.getInternalAxes()[5]);

        // Extract axis specific setpoint position
        TiXmlElement *ASPos_el = dat->FirstChildElement("ASPos");
        ASPos_el->Attribute("A1", &setpoint_positions.getInternalAxes()[0]);
        ASPos_el->Attribute("A2", &setpoint_positions.getInternalAxes()[1]);
        ASPos_el->Attribute("A3", &setpoint_positions.getInternalAxes()[2]);
        ASPos_el->Attribute("A4", &setpoint_positions.getInternalAxes()[3]);
        ASPos_el->Attribute("A5", &setpoint_positions.getInternalAxes()[4]);
        ASPos_el->Attribute("A6", &setpoint_positions.getInternalAxes()[5]);

        // Extract external axis specific actual position
        TiXmlElement *EIPos_el = dat->FirstChildElement("EIPos");
        EIPos_el->Attribute("E1", &positions.getExternalAxes()[0]);
        EIPos_el->Attribute("E2", &positions.getExternalAxes()[1]);
        EIPos_el->Attribute("E3", &positions.getExternalAxes()[2]);
        EIPos_el->Attribute("E4", &positions.getExternalAxes()[3]);
        EIPos_el->Attribute("E5", &positions.getExternalAxes()[4]);
        EIPos_el->Attribute("E6", &positions.getExternalAxes()[5]);

        // Extract external axis specific setpoint position
        TiXmlElement *ESPos_el = dat->FirstChildElement("ESPos");
        ESPos_el->Attribute("E1", &setpoint_positions.getExternalAxes()[0]);
        ESPos_el->Attribute("E2", &setpoint_positions.getExternalAxes()[1]);
        ESPos_el->Attribute("E3", &setpoint_positions.getExternalAxes()[2]);
        ESPos_el->Attribute("E4", &setpoint_positions.getExternalAxes()[3]);
        ESPos_el->Attribute("E5", &setpoint_positions.getExternalAxes()[4]);
        ESPos_el->Attribute("E6", &setpoint_positions.getExternalAxes()[5]);

        // Extract cartesian actual position
        TiXmlElement *RIst_el = dat->FirstChildElement("RIst");
        RIst_el->Attribute("X", &cart_position[0]);
        RIst_el->Attribute("Y", &cart_position[1]);
        RIst_el->Attribute("Z", &cart_position[2]);
        RIst_el->Attribute("A", &cart_position[3]);
        RIst_el->Attribute("B", &cart_position[4]);
        RIst_el->Attribute("C", &cart_position[5]);

        // Extract cartesian actual position
        TiXmlElement *RSol_el = dat->FirstChildElement("RSol");
        RSol_el->Attribute("X", &initial_cart_position[0]);
        RSol_el->Attribute("Y", &initial_cart_position[1]);
        RSol_el->Attribute("Z", &initial_cart_position[2]);
        RSol_el->Attribute("A", &initial_cart_position[3]);
        RSol_el->Attribute("B", &initial_cart_position[4]);
        RSol_el->Attribute("C", &initial_cart_position[5]);

        // Get the IPOC timestamp
        TiXmlElement *ipoc_el = dat->FirstChildElement("IPOC");
        ipoc = std::stoull(ipoc_el->FirstChild()->Value());
    }

} // namespace kuka_rsi_hw_interface

#endif
