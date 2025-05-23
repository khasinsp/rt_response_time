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

#ifndef KUKA_RSI_HW_INTERFACE_RSI_COMMAND_
#define KUKA_RSI_HW_INTERFACE_RSI_COMMAND_

#include "KukaAxes.h"

#include <tinyxml.h>
#include <vector>


namespace kuka_rsi_hw_interface {

    class RSICommand {
    public:
        RSICommand();

        RSICommand(const KukaAxes& corrections, unsigned long long ipoc);

        std::string xml_doc;
    };

    RSICommand::RSICommand() {
        // Intentionally empty
    }

    RSICommand::RSICommand(const KukaAxes& axes, unsigned long long ipoc) {
        TiXmlDocument doc;
        TiXmlElement *root = new TiXmlElement("Sen");
        root->SetAttribute("Type", "CoRob");
        root->SetAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
        root->SetAttribute("xsi:noNamespaceSchemaLocation", "ExternalData.xsd");

        TiXmlElement *dat = new TiXmlElement("Dat");
        dat->SetAttribute("TaskType", "b");
        root->LinkEndChild(dat);

        TiXmlElement *estr = new TiXmlElement("EStr");
        estr->LinkEndChild(new TiXmlText("Info: RSI activated!"));
        dat->LinkEndChild(estr);

        // relative correction
        TiXmlElement *rkorr = new TiXmlElement("RKorr");
        // Add string attribute
        rkorr->SetAttribute("X", std::to_string(0.0));
        rkorr->SetAttribute("Y", std::to_string(0.0));
        rkorr->SetAttribute("Z", std::to_string(0.0));
        rkorr->SetAttribute("A", std::to_string(0.0));
        rkorr->SetAttribute("B", std::to_string(0.0));
        rkorr->SetAttribute("C", std::to_string(0.0));
        dat->LinkEndChild(rkorr);

        // axis correction
        TiXmlElement *el = new TiXmlElement("AKorr");
        // Add string attribute
        el->SetAttribute("A1", std::to_string(axes.getInternalAxes()[0]));
        el->SetAttribute("A2", std::to_string(axes.getInternalAxes()[1]));
        el->SetAttribute("A3", std::to_string(axes.getInternalAxes()[2]));
        el->SetAttribute("A4", std::to_string(axes.getInternalAxes()[3]));
        el->SetAttribute("A5", std::to_string(axes.getInternalAxes()[4]));
        el->SetAttribute("A6", std::to_string(axes.getInternalAxes()[5]));
        dat->LinkEndChild(el);

        // external axis correction
        TiXmlElement *ekorr = new TiXmlElement("EKorr");
        // Add string attribute
        ekorr->SetAttribute("E1", std::to_string(axes.getExternalAxes()[0]));
        ekorr->SetAttribute("E2", std::to_string(axes.getExternalAxes()[1]));
        ekorr->SetAttribute("E3", std::to_string(axes.getExternalAxes()[2]));
        ekorr->SetAttribute("E4", std::to_string(axes.getExternalAxes()[3]));
        ekorr->SetAttribute("E5", std::to_string(axes.getExternalAxes()[4]));
        ekorr->SetAttribute("E6", std::to_string(axes.getExternalAxes()[5]));
        dat->LinkEndChild(ekorr);

        TiXmlElement *tech = new TiXmlElement("Tech");
        tech->SetAttribute("x", "1");
        tech->SetAttribute("p3", "0.0");
        tech->SetAttribute("p4", "0.0");
        tech->SetAttribute("p5", "0.0");
        tech->SetAttribute("p3x1", "0.0");
        tech->SetAttribute("p4x1", "0.0");
        tech->SetAttribute("p5x1", "0.0");
        tech->SetAttribute("p3x2", "0.0");
        tech->SetAttribute("p4x2", "0.0");
        tech->SetAttribute("p5x2", "0.0");
        tech->SetAttribute("p3x3", "0.0");
        tech->SetAttribute("p4x3", "0.0");
        tech->SetAttribute("p5x3", "0.0");
        dat->LinkEndChild(tech);

        // digital out????
        TiXmlElement *dio = new TiXmlElement("DiO");
        dio->LinkEndChild(new TiXmlText("0"));
        dat->LinkEndChild(dio);

        // timestamp
        el = new TiXmlElement("IPOC");
        el->LinkEndChild(new TiXmlText(std::to_string(ipoc)));
        dat->LinkEndChild(el);

        doc.LinkEndChild(root);
        TiXmlPrinter printer;
        printer.SetStreamPrinting();
        doc.Accept(&printer);

        xml_doc = printer.Str();
    }

} // namespace kuka_rsi_hw_interface

#endif
