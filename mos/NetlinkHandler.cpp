/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <android-base/logging.h>
//-----rk-code--------
#include <android-base/properties.h>
#include <cutils/properties.h>
//--------------------

#include <sysutils/NetlinkEvent.h>
#include "NetlinkHandler.h"

NetlinkHandler::NetlinkHandler(int listenerSocket) : NetlinkListener(listenerSocket) {}

NetlinkHandler::~NetlinkHandler() {}

int NetlinkHandler::start() {
    return this->startListener();
}

void NetlinkHandler::onEvent(NetlinkEvent* evt) {
    const char* subsys = evt->getSubsystem();

    if (!subsys) {
        LOG(WARNING) << "No subsystem found in netlink event";
        return;
    }

    if (android::base::GetBoolProperty("ro.rockchip.vehicle.mos", false) && std::string(subsys) == "platform") {
        const char* rebootParam = evt->findParam("REBOOT");
        const char* shutdownParam = evt->findParam("OFF");
        std::string rebootDetails(rebootParam ? rebootParam : "");
        std::string shutdownDetails(shutdownParam ? shutdownParam : "");
        if (shutdownDetails == "os0-os1") {
            LOG(ERROR) << "MOS,Linux request Android to shutdown!!!";
            property_set("sys.powerctl", "shutdown");
        } else if (rebootDetails == "os0-os1") {
	        LOG(ERROR) << "MOS,Linux request Android to reboot!!!";
            property_set("sys.powerctl", "reboot");
        }
    //--------------------
    }
}
