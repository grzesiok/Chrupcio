/****************************** Module Header ******************************\
* Module Name:  NetworkWatcher.h
* Project:      Chrupcio
* Copyright     Grzegorz Kasprzyszak
*
* Provides a class to capture data sent/recv data over network
\***************************************************************************/

#pragma once
#include "out/build/x64-debug/_deps/pcapplusplus-src/Pcap++/header/PcapLiveDevice.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Packet++/header/RawPacket.h"
#include "algortihms/queue/queue.h"

class CNetworkWatcher
{
public:
    CNetworkWatcher();
 
    virtual ~CNetworkWatcher(void);

private:
    std::vector<pcpp::PcapLiveDevice*> m_devicesList;
    CQueue queue;
};