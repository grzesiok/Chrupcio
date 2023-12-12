/****************************** Module Header ******************************\
* Module Name:  NetworkWatcher.h
* Project:      Chrupcio
* Copyright     Grzegorz Kasprzyszak
*
* Provides a class to capture data sent/recv data over network
\***************************************************************************/

#pragma once
#include <pqxx/pqxx>
#include "out/build/x64-debug/_deps/pcapplusplus-src/Pcap++/header/PcapLiveDevice.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Packet++/header/RawPacket.h"

class CNetworkWatcher
{
public:
    CNetworkWatcher(pqxx::connection* pdb_connection, const char* pstrDeviceName);
 
    virtual ~CNetworkWatcher(void);

private:
    std::vector<pcpp::PcapLiveDevice*> m_devicesList;
    pqxx::connection* m_pdb_connection;
};