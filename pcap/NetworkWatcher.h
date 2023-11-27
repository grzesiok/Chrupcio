/****************************** Module Header ******************************\
* Module Name:  NetworkWatcher.h
* Project:      Chrupcio
* Copyright     Grzegorz Kasprzyszak
*
* Provides a class to capture data sent/recv data over network
\***************************************************************************/

#pragma once

#include <pcap.h>
#include <windows.h>

class CNetworkWatcher
{
public:
    CNetworkWatcher(PWSTR pszDeviceName);
 
    virtual ~CNetworkWatcher(void);

    // To pull next packet
    void nextPacket(void);

private:
    pcap_t* m_pcapHandle;
    struct bpf_program m_pcapFp; /* compiled filter program (expression) */
};