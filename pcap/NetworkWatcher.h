/****************************** Module Header ******************************\
* Module Name:  NetworkWatcher.h
* Project:      Chrupcio
* Copyright     Grzegorz Kasprzyszak
*
* Provides a class to capture data sent/recv data over network
\***************************************************************************/

#pragma once

#define _WINSOCKAPI_
#include <windows.h>
#include <pcap.h>

class CNetworkWatcher
{
public:
    CNetworkWatcher(PWSTR pszDeviceName);

    // Statistic object destructor. 
    virtual ~CNetworkWatcher(void);

protected:
    // Start the service.
    void ProcessPacket(void);

private:
    pcap_t* m_pcapHandle;
    struct bpf_program m_pcapFp; /* compiled filter program (expression) */
};