/****************************** Module Header ******************************\
* Module Name:  NetworkWatcher.h
* Project:      Chrupcio
* Copyright     Grzegorz Kasprzyszak
*
* Provides a class to capture data sent/recv data over network
\***************************************************************************/

#pragma once

#include <pcap.h>

struct SNetworkPacket {
	void* _pdata;
	timeval _ts;
	size_t _size;
};

class CNetworkWatcher
{
public:
    CNetworkWatcher(const char* pstrDeviceName, const char* pstrFilterExp);
 
    virtual ~CNetworkWatcher(void);

    // To pull next packet
	SNetworkPacket nextPacket(void);

private:
    pcap_t* m_pcapHandle;
    struct bpf_program m_pcapFp; /* compiled filter program (expression) */
};