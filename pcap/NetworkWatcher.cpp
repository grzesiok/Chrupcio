#include "NetworkWatcher.h"
#include "..\Error.h"

CNetworkWatcher::CNetworkWatcher(PWSTR pszDeviceName)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "ip and not (dst net 192.168.0.0/16 and src net 192.168.0.0/16)"; /* filter expression (only IP packets) */
    bpf_u_int32 net;
    bpf_u_int32 mask;
    const char* p_deviceName = "\\Device\\NPF_{8CDF54B9-41F5-4B0E-8C05-A7A7ACFB5243}";

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(p_deviceName, &net, &mask, errbuf) == -1) {
        WriteEventLogEntry(EVENTLOG_ERROR_TYPE, (PWSTR)L"Couldn't get netmask for device %s: %s", p_deviceName, errbuf);
        net = 0;
        mask = 0;
        throw ServiceErrorPCAPLookupNetFailed;
    }
    /* open capture device */
    m_pcapHandle = pcap_open_live(p_deviceName, BUFSIZ, 0, 1000, errbuf);
    if (m_pcapHandle == NULL) {
        WriteEventLogEntry(EVENTLOG_ERROR_TYPE, (PWSTR)L"Couldn't open device %s: %s", p_deviceName, errbuf);
        throw ServiceErrorPCAPOpenLiveFailed;
    }
    /* make sure we're capturing on an Ethernet device */
    if (pcap_datalink(m_pcapHandle) != DLT_EN10MB) {
        WriteEventLogEntry(EVENTLOG_ERROR_TYPE, (PWSTR)L"%s is not an Ethernet", p_deviceName);
        throw ServiceErrorPCAPDataLinkFailed;
    }
    /* compile the filter expression */
    if (pcap_compile(m_pcapHandle, &m_pcapFp, filter_exp, 0, net) == -1) {
        WriteEventLogEntry(EVENTLOG_ERROR_TYPE, (PWSTR)L"Couldn't parse filter %s: %s", filter_exp, pcap_geterr(m_pcapHandle));
        throw ServiceErrorPCAPCompileFailed;
    }
    /* apply the compiled filter */
    if (pcap_setfilter(m_pcapHandle, &m_pcapFp) == -1) {
        WriteEventLogEntry(EVENTLOG_ERROR_TYPE, (PWSTR)L"Couldn't install filter %s: %s", filter_exp, pcap_geterr(m_pcapHandle));
        throw ServiceErrorPCAPSetFilterFailed;
    }
}

CNetworkWatcher::~CNetworkWatcher(void)
{
    pcap_freecode(&m_pcapFp);
    pcap_close(m_pcapHandle);
}

void CNetworkWatcher::ProcessPacket(void)
{
}