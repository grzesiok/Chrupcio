#include "NetworkWatcher.h"
#include "..\Error.h"

CNetworkWatcher::CNetworkWatcher(PWSTR pszDeviceName)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_exp[] = "ip and not (dst net 192.168.0.0/16 and src net 192.168.0.0/16)"; /* filter expression (only IP packets) */
	bpf_u_int32 net;
	bpf_u_int32 mask;
	char* p_deviceName = NULL;

	wcstombs(p_deviceName, pszDeviceName, wcslen(pszDeviceName));
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(p_deviceName, &net, &mask, errbuf) == -1) {
		net = 0;
		mask = 0;
		throw ServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPLookupNetFailed, L"Couldn't get netmask for device %s: %s", p_deviceName, errbuf);
	}
	/* open capture device */
	m_pcapHandle = pcap_open_live(p_deviceName, BUFSIZ, 0, 1000, errbuf);
	if (m_pcapHandle == NULL) {
		throw ServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPOpenLiveFailed, L"Couldn't open device %s: %s", p_deviceName, errbuf);
	}
	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(m_pcapHandle) != DLT_EN10MB) {
		throw ServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPDataLinkFailed, L"%s is not an Ethernet", p_deviceName);
	}
	/* compile the filter expression */
	if (pcap_compile(m_pcapHandle, &m_pcapFp, filter_exp, 0, net) == -1) {
		throw ServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPCompileFailed, L"Couldn't parse filter %s: %s", filter_exp, pcap_geterr(m_pcapHandle));
	}
	/* apply the compiled filter */
	if (pcap_setfilter(m_pcapHandle, &m_pcapFp) == -1) {
		throw ServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPSetFilterFailed, L"Couldn't install filter %s: %s", filter_exp, pcap_geterr(m_pcapHandle));
	}
}

CNetworkWatcher::~CNetworkWatcher(void)
{
	pcap_freecode(&m_pcapFp);
	pcap_close(m_pcapHandle);
}

void CNetworkWatcher::nextPacket(void)
{
	void* packet;
	struct pcap_pkthdr header;
	packet = (void*)pcap_next(m_pcapHandle, &header);
}