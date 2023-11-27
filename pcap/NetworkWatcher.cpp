#include "NetworkWatcher.h"
#include "service/ServiceException.h"
#include "Error.h"

CNetworkWatcher::CNetworkWatcher(const char* pstrDeviceName, const char* pstrFilterExp)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	wchar_t werrbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net;
	bpf_u_int32 mask;
	PWSTR pszDeviceName = new wchar_t[strlen(pstrDeviceName)];
	PWSTR pszFilterExp = new wchar_t[strlen(pstrFilterExp)];

	mbstowcs(pszDeviceName, pstrDeviceName, strlen(pstrDeviceName));
	mbstowcs(pszFilterExp, pstrFilterExp, strlen(pstrFilterExp));
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(pstrDeviceName, &net, &mask, errbuf) == -1) {
		net = 0;
		mask = 0;
		mbstowcs(werrbuf, errbuf, strlen(errbuf));
		throw CServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPLookupNetFailed, L"Couldn't get netmask for device %s: %s", pszDeviceName, werrbuf);
	}
	/* open capture device */
	m_pcapHandle = pcap_open_live(pstrDeviceName, BUFSIZ, 0, 1000, errbuf);
	if (m_pcapHandle == NULL) {
		mbstowcs(werrbuf, errbuf, strlen(errbuf));
		throw CServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPOpenLiveFailed, L"Couldn't open device %s: %s", pszDeviceName, werrbuf);
	}
	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(m_pcapHandle) != DLT_EN10MB) {
		throw CServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPDataLinkFailed, L"%s is not an Ethernet", pszDeviceName);
	}
	/* compile the filter expression */
	if (pcap_compile(m_pcapHandle, &m_pcapFp, pstrFilterExp, 0, net) == -1) {
		throw CServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPCompileFailed, L"Couldn't compile filter %s: %s", pszFilterExp, pcap_geterr(m_pcapHandle));
	}
	/* apply the compiled filter */
	if (pcap_setfilter(m_pcapHandle, &m_pcapFp) == -1) {
		throw CServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPSetFilterFailed, L"Couldn't apply filter %s: %s", pszFilterExp, pcap_geterr(m_pcapHandle));
	}
	delete[] pszDeviceName;
	delete[] pszFilterExp;
}

CNetworkWatcher::~CNetworkWatcher(void)
{
	pcap_freecode(&m_pcapFp);
	pcap_close(m_pcapHandle);
}

SNetworkPacket CNetworkWatcher::nextPacket(void) {
	SNetworkPacket networkPacket;
	struct pcap_pkthdr header;
	networkPacket._pdata = (void*)pcap_next(m_pcapHandle, &header);
	networkPacket._size = header.len;
	networkPacket._ts = header.ts;
	return networkPacket;
}