#include "NetworkWatcher.h"
#include "service/ServiceException.h"
#include "Error.h"
#include <algorithm>
#include "out/build/x64-debug/_deps/pcapplusplus-src/Common++/header/SystemUtils.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Pcap++/header/PcapLiveDeviceList.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Pcap++/header/PcapLiveDevice.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Packet++/header/Packet.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Packet++/header/RawPacket.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Packet++/header/IPv4Layer.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Packet++/header/HttpLayer.h"
#include <string>

const static std::string gcSQLPacketInsertHTTPRequest =
"INSERT INTO packet (ts_sec,ts_usec, \
                     ip_src,ip_dst, \
                     packet_type, \
                     http_method, http_version, http_url, http_data_size, http_header_size) \
	VALUES ($1, $2, \
            $3, $4, \
            'HTTP_REQEST', \
            $5, $6, $7, $8, $9);";
const static std::string gcSQLPacketInsertHTTPResponse =
"INSERT INTO packet (ts_sec,ts_usec, \
                     ip_src,ip_dst, \
                     packet_type, \
                     http_version, http_data_size, http_header_size, http_status_code) \
	VALUES ($1, $2, \
            $3, $4, \
            'HTTP_RESPONSE', \
            $5, $6, $7, $8);";

std::string translateHttpMethodToString(pcpp::HttpRequestLayer::HttpMethod httpMethod) {
	switch(httpMethod) {
	case pcpp::HttpRequestLayer::HttpGET:
		return "GET";
	case pcpp::HttpRequestLayer::HttpPOST:
		return "POST";
	}
	return "Other";
}

std::string translateHttpVersionToString(pcpp::HttpVersion httpVersion) {
	switch (httpVersion) {
	case pcpp::HttpVersion::ZeroDotNine:
		return "HTTP/0.9";
	case pcpp::HttpVersion::OneDotZero:
		return "HTTP/1.0";
	case pcpp::HttpVersion::OneDotOne:
		return "HTTP/1.1";
	case pcpp::HttpVersion::HttpVersionUnknown:
		return "Unknown";
	}
	return "Other";
}

/**
* A callback function for the async capture which is called each time a packet is captured
*/
void onPacketArrives(pcpp::RawPacket* pPacket, pcpp::PcapLiveDevice* pDevice, void* dbConnection)
{
	/* DB connection */
	pqxx::connection* pdb_connection = (pqxx::connection*)dbConnection;
	/* Create a transactional object. */
	pqxx::work W(*pdb_connection);
	// parsed the raw packet
	pcpp::Packet parsedPacket(pPacket);
	pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ipLayer == NULL) {
		//std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
		return;
	}
	/* Execute SQL query */
	if (parsedPacket.isPacketOfType(pcpp::HTTPRequest)) {
		pcpp::HttpRequestLayer* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
		std::string httpMethod = translateHttpMethodToString(httpRequestLayer->getFirstLine()->getMethod());
		std::string httpVersion = translateHttpVersionToString(httpRequestLayer->getFirstLine()->getVersion());
		W.exec_prepared("packet_insert_httpRequest",
			(uint64_t)pPacket->getPacketTimeStamp().tv_sec, (uint64_t)pPacket->getPacketTimeStamp().tv_nsec,
			ipLayer->getSrcIPAddress().toString(), ipLayer->getDstIPAddress().toString(),
			httpMethod,
			httpVersion,
			httpRequestLayer->getUrl(),
			httpRequestLayer->getDataLen(),
			httpRequestLayer->getHeaderLen());
	}
	else if (parsedPacket.isPacketOfType(pcpp::HTTPResponse)) {
		pcpp::HttpResponseLayer* httpResponseLayer = parsedPacket.getLayerOfType<pcpp::HttpResponseLayer>();
		std::string httpVersion = translateHttpVersionToString(httpResponseLayer->getFirstLine()->getVersion());
		W.exec_prepared("packet_insert_httpResponse",
			(uint64_t)pPacket->getPacketTimeStamp().tv_sec, (uint64_t)pPacket->getPacketTimeStamp().tv_nsec,
			ipLayer->getSrcIPAddress().toString(), ipLayer->getDstIPAddress().toString(),
			httpVersion,
			httpResponseLayer->getDataLen(),
			httpResponseLayer->getHeaderLen(),
			httpResponseLayer->getFirstLine()->getStatusCodeAsInt());
	}
	/* Commit transaction */
	W.commit();
}

CNetworkWatcher::CNetworkWatcher(pqxx::connection* pdb_connection, const char* pstrDeviceName)
{
	m_pdb_connection = pdb_connection;
	// parse statement
	m_pdb_connection->prepare("packet_insert_httpRequest", gcSQLPacketInsertHTTPRequest);
	m_pdb_connection->prepare("packet_insert_httpResponse", gcSQLPacketInsertHTTPResponse);
	// create a filter instance to capture only rquired traffic
	pcpp::ProtoFilter protocolFilterHTTP(pcpp::HTTP);
	std::vector<pcpp::GeneralFilter*> protocolFilterVec;
	protocolFilterVec.push_back(&protocolFilterHTTP);
	pcpp::OrFilter protocolFilter(protocolFilterVec);
	// get the list of interfaces and rint then to the event log
	m_devicesList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	for (unsigned int i = 0; i < m_devicesList.size(); i++) {
		pcpp::PcapLiveDevice* pDev = m_devicesList[i];
		if (pDev == NULL) {
			throw CServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPLookupNetFailed, L"Cannot find interface with name of '%S", pstrDeviceName);
		}
		if (!pDev->open())
		{
			throw CServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPLookupNetFailed, L"Cannot open device '%S", pstrDeviceName);
		}
		pDev->setFilter(protocolFilter);
		pcpp::OnPacketArrivesCallback pOnPacketArrives = onPacketArrives;
		void* onPacketArrivesUserCookie = NULL;
		pDev->startCapture(pOnPacketArrives, m_pdb_connection);
	}
}

CNetworkWatcher::~CNetworkWatcher(void)
{
	for (unsigned int i = 0; i < m_devicesList.size(); i++) {
		pcpp::PcapLiveDevice* pDev = m_devicesList[i];
		// stop capturing packets
		pDev->stopCapture();
	}
}