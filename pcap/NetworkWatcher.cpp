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
#include "algortihms/queue/queue.h"
#include "algortihms/memory/memory.h"

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

struct Packet {
	pcpp::LinkLayerType _linkType;
	timespec _timestamp;
	int _dataLen;
};

/**
* A callback function for the async capture which is called each time a packet is captured
*/
void onPacketArrives(pcpp::RawPacket* pPacket, pcpp::PcapLiveDevice* pDevice, void* queue)
{
	CQueue* pQueue = (CQueue*)queue;
	// Register producer
	CQueueProducer* pQueueProducer = pQueue->register_producer();
	// parsed the raw packet
	pcpp::Packet parsedPacket(pPacket);
	/* Collect information only about HTTP traffic */
	if (parsedPacket.isPacketOfType(pcpp::HTTPRequest) || parsedPacket.isPacketOfType(pcpp::HTTPResponse)) {
		Packet* pRawPacket = (Packet*)malloc(sizeof(Packet) + pPacket->getRawDataLen());
		if (pRawPacket != NULL) {
			pRawPacket->_timestamp = pPacket->getPacketTimeStamp();
			pRawPacket->_linkType = pPacket->getLinkLayerType();
			pRawPacket->_dataLen = pPacket->getRawDataLen();
			memcpy(memoryPtrMove(pRawPacket, sizeof(Packet)), pPacket->getRawData(), pPacket->getRawDataLen());
			/* Push data to queue */
			pQueueProducer->write(pRawPacket, sizeof(Packet) + pPacket->getRawDataLen());
			free(pRawPacket);
		}
	}
	delete pQueueProducer;
}

void watcherThread(void* queue) {
	uint32_t ret;
	void* buffer;
	CQueue* pQueue = (CQueue*)queue;
	// Register producer
	CQueueConsumer* pQueueConsumer = pQueue->register_consumer();
	if (pQueueConsumer == NULL) {
		goto __cleanup;
	}
	buffer = malloc(sizeof(char) * 1024 * 1024); //Allocating 1MB
	if (buffer == NULL) {
		goto __cleanup_free_consumer;
	}
	while (pQueue->isActive()) {
		ret = pQueueConsumer->read(buffer, 1000);
		if (ret != QUEUE_RET_ERROR) {
			/* Reformat structure after pulling it from queue */
			Packet* pPacket = (Packet*)buffer;
			pcpp::RawPacket* pRawPacket = new pcpp::RawPacket((uint8_t*)memoryPtrMove(pPacket, sizeof(Packet)), pPacket->_dataLen, pPacket->_timestamp, false, pPacket->_linkType);
		}
	}
	free(buffer);
__cleanup_free_consumer:
	delete pQueueConsumer;
__cleanup:
	return;
}

CNetworkWatcher::CNetworkWatcher() : queue(1024 * 1024 * 128)
{
	// parse statement
	//m_pdb_connection->prepare("packet_insert_httpRequest", gcSQLPacketInsertHTTPRequest);
	//m_pdb_connection->prepare("packet_insert_httpResponse", gcSQLPacketInsertHTTPResponse);
	// create a filter instance to capture only rquired traffic
	pcpp::ProtoFilter protocolFilterHTTP(pcpp::HTTP);
	// get the list of interfaces and rint then to the event log
	m_devicesList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	for (unsigned int i = 0; i < m_devicesList.size(); i++) {
		pcpp::PcapLiveDevice* pDev = m_devicesList[i];
		if (pDev == NULL) {
			throw CServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPLookupNetFailed, L"Cannot find interface with name of '%S", pDev->getName());
		}
		if (!pDev->open())
		{
			throw CServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPLookupNetFailed, L"Cannot open device '%S", pDev->getName());
		}
		pDev->setFilter(protocolFilterHTTP);
		pcpp::OnPacketArrivesCallback pOnPacketArrives = onPacketArrives;
		void* onPacketArrivesUserCookie = &queue;
		pDev->startCapture(pOnPacketArrives, onPacketArrivesUserCookie);
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