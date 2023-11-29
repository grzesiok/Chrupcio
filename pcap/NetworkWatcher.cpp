#include "NetworkWatcher.h"
#include "service/ServiceException.h"
#include "Error.h"
#include <algorithm>
#include "out/build/x64-debug/_deps/pcapplusplus-src/Common++/header/SystemUtils.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Pcap++/header/PcapLiveDeviceList.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Pcap++/header/PcapLiveDevice.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Packet++/header/Packet.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Packet++/header/RawPacket.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Packet++/header/EthLayer.h"
#include "out/build/x64-debug/_deps/pcapplusplus-src/Packet++/header/IPv4Layer.h"
#include <string>

/**
* A callback function for the async capture which is called each time a packet is captured
*/
void onPacketArrives(pcpp::RawPacket* pPacket, pcpp::PcapLiveDevice* pDevice, void* dbConnection)
{
	pqxx::connection* pdb_connection = (pqxx::connection*)dbConnection;
	/* Create a transactional object. */
	pqxx::work W(*pdb_connection);
	// parsed the raw packet
	pcpp::Packet parsedPacket(pPacket);
	pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
	if (ethernetLayer == NULL) {
		//std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
		return;
	}
	pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ipLayer == NULL) {
		//std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
		return;
	}
	/* Execute SQL query */
	W.exec_prepared("packets_insert",
		pPacket->getPacketTimeStamp().tv_sec,
		pPacket->getPacketTimeStamp().tv_nsec,
		ethernetLayer->getSourceMac().toString(),
		ethernetLayer->getDestMac().toString(),
		pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType),
		pcpp::netToHost16(ipLayer->getIPv4Header()->ipId),
		(int)ipLayer->getIPv4Header()->timeToLive,
		ipLayer->getProtocol(),
		ipLayer->getSrcIPAddress().toString(),
		ipLayer->getDstIPAddress().toString());
	/* Commit transaction */
	W.commit();
}

CNetworkWatcher::CNetworkWatcher(pqxx::connection* pdb_connection, const char* pstrDeviceName)
{
	m_pdb_connection = pdb_connection;
	m_pdb_connection->prepare("packets_insert", "INSERT INTO packets (ts_sec,ts_usec,eth_src,eth_dst,eth_type,ip_id,ip_ttl,ip_protocol,ip_src,ip_dst) \
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);");

	// find the interface by IP address
	m_dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp("192.168.50.69");
	if (m_dev == NULL) {
		throw CServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPLookupNetFailed, L"Cannot find interface with name of '%S", pstrDeviceName);
	}
	if (!m_dev->open())
	{
		throw CServiceException(EVENTLOG_ERROR_TYPE, ServiceErrorPCAPLookupNetFailed, L"Cannot open device '%S", pstrDeviceName);
	}
	// create a filter instance to capture only TCP traffic
	pcpp::ProtoFilter protocolFilter(pcpp::IP);
	m_dev->setFilter(protocolFilter);
	pcpp::OnPacketArrivesCallback pOnPacketArrives = onPacketArrives;
	void* onPacketArrivesUserCookie = NULL;
	m_dev->startCapture(pOnPacketArrives, m_pdb_connection);
}

CNetworkWatcher::~CNetworkWatcher(void)
{
	if (m_dev) {
		// stop capturing packets
		m_dev->stopCapture();
	}
}