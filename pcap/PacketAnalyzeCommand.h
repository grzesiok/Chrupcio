#pragma once
#include "execute_unit/Command.h"
#include "pcap/NetworkWatcher.h"

class PacketAnalyzeCommand : public CCommand {
public:
	PacketAnalyzeCommand() : CCommand("PACKET_ANALYZE", "Analyze network packets and store it in DB file") {}

	uint32_t execute(void* pdata, size_t dataSize);
};