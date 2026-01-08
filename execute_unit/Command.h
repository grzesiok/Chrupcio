#pragma once
#include <string>

#include <atomic>

class CCommand
{
public:
	CCommand(std::string cmd, std::string description) {
		m_cmd = cmd;
		m_description = description;
	}

	virtual ~CCommand(void) {
	}

	// Single execution entry point which optionally supports cancellation.
	// Implementations that don't support cancellation may ignore the
	// `cancelFlag` parameter (it defaults to nullptr).
	virtual uint32_t execute(void* pdata, size_t dataSize, std::atomic<bool>* cancelFlag = nullptr) = 0;
private:
	std::string m_cmd;
	std::string m_description;
};