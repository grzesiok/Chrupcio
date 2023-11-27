#pragma once
#include <string>

class CCommand
{
public:
	CCommand(std::string cmd, std::string description) {
		m_cmd = cmd;
		m_description = description;
	}

	virtual ~CCommand(void) {
	}

	virtual uint32_t execute(void* pdata, size_t dataSize) = 0;
private:
	std::string m_cmd;
	std::string m_description;
};