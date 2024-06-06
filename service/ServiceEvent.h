#pragma once

class CServiceEvent {
public:
	void WriteEventLogEntry(WORD wType, PWSTR pszMessage, ...);
};