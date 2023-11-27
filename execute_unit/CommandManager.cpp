#include "execute_unit/CommandManager.h"

CCommandManager::CCommandManager(void) {
}

CCommandManager::~CCommandManager(void) {
    std::map<std::string, CCommand*>::iterator it;
    for (it = m_commands.begin(); it != m_commands.end(); ++it) {
        delete it->second;
    }
}

uint32_t CCommandManager::addCommand(std::string cmd, CCommand *pcommand) {
    m_commands[cmd] = pcommand;
    return 0;
}

uint32_t CCommandManager::jobExecute(SJob pJob, EJobMode mode, EJobQueueType queueType) {
    CCommand* pcommand = m_commands[pJob._cmd];
    return pcommand->execute(pJob._pdata, pJob._dataSize);
}