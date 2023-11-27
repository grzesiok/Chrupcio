#pragma once
#include "execute_unit/Command.h"
#include <map>

typedef enum {
    JobModeSynchronous,
    JobModeAsynchronous
} EJobMode;

typedef enum {
    JobQueueTypeNone,
    JobQueueTypeShortOps,
    JobQueueTypeLongOps
} EJobQueueType;

struct SJob {
    std::string _cmd;
    void* _pdata;
    size_t _dataSize;
};

class CCommandManager
{
public:
    CCommandManager(void);

    virtual ~CCommandManager(void);

    uint32_t addCommand(std::string cmd, CCommand* pcommand);
    uint32_t jobExecute(SJob pJob, EJobMode mode, EJobQueueType queueType);
private:
    std::map<std::string, CCommand*> m_commands;
};