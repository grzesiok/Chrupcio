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

#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <unordered_map>
#include <cstdint>

class CCommandManager
{
public:
    CCommandManager(void);

    virtual ~CCommandManager(void);

    bool addCommand(std::string cmd, CCommand* pcommand);

    // If mode == JobModeSynchronous: blocks and returns command return code.
    // If mode == JobModeAsynchronous: queues a background job and returns a
    // positive job id (>0) which can be used to track or wait on the job.
    uint32_t jobExecute(SJob pJob, EJobMode mode, EJobQueueType queueType);

    // Request all running asynchronous jobs to stop (sets their cancel flags).
    void stopAllJobs();

    // Waits for all running asynchronous jobs to finish (joins threads).
    void waitAllJobs();

    // Waits up to timeoutMs milliseconds for all running asynchronous jobs to
    // finish. Returns true if all jobs finished within the timeout, false if
    // the timeout elapsed with still-running jobs.
    bool waitAllJobs(uint64_t timeoutMs);

private:
    std::map<std::string, CCommand*> m_commands;

    struct JobInfo {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> cancelFlag;
        std::atomic<bool> finished{false};
        std::atomic<uint32_t> result{0};
    };

    std::mutex m_jobsMutex;
    std::condition_variable m_jobsFinishedCv;
    std::unordered_map<uint32_t, std::unique_ptr<JobInfo>> m_jobs;
    std::atomic<uint32_t> m_nextJobId{0};
};