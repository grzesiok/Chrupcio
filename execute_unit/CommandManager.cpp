#include "execute_unit/CommandManager.h"
#include <algorithm>

CCommandManager::CCommandManager(void) {
}

CCommandManager::~CCommandManager(void) {
    // Request cancellation and wait for all async jobs to finish before
    // destroying the command manager and owned commands.
    stopAllJobs();
    waitAllJobs();

    std::map<std::string, CCommand*>::iterator it;
    for (it = m_commands.begin(); it != m_commands.end(); ++it) {
        delete it->second;
    }
}

bool CCommandManager::addCommand(std::string cmd, CCommand *pcommand) {
    m_commands[cmd] = pcommand;
    return true;
}

uint32_t CCommandManager::jobExecute(SJob pJob, EJobMode mode, EJobQueueType queueType) {
    // Find command
    auto it = m_commands.find(pJob._cmd);
    if (it == m_commands.end()) {
        // Command not found
        return static_cast<uint32_t>(-1);
    }
    CCommand* pcommand = it->second;

    if (mode == JobModeSynchronous) {
        return pcommand->execute(pJob._pdata, pJob._dataSize, nullptr);
    }

    // Asynchronous execution: create job record and start thread
    uint32_t jobId = ++m_nextJobId;
    auto job = std::make_unique<JobInfo>();
    job->cancelFlag = std::make_shared<std::atomic<bool>>(false);
    job->finished = false;
    job->result = 0;

    // Capture needed values by value; job pointer moved into map below
    std::shared_ptr<std::atomic<bool>> cancel = job->cancelFlag;

    job->thread = std::thread([this, pcommand, pJob, cancel, jobId]() mutable {
        uint32_t rc = pcommand->execute(pJob._pdata, pJob._dataSize, cancel.get());
        {
            std::lock_guard<std::mutex> lg(m_jobsMutex);
            auto jt = m_jobs.find(jobId);
            if (jt != m_jobs.end()) {
                jt->second->result = rc;
                jt->second->finished = true;
            }
        }
    });

    {
        std::lock_guard<std::mutex> lg(m_jobsMutex);
        m_jobs.emplace(jobId, std::move(job));
    }

    // Return job id > 0
    return jobId;
}

void CCommandManager::stopAllJobs() {
    std::lock_guard<std::mutex> lg(m_jobsMutex);
    for (auto &p : m_jobs) {
        if (p.second && p.second->cancelFlag) {
            p.second->cancelFlag->store(true);
        }
    }
}

void CCommandManager::waitAllJobs() {
    // Move job records out to join without holding lock
    std::unordered_map<uint32_t, std::unique_ptr<JobInfo>> jobs;
    {
        std::lock_guard<std::mutex> lg(m_jobsMutex);
        jobs = std::move(m_jobs);
        m_jobs.clear();
    }

    for (auto &kv : jobs) {
        auto &ji = kv.second;
        if (ji->thread.joinable()) {
            ji->thread.join();
        }
    }
}