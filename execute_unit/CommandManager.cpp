#include "execute_unit/CommandManager.h"
#include <algorithm>
#include "logging/Logging.h"
#include <chrono>
#include <limits>

CCommandManager::CCommandManager(void) {
    // No-op. Logging is initialized centrally via Logging::initLogging().
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
        // Notify waiters that a job has finished
        m_jobsFinishedCv.notify_all();
        Logging::info("Job {} finished with rc={}", jobId, rc);
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
    // Block indefinitely until all jobs finish
    (void)waitAllJobs(std::numeric_limits<uint64_t>::max());
}

bool CCommandManager::waitAllJobs(uint64_t timeoutMs) {
    using clock = std::chrono::steady_clock;
    auto deadline = clock::time_point::max();
    if (timeoutMs != std::numeric_limits<uint64_t>::max()) {
        deadline = clock::now() + std::chrono::milliseconds(timeoutMs);
    }

    std::unique_lock<std::mutex> lk(m_jobsMutex);
    auto allFinished = [this]() {
        return std::all_of(m_jobs.begin(), m_jobs.end(), [](auto &kv) { return kv.second->finished.load(); });
    };

    // Wait until either all jobs are finished or timeout occurs
    while (!m_jobs.empty() && !allFinished()) {
        if (deadline == clock::time_point::max()) {
            m_jobsFinishedCv.wait(lk, allFinished);
        } else {
            bool ok = m_jobsFinishedCv.wait_until(lk, deadline, allFinished);
            if (!ok) {
                // timeout occurred and jobs still running
                Logging::warn("waitAllJobs timed out with {} jobs still running", m_jobs.size());
                return false;
            }
        }
    }

    // All jobs are finished; move out records and join threads
    std::unordered_map<uint32_t, std::unique_ptr<JobInfo>> jobs = std::move(m_jobs);
    m_jobs.clear();
    lk.unlock();

    for (auto &kv : jobs) {
        auto &ji = kv.second;
        if (ji->thread.joinable()) {
            Logging::info("Joining job thread {}", kv.first);
            ji->thread.join();
        }
    }

    return true;
}