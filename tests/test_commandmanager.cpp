#include "doctest/doctest.h"
#include "execute_unit/CommandManager.h"
#include "execute_unit/Command.h"
#include <string>
#include <thread>
#include <chrono>
#include <atomic>

class MockCommand : public CCommand {
public:
    MockCommand() : CCommand("mock","mockdesc"), called(false) {}
    uint32_t execute(void* pdata, size_t dataSize, std::atomic<bool>* cancelFlag = nullptr) override {
        (void)cancelFlag;
        called = true;
        if (pdata!=nullptr && dataSize>0) last = std::string((char*)pdata, dataSize);
        return 123;
    }
    bool called;
    std::string last;
};

TEST_CASE("AddAndExecuteCommand") {
    CCommandManager mgr;
    MockCommand* cmd = new MockCommand();
    bool added = mgr.addCommand("test", cmd);
    CHECK(added);

    SJob job;
    job._cmd = "test";
    std::string payload = "abc";
    job._pdata = (void*)payload.data();
    job._dataSize = payload.size();

    uint32_t rc = mgr.jobExecute(job, JobModeSynchronous, JobQueueTypeNone);
    CHECK((uint32_t)123 == rc);
    CHECK(cmd->called);
    CHECK(std::string("abc") == cmd->last);

    // manager destructor will delete cmd
}

// Async command that honors cancel flag
class MockAsyncCommand : public CCommand {
public:
    MockAsyncCommand(std::atomic<bool>* started, std::atomic<bool>* finished, std::atomic<bool>* cancelled)
        : CCommand("mockasync","mockdesc"), m_started(started), m_finished(finished), m_cancelled(cancelled) {}

    uint32_t execute(void* pdata, size_t dataSize, std::atomic<bool>* cancelFlag = nullptr) override {
        (void)dataSize;
        m_started->store(true);
        // Simulate work for up to 500ms, periodically checking cancelFlag
        for (int i = 0; i < 50; ++i) {
            if (cancelFlag && cancelFlag->load()) {
                m_cancelled->store(true);
                m_finished->store(true);
                return 1; // cancelled
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        m_finished->store(true);
        return 0; // success
    }

private:
    std::atomic<bool>* m_started;
    std::atomic<bool>* m_finished;
    std::atomic<bool>* m_cancelled;
};

TEST_CASE("AsyncJobCompletesBeforeDestructor") {
    std::atomic<bool> started(false);
    std::atomic<bool> finished(false);
    std::atomic<bool> cancelled(false);

    {
        CCommandManager mgr;
        MockAsyncCommand* cmd = new MockAsyncCommand(&started, &finished, &cancelled);
        mgr.addCommand("async", cmd);

        SJob job;
        job._cmd = "async";
        job._pdata = nullptr;
        job._dataSize = 0;

        uint32_t jobId = mgr.jobExecute(job, JobModeAsynchronous, JobQueueTypeNone);
        CHECK(jobId > 0);

        // wait until the background job started
        for (int i=0;i<50 && !started.load();++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        CHECK(started.load());

        // leaving scope should trigger CCommandManager destructor which must
        // notify and wait for async jobs to finish gracefully
    }

    // after manager destruction the job must have finished
    CHECK(finished.load());
}

TEST_CASE("StopAllJobsNotifiesAndJoins") {
    std::atomic<bool> started(false);
    std::atomic<bool> finished(false);
    std::atomic<bool> cancelled(false);

    CCommandManager mgr;
    MockAsyncCommand* cmd = new MockAsyncCommand(&started, &finished, &cancelled);
    mgr.addCommand("async2", cmd);

    SJob job;
    job._cmd = "async2";
    job._pdata = nullptr;
    job._dataSize = 0;

    uint32_t jobId = mgr.jobExecute(job, JobModeAsynchronous, JobQueueTypeNone);
    CHECK(jobId > 0);

    // wait until the background job started
    for (int i=0;i<50 && !started.load();++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK(started.load());

    // Request stop and wait
    mgr.stopAllJobs();
    mgr.waitAllJobs();

    CHECK(finished.load());
    CHECK(cancelled.load());
}
