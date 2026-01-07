#include "doctest/doctest.h"
#include "execute_unit/CommandManager.h"
#include "execute_unit/Command.h"
#include <string>

class MockCommand : public CCommand {
public:
    MockCommand() : CCommand("mock","mockdesc"), called(false) {}
    uint32_t execute(void* pdata, size_t dataSize) override {
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
