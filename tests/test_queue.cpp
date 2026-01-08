#include "doctest/doctest.h"
#include "algortihms/queue/queue.h"
#include <cstring>

TEST_CASE("WriteRead_Simple") {
    CQueue q(1024);
    CHECK(q.isActive());

    CQueueProducer* p = q.register_producer();
    CHECK(p != nullptr);
    CQueueConsumer* c = q.register_consumer();
    CHECK(c != nullptr);

    const char* msg = "hello";
    char buf[32] = {0};

    uint32_t w = p->write(msg, (uint32_t)strlen(msg));
    CHECK((uint32_t)strlen(msg) == w);

    uint32_t r = c->read(buf, 1000);
    CHECK((uint32_t)strlen(msg) == r);
    CHECK(strcmp(buf, msg) == 0);

    // clean up
    delete p;
    delete c;
}

TEST_CASE("Write_TooLarge_ReturnsError") {
    // Create a very small queue and attempt to write a too-large entry
    CQueue q(16); // small buffer
    CQueueProducer* p = q.register_producer();
    CHECK(p != nullptr);
    char data[32] = {0};
    uint32_t res = p->write(data, 16); // 16 + header >= 16 -> error
    CHECK((uint32_t)QUEUE_RET_ERROR == res);
    delete p;
}

