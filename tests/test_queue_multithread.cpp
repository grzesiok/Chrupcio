#include "doctest/doctest.h"
#include "algortihms/queue/queue.h"
#include <thread>
#include <vector>
#include <atomic>

TEST_CASE("Multithreaded producers and single consumer") {
    CQueue q(32 * 1024);
    const int producers = 4;
    const int perProducer = 1000;

    std::atomic<int> produced{0};
    std::atomic<int> consumed{0};
    std::atomic<uint64_t> sum{0};

    // consumer thread
    std::thread consumer([&]() {
        CQueueConsumer* c = q.register_consumer();
        REQUIRE(c != nullptr);
        for (;;) {
            int value = 0;
            uint32_t r = c->read(&value, 1000);
            if (r == QUEUE_RET_DESTROYING) break;
            if (r == 0) continue;
            consumed++;
            sum += value;
            if (consumed.load() >= producers * perProducer) break;
        }
        delete c;
    });

    // producer threads
    std::vector<std::thread> threads;
    for (int i = 0; i < producers; ++i) {
        threads.emplace_back([&]() {
            CQueueProducer* p = q.register_producer();
            REQUIRE(p != nullptr);
            for (int j = 0; j < perProducer; ++j) {
                int v = 1; // constant 1 per entry
                uint32_t w = p->write(&v, sizeof(v));
                CHECK(w == sizeof(v));
                produced++;
            }
            delete p;
        });
    }
    for (auto &t : threads) t.join();
    // wait for consumer
    consumer.join();

    CHECK(produced.load() == producers * perProducer);
    CHECK(consumed.load() == producers * perProducer);
    CHECK(sum.load() == (uint64_t)producers * perProducer);
}

TEST_CASE("Zero length write/read") {
    CQueue q(1024);
    CQueueProducer* p = q.register_producer();
    CQueueConsumer* c = q.register_consumer();
    char buf[1];
    uint32_t w = p->write(nullptr, 0);
    CHECK(w == 0);
    uint32_t r = c->read(buf, 1000);
    CHECK(r == 0);
    delete p;
    delete c;
}

TEST_CASE("CRC mismatch detected") {
#ifdef UNIT_TEST
    CQueue q(1024);
    CQueueProducer* p = q.register_producer();
    CQueueConsumer* c = q.register_consumer();

    const char* msg = "hello";
    char buf[32] = {0};

    uint32_t w = p->write(msg, (uint32_t)strlen(msg));
    CHECK(w == (uint32_t)strlen(msg));

    // corrupt next entry's CRC
    q.test_corrupt_next_entry_crc();

    uint32_t r = c->read(buf, 1000);
    CHECK(r == QUEUE_RET_ERROR);

    delete p;
    delete c;
#else
    WARN("CRC mismatch test requires UNIT_TEST definition; skipped")
#endif
}
