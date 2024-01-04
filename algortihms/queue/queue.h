#ifndef _LIBALGORITHMS_ALGORITHMS_QUEUE_H
#define _LIBALGORITHMS_ALGORITHMS_QUEUE_H

#include <atomic>
#include <mutex>
#include <condition_variable>

#define QUEUE_RET_ERROR 0xffffffff
#define QUEUE_RET_DESTROYING 0xfffffffe

struct QueueStats {
    std::atomic<std::uint16_t> _producers;
    std::atomic<std::uint16_t> _consumers;

    std::atomic<std::uint64_t> _entriesCurrent;//number of entries actually stored in queue
    std::atomic<std::uint64_t> _entriesMax;//maximum number of entries stored in queue
    std::atomic<std::uint64_t> _memUsageCurrent;//Actual usage of memory for stored entries
    std::atomic<std::uint64_t> _memUsageMax;//Maximum amount of memory needed for entries
    std::atomic<std::uint64_t> _memSizeCurrent;//Current size of queue
    std::atomic<std::uint64_t> _memSizeMin;//Minimum size of queue
    std::atomic<std::uint64_t> _memSizeMax;//Maximum size of queue
};

class CQueue;

class CQueueProducer {
public:
    CQueueProducer(CQueue* pQueue);
    virtual ~CQueueProducer();
    uint32_t write(const void* pbuf, uint32_t nBytes, uint32_t wait_ms);
    uint32_t write(const void* pbuf, uint32_t nBytes);
private:
    CQueue* _pQueue;
};

class CQueueConsumer {
public:
    CQueueConsumer(CQueue* pQueue);
    virtual ~CQueueConsumer();
    uint32_t read(void* pbuf, uint32_t wait_ms);
    uint32_t read(void* pbuf);
private:
    CQueue* _pQueue;
};

class CQueue {
public:
    CQueue(uint32_t size);
    virtual ~CQueue();
    CQueueProducer* register_producer();
    void free_producer();
    CQueueConsumer* register_consumer();
    void free_consumer();
    bool isActive();
    uint32_t write(const void* pbuf, uint32_t nBytes, uint32_t wait_ms);
    uint32_t read(void* pbuf, uint32_t wait_ms);
private:
    char* _head;
    char* _tail;
    void* _leftBorder;
    void* _rightBorder;
    std::mutex _readMutex;
    std::condition_variable _readCondVariable;
    std::mutex _writeMutex;
    std::condition_variable _writeCondVariable;
    QueueStats _stats;
    bool _isActive;

    void i_queue_write(const void* src, uint32_t size);
    void i_queue_read(void* dst, uint32_t size);
};

#endif /*_LIBALGORITHMS_ALGORITHMS_QUEUE_H */