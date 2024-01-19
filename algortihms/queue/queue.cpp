#include "queue.h"
#include "algortihms/memory/memory.h"
#include <immintrin.h>
#include <chrono>
using namespace std::chrono_literals;

typedef struct {
    uint32_t _size;
    uint32_t _crc32;
} queue_entry_t;

uint32_t sse42_crc32(const void* bytes, size_t len) {
    uint32_t hash = 0xffffffff;
    size_t i = 0;
    for (i = 0; i < len; i++) {
        hash = _mm_crc32_u8(hash, ((uint8_t*)bytes)[i]);
    }
    return hash;
}

CQueue::CQueue(uint32_t size) {
    void* pqueue = malloc(size);
    if (pqueue != NULL) {
        this->_leftBorder = pqueue;
        this->_rightBorder = memoryPtrMove(this->_leftBorder, size);
        this->_head = (char*)this->_leftBorder;
        this->_tail = (char*)this->_leftBorder;
        this->_stats._consumers = 0;
        this->_stats._producers = 0;
        this->_isActive = true;
        this->_stats._entriesCurrent = 0;
        this->_stats._entriesMax = 0;
        this->_stats._memUsageCurrent = 0;
        this->_stats._memUsageMax = 0;
        this->_stats._memSizeCurrent = size;
        this->_stats._memSizeMin = size;
        this->_stats._memSizeMax = size;
        memset(this->_leftBorder, 0, size);
    } else this->_isActive = false;
}

CQueue::~CQueue() {
    if (this->_isActive) {
        this->_isActive = false;
        std::unique_lock<std::mutex> W{ this->_writeMutex };
        this->_writeCondVariable.wait(W, [&]()
            {
                return this->_stats._producers == 0;
            });
        std::unique_lock<std::mutex> R{ this->_readMutex };
        this->_readCondVariable.wait(R, [&]()
            {
                return this->_stats._consumers == 0;
            });
        free(this->_leftBorder);
    }
}

bool CQueue::isActive() {
    return _isActive;
}

void CQueue::i_queue_write(const void* src, uint32_t size) {
    unsigned char* psrc = (unsigned char*)src;
    while (size-- > 0) {
        *this->_head++ = *psrc++;
        if (this->_head == this->_rightBorder)
            this->_head = (char*)this->_leftBorder;
    }
}

void CQueue::i_queue_read(void* dst, uint32_t size) {
    unsigned char* pdst = (unsigned char*)dst;
    while (size-- > 0) {
        *pdst++ = *this->_tail++;
        if (this->_tail == this->_rightBorder)
            this->_tail = (char*)this->_leftBorder;
    }
}

CQueueConsumer* CQueue::register_consumer() {
    CQueueConsumer* pNewConsumer = NULL;
    this->_readMutex.lock();
    if (this->_isActive) {
        pNewConsumer = new CQueueConsumer(this);
        this->_stats._consumers++;
    }
    this->_readMutex.unlock();
    return pNewConsumer;
}

void CQueue::free_consumer() {
    if (this->_isActive) {
        this->_stats._consumers--;
    }
    this->_readCondVariable.notify_all();
}

CQueueProducer* CQueue::register_producer() {
    CQueueProducer* pNewProducer = NULL;
    this->_writeMutex.lock();
    if (this->_isActive) {
        pNewProducer = new CQueueProducer(this);
        this->_stats._producers++;
    }
    this->_writeMutex.unlock();
    return pNewProducer;
}

void CQueue::free_producer() {
    if (this->_isActive) {
        this->_stats._producers--;
    }
    this->_writeCondVariable.notify_all();
}

CQueueConsumer::CQueueConsumer(CQueue* pQueue) {
    _pQueue = pQueue;
}

CQueueConsumer::~CQueueConsumer() {
    this->_pQueue->free_consumer();
}

uint32_t CQueue::read(void* pbuf, uint32_t wait_ms) {
    queue_entry_t header;

    std::unique_lock<std::mutex> R{ this->_readMutex };
    while (this->_stats._entriesCurrent == 0) {
        auto now = std::chrono::system_clock::now();
        this->_writeCondVariable.wait_until(R, now + wait_ms * 1ms, [&]()
            {
                return this->_stats._entriesCurrent > 0;
            });
        if (!this->_isActive) {
            R.unlock();
            return QUEUE_RET_DESTROYING;
        }
    }
    // copy header as first bytes)
    i_queue_read(&header, sizeof(queue_entry_t));
    // then copy data
    i_queue_read(pbuf, header._size);
    _stats._entriesCurrent--;
    _stats._memUsageCurrent -= header._size + sizeof(queue_entry_t);
    R.unlock();
    // and broadcast changes to other threads
    this->_writeCondVariable.notify_all();
    if (sse42_crc32(pbuf, header._size) != header._crc32) {
        return QUEUE_RET_ERROR;
    }
    return header._size;
}

uint32_t CQueueConsumer::read(void* pbuf, uint32_t wait_ms) {
    return this->_pQueue->read(pbuf, wait_ms);
}

uint32_t CQueueConsumer::read(void* pbuf) {
    return this->_pQueue->read(pbuf, 0xffffffff);
}

CQueueProducer::CQueueProducer(CQueue* pQueue) {
    _pQueue = pQueue;
}

CQueueProducer::~CQueueProducer() {
    this->_pQueue->free_producer();
}

uint32_t CQueue::write(const void* pbuf, uint32_t nBytes, uint32_t wait_ms) {
    queue_entry_t header;
    uint32_t entrySize = nBytes + sizeof(queue_entry_t);

    if (entrySize >= _stats._memSizeCurrent)
        return QUEUE_RET_ERROR;
    // prepare header
    header._size = nBytes;
    header._crc32 = sse42_crc32(pbuf, nBytes);
    std::unique_lock<std::mutex> W{ this->_writeMutex };
    while (_stats._memSizeCurrent - _stats._memUsageCurrent <= entrySize) {
        auto now = std::chrono::system_clock::now();
        // check if we have enough room to store data
        this->_writeCondVariable.wait_until(W, now + wait_ms * 1ms, [&]()
            {
                return _stats._memSizeCurrent - _stats._memUsageCurrent >= entrySize;
            });
        if (!this->_isActive) {
            W.unlock();
            return QUEUE_RET_DESTROYING;
        }
    }
    // copy header
    i_queue_write(&header, sizeof(queue_entry_t));
    // and data
    i_queue_write( pbuf, header._size);
    size_t numOfEntries = ++_stats._entriesCurrent;
    if (numOfEntries > _stats._entriesMax)
        _stats._entriesMax = numOfEntries;
    size_t usageOfMemory = _stats._memUsageCurrent += entrySize;
    if (usageOfMemory > _stats._memUsageMax)
        _stats._memUsageMax = usageOfMemory;
    W.unlock();
    this->_readCondVariable.notify_all();
    return nBytes;
}

uint32_t CQueueProducer::write(const void* pbuf, uint32_t nBytes, uint32_t wait_ms) {
    return this->_pQueue->write(pbuf, nBytes, wait_ms);
}

uint32_t CQueueProducer::write(const void* pbuf, uint32_t nBytes) {
    return this->_pQueue->write(pbuf, nBytes, 0xffffffff);
}