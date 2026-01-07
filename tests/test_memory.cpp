#include "doctest/doctest.h"
#include "algortihms/memory/memory.h"
#include <cstdint>

TEST_CASE("MemoryPtrMove") {
    int x = 0;
    void* p = &x;
    void* p2 = memoryPtrMove(p, 8);
    CHECK(reinterpret_cast<char*>(p) + 8 == reinterpret_cast<char*>(p2));
}

TEST_CASE("MemoryAlign") {
    // 10 aligned to 8 -> 16
    CHECK((size_t)16 == (size_t)memoryAlign(10, 8));
    // already aligned stays the same
    CHECK((size_t)16 == (size_t)memoryAlign(16, 8));
}

