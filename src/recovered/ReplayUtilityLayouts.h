#pragma once

#include <stddef.h>

// Replay's three-float record has no fourth SIMD lane in memory. The recovered
// normalization routine returns its length in XMM0 with the upper lanes clear.
namespace replay::recovered
{
struct Vector3
{
    float x;
    float y;
    float z;
};

static_assert(sizeof(Vector3) == 12);
static_assert(alignof(Vector3) == 4);
static_assert(offsetof(Vector3, x) == 0);
static_assert(offsetof(Vector3, y) == 4);
static_assert(offsetof(Vector3, z) == 8);
}
