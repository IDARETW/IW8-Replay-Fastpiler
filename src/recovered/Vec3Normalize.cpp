#include "recovered/ReplayUtilityLayouts.h"
#include <xmmintrin.h>

// Preserve scalar SSE order and the native four-lane XMM0 return. This avoids
// introducing a libm call or assuming a float return from the recovered name.
extern "C" __m128 Vec3Normalize(replay::recovered::Vector3* vector)
{
    const float x = vector->x;
    const float y = vector->y;
    const float z = vector->z;
    const __m128 magnitude = _mm_sqrt_ss(_mm_set_ss((x * x + y * y) + z * z));
    const float length = _mm_cvtss_f32(magnitude);
    const float divisor = _mm_comigt_ss(magnitude, _mm_setzero_ps()) ? length : 1.0f;
    const float inverse = 1.0f / divisor;
    vector->x = x * inverse;
    vector->y = y * inverse;
    vector->z = z * inverse;
    return magnitude;
}
