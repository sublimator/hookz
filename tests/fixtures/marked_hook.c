#include <stdint.h>
extern int32_t _g(uint32_t, uint32_t);
extern int64_t accept(uint32_t, uint32_t, int64_t);
extern int64_t rollback(uint32_t, uint32_t, int64_t);
extern int64_t state(uint32_t, uint32_t, uint32_t, uint32_t);

int64_t hook(uint32_t r) { //@hook_entry
    _g(1, 1);

    uint8_t key[4] = "test";
    uint8_t val[8];
    int64_t len = state((uint32_t)val, 8, (uint32_t)key, 4); //@state_read

    if (len < 0) //@no_state
        return rollback("missing", 7, -1);

    if (len > 4) //@big_value
        return accept("big", 3, len);

    return accept("ok", 2, 0); //@small_value
}
