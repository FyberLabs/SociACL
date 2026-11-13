#include "sociacl.h"
#include <assert.h>
int main(void) {
    const uint8_t empty[] = "{}";
    assert(sociacl_match_settled_epoch(empty, 2) == 0);
    assert(sociacl_match_settled_epoch(NULL, 1) == 0);
    assert(sociacl_match_settled_epoch(empty, 524289) == 0);
    return 0;
}
