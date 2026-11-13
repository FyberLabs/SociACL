#include "sociacl.h"
#include <assert.h>

int main(void) {
    const uint8_t empty[] = "{}";
    assert(sociacl_verify_epoch_manifest(empty, 2, empty, 2) == 0);
    assert(sociacl_verify_epoch_manifest(NULL, 1, empty, 2) == 0);
    assert(sociacl_verify_epoch_manifest(empty, 2, NULL, 1) == 0);
    assert(sociacl_verify_epoch_manifest(empty, 65537, empty, 2) == 0);
    return 0;
}
