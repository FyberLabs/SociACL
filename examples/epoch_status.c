#include "sociacl.h"
#include <assert.h>

int main(void) {
    const uint8_t empty[] = {'{', '}'};
    assert(sociacl_verify_epoch_status(empty, sizeof empty, empty, sizeof empty, 0, 0, 0) == 0);
    assert(sociacl_verify_epoch_status(NULL, 2, empty, sizeof empty, 0, 0, 0) == 0);
    assert(sociacl_verify_epoch_status(empty, sizeof empty, NULL, 2, 0, 0, 0) == 0);
    assert(sociacl_verify_epoch_status(empty, 16385, empty, sizeof empty, 0, 0, 0) == 0);
    return 0;
}
