/* Gun transport via the C FFI. Decode does not verify or establish ownership.
 * Build after `cargo build -p sociacl-c`:
 *   cc -I crates/sociacl-c/include examples/gun.c -L target/debug -lsociacl -o gun
 *   LD_LIBRARY_PATH=target/debug ./gun
 */

#include "sociacl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static void must(int rc, const char *what) {
    if (rc != 0) {
        die(what);
    }
}

int main(void) {
    const char *bob = "untrusted-principal";

    char reason[128];
    size_t written = 0;
    must(
        sociacl_gun_hint_encode(
            bob,
            "claim-1",
            "see",
            NULL,
            NULL,
            0,
            &written,
            reason,
            sizeof reason
        ),
        "hint size"
    );
    unsigned char *hint = malloc(written);
    if (!hint) {
        die("malloc");
    }
    must(
        sociacl_gun_hint_encode(
            bob,
            "claim-1",
            "see",
            NULL,
            hint,
            written,
            &written,
            reason,
            sizeof reason
        ),
        "hint encode"
    );
    must(sociacl_gun_hint_accept(hint, written, reason, sizeof reason), "accept");
    printf("accept: %s\n", reason);

    char url[64];
    must(
        sociacl_gun_normalize_url(
            "https://Example.COM/item/1/#x",
            url,
            sizeof url,
            reason,
            sizeof reason
        ),
        "url"
    );
    printf("url leaf: %s\n", url);

    free(hint);
    return 0;
}
