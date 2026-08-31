/* Gun adapter via the C FFI: hint is not a grant. Dest Check is.
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
    sociacl_plane *plane = sociacl_plane_new();
    if (!plane) {
        die("sociacl_plane_new");
    }

    char alice[64];
    char bob[64];
    must(sociacl_gun_user_soul("0xalice", alice, sizeof alice), "alice soul");
    must(sociacl_gun_user_soul("0xbob", bob, sizeof bob), "bob soul");
    must(sociacl_add_person(plane, alice), "alice");
    must(sociacl_add_person(plane, bob), "bob");
    must(sociacl_add_object(plane, "claim-1", alice), "claim");
    must(sociacl_set_object_property(plane, "claim-1", "predicate", "delegate"), "pred");

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

    int rc = sociacl_gun_check(
        plane,
        "see",
        "claim-1",
        bob,
        hint,
        written,
        NULL,
        0,
        reason,
        sizeof reason
    );
    if (rc != 0) {
        fprintf(stderr, "hint alone must deny, got %d %s\n", rc, reason);
        exit(1);
    }
    printf("hint alone: allowed=0\n");

    must(sociacl_delegate(plane, alice, bob, "claim-1", "read", 0), "delegate");
    rc = sociacl_gun_check(
        plane,
        "see",
        "claim-1",
        bob,
        hint,
        written,
        NULL,
        0,
        reason,
        sizeof reason
    );
    if (rc != 1) {
        fprintf(stderr, "dest re-check must allow, got %d %s\n", rc, reason);
        exit(1);
    }
    printf("dest re-check: allowed=1 reason=%s\n", reason);

    rc = sociacl_gun_elect(plane, "claim-1", hint, written, reason, sizeof reason);
    if (rc != -1) {
        die("elect from hint must fail");
    }
    printf("elect from hint: %s\n", reason);

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
    sociacl_plane_free(plane);
    return 0;
}
