/* Social Light hop frame via the C FFI.
 * Encode, accept, Check, Discover. Elect stays refuse-closed.
 * Build after `cargo build -p sociacl-c`:
 *   cc -I crates/sociacl-c/include examples/social_light.c \
 *     -L target/debug -lsociacl -o target/sociacl-social-light-c
 *   LD_LIBRARY_PATH=target/debug target/sociacl-social-light-c
 */

#include "sociacl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static void must(int rc, const char *what, const char *reason) {
    if (rc != 0) {
        fprintf(stderr, "%s: %s\n", what, reason);
        exit(1);
    }
}

int main(void) {
    sociacl_plane *plane = sociacl_plane_new();
    if (!plane) {
        die("plane");
    }
    must(sociacl_add_person(plane, "alice"), "alice", "");
    must(sociacl_add_person(plane, "bob"), "bob", "");
    must(sociacl_add_object(plane, "doc", "alice"), "doc", "");

    unsigned char pk[SOCIACL_VERIFY_KEY_LEN];
    unsigned char sk[SOCIACL_ISSUER_SECRET_LEN];
    if (sociacl_issuer_keygen(pk, sk) != 0) {
        die("keygen");
    }
    must(sociacl_enroll(plane, "alice", "principal", pk, sizeof pk), "enroll", "");

    char reason[128];
    size_t written = 0;
    if (sociacl_social_light_encode(
            plane,
            "convention-badge",
            sk,
            sizeof sk,
            "alice",
            "bob",
            "identity-live",
            "doc",
            "booth-12",
            NULL,
            0,
            &written,
            reason,
            sizeof reason
        ) != 0) {
        die(reason);
    }
    unsigned char *frame = malloc(written);
    if (!frame) {
        die("malloc");
    }
    if (sociacl_social_light_encode(
            plane,
            "convention-badge",
            sk,
            sizeof sk,
            "alice",
            "bob",
            "identity-live",
            "doc",
            "booth-12",
            frame,
            written,
            &written,
            reason,
            sizeof reason
        ) != 0) {
        die(reason);
    }
    if (written < 4 || memcmp(frame, "SLHP", 4) != 0) {
        die("frame magic");
    }
    must(
        sociacl_social_light_accept(plane, frame, written, reason, sizeof reason),
        "accept",
        reason
    );
    must(
        sociacl_social_light_discover(plane, frame, written, reason, sizeof reason),
        "discover",
        reason
    );
    if (strcmp(reason, "living-person bob share booth-12") != 0) {
        fprintf(stderr, "discover: %s\n", reason);
        exit(1);
    }
    if (sociacl_social_light_elect(plane, "doc", frame, written, reason, sizeof reason) != -1) {
        die("elect must fail");
    }

    free(frame);
    sociacl_plane_free(plane);
    printf("social-light c: badge reported, elect refused\n");
    return 0;
}
