/* Live Elect through the C FFI.
 *
 * Keep-operating refuses. Commit waits. A live canceler can stop the
 * ceremony. After the wait, commit installs the named heir.
 *
 * cc -I crates/sociacl-c/include examples/elect.c -L target/debug -lsociacl -o target/sociacl-elect-c
 * LD_LIBRARY_PATH=target/debug target/sociacl-elect-c
 */

#include "sociacl.h"

#include <stdio.h>
#include <stdlib.h>

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static const char *HEIR =
    "will heir-doc for object doc\n"
    "written-by alice\n"
    "cancelable-by executor\n"
    "discover heir bob\n";

int main(void) {
    sociacl_plane *plane = sociacl_plane_new();
    if (!plane) {
        die("plane");
    }
    sociacl_add_person(plane, "alice");
    sociacl_add_person(plane, "bob");
    sociacl_add_person(plane, "executor");
    sociacl_add_object(plane, "doc", "alice");

    char reason[256];
    if (sociacl_write_will(plane, HEIR, reason, sizeof reason) != 0) {
        die(reason);
    }
    if (sociacl_elect(plane, "doc", reason, sizeof reason) == 0) {
        die("live owner must refuse elect");
    }
    printf("elect while alice is live: %s\n", reason);

    sociacl_set_authn(plane, "alice", "gone");
    if (sociacl_elect(plane, "doc", reason, sizeof reason) != 0) {
        die(reason);
    }
    printf("elect started: %s\n", reason);

    if (sociacl_commit_elect(plane, "doc", reason, sizeof reason) == 0) {
        die("commit before wait must fail");
    }
    printf("commit before wait: %s\n", reason);

    uint64_t now = 0;
    sociacl_now(plane, &now);
    sociacl_set_now(plane, now + 10);
    if (sociacl_commit_elect(plane, "doc", reason, sizeof reason) != 0) {
        die(reason);
    }
    printf("commit after wait: %s\n", reason);

    int allowed = sociacl_check(
        plane, "read", "doc", "bob", "owner", reason, sizeof reason
    );
    printf("bob owns doc: allowed=%d reason=%s\n", allowed, reason);

    sociacl_plane_free(plane);
    return allowed == 1 ? 0 : 1;
}
