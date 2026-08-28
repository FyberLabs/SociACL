/* 3-node POSIX-shaped group Check via the C FFI.
 * Build after `cargo build -p sociacl-c`:
 *   cc -I crates/sociacl-c/include examples/check.c -L target/debug -lsociacl -o check
 *   LD_LIBRARY_PATH=target/debug ./check
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

static void expect_check(
    sociacl_plane *plane,
    const char *accessor,
    const char *predicate,
    int want
) {
    char reason[64];
    int rc = sociacl_check(
        plane,
        "read",
        "doc",
        accessor,
        predicate,
        reason,
        sizeof reason
    );
    if (rc < 0) {
        fprintf(stderr, "check %s %s error: %s\n", accessor, predicate, reason);
        exit(1);
    }
    if (rc != want) {
        fprintf(
            stderr,
            "check %s %s: got %d want %d reason=%s\n",
            accessor,
            predicate,
            rc,
            want,
            reason
        );
        exit(1);
    }
    printf("%s %s: allowed=%d reason=%s\n", accessor, predicate, rc, reason);
}

int main(void) {
    sociacl_plane *plane = sociacl_plane_new();
    if (!plane) {
        die("sociacl_plane_new");
    }

    must(sociacl_add_person(plane, "alice"), "alice");
    must(sociacl_add_person(plane, "bob"), "bob");
    must(sociacl_add_person(plane, "carol"), "carol");
    must(sociacl_add_group(plane, "ops"), "ops");
    must(sociacl_add_object(plane, "doc", "alice"), "doc");

    must(sociacl_state_edge(plane, "alice", "alice", "ops", "member-of"), "alice member");
    must(sociacl_state_edge(plane, "ops", "alice", "ops", "member-of"), "alice member 2");
    must(sociacl_state_edge(plane, "bob", "bob", "ops", "member-of"), "bob member");
    must(sociacl_state_edge(plane, "ops", "bob", "ops", "member-of"), "bob member 2");
    must(sociacl_state_edge(plane, "alice", "doc", "ops", "object-group"), "doc group");
    must(sociacl_state_edge(plane, "ops", "doc", "ops", "object-group"), "doc group 2");

    expect_check(plane, "alice", "owner", 1);
    expect_check(plane, "bob", "same-group", 1);
    expect_check(plane, "carol", "same-group", 0);

    sociacl_plane_free(plane);
    return 0;
}
