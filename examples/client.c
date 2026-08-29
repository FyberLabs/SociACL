/* Case C client via the C FFI: export a durable bundle, Check, Remint.
 * Elect stays refuse-closed. Live Check still works after export.
 * Build after `cargo build -p sociacl-c`:
 *   cc -I crates/sociacl-c/include examples/client.c -L target/debug -lsociacl -o client
 *   LD_LIBRARY_PATH=target/debug ./client
 */

#include "sociacl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUNDLE_PATH "/tmp/sociacl-client-bundle.bin"

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static void must(int rc, const char *what) {
    if (rc != 0) {
        die(what);
    }
}

static void expect_plane_check(
    sociacl_plane *plane,
    const char *accessor,
    int want
) {
    char reason[64];
    int rc = sociacl_check(
        plane,
        "read",
        "doc",
        accessor,
        "posix-mode",
        reason,
        sizeof reason
    );
    if (rc < 0) {
        fprintf(stderr, "plane check %s error: %s\n", accessor, reason);
        exit(1);
    }
    if (rc != want) {
        fprintf(
            stderr,
            "plane check %s: got %d want %d reason=%s\n",
            accessor,
            rc,
            want,
            reason
        );
        exit(1);
    }
    printf("plane %s: allowed=%d reason=%s\n", accessor, rc, reason);
}

static void expect_client_check(
    sociacl_client *client,
    const char *accessor,
    int want
) {
    char reason[64];
    int rc = sociacl_client_check(
        client,
        "read",
        "doc",
        accessor,
        "posix-mode",
        reason,
        sizeof reason
    );
    if (rc < 0) {
        fprintf(stderr, "client check %s error: %s\n", accessor, reason);
        exit(1);
    }
    if (rc != want) {
        fprintf(
            stderr,
            "client check %s: got %d want %d reason=%s\n",
            accessor,
            rc,
            want,
            reason
        );
        exit(1);
    }
    printf("client %s: allowed=%d reason=%s\n", accessor, rc, reason);
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
    must(sociacl_set_object_property(plane, "doc", "predicate", "posix-mode"), "pred");
    must(sociacl_set_object_property(plane, "doc", "group", "ops"), "group");
    must(sociacl_set_object_property(plane, "doc", "mode", "0640"), "mode");
    must(sociacl_jointly_state(plane, "bob", "ops", "member-of"), "bob member");

    expect_plane_check(plane, "alice", 1);
    expect_plane_check(plane, "bob", 1);
    expect_plane_check(plane, "carol", 0);

    char reason[128];
    if (sociacl_export_bundle_file(plane, "alice", BUNDLE_PATH, reason, sizeof reason) != 0) {
        fprintf(stderr, "export: %s\n", reason);
        exit(1);
    }

    expect_plane_check(plane, "bob", 1);

    sociacl_client *client = sociacl_client_open_file(BUNDLE_PATH, reason, sizeof reason);
    if (!client) {
        fprintf(stderr, "open: %s\n", reason);
        exit(1);
    }

    expect_client_check(client, "alice", 1);
    expect_client_check(client, "bob", 1);
    expect_client_check(client, "carol", 0);

    if (sociacl_client_remint(client, "doc", "bob", reason, sizeof reason) != 1) {
        fprintf(stderr, "remint: %s\n", reason);
        exit(1);
    }
    printf("client remint bob: %s\n", reason);

    if (sociacl_client_elect(client, "doc", reason, sizeof reason) != -1) {
        die("elect must fail closed");
    }
    printf("client elect: refused (%s)\n", reason);

    sociacl_client_free(client);
    sociacl_plane_free(plane);
    remove(BUNDLE_PATH);
    return 0;
}
