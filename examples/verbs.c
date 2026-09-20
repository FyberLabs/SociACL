/* Live-plane verbs and network membership through the C FFI.
 *
 * cc -I crates/sociacl-c/include examples/verbs.c -L target/debug -lsociacl -o target/sociacl-verbs-c
 * LD_LIBRARY_PATH=target/debug target/sociacl-verbs-c
 */

#include "sociacl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

int main(void) {
    sociacl_plane *plane = sociacl_plane_new();
    if (!plane) {
        die("plane");
    }
    sociacl_add_person(plane, "alice");
    sociacl_add_person(plane, "bob");
    sociacl_add_person(plane, "mallory");
    sociacl_add_network(plane, "panopticon");
    sociacl_add_object(plane, "panopticon", "alice");
    sociacl_set_object_property(plane, "panopticon", "predicate", "same-network");

    char reason[256];
    if (sociacl_admit_member(plane, "alice", "panopticon", reason, sizeof reason) != 0) {
        die(reason);
    }
    if (sociacl_admit_member(plane, "bob", "panopticon", reason, sizeof reason) != 0) {
        die(reason);
    }

    int bob = sociacl_check(
        plane, "read", "panopticon", "bob", "same-network", reason, sizeof reason
    );
    int mallory = sociacl_check(
        plane, "read", "panopticon", "mallory", "same-network", reason, sizeof reason
    );
    printf("bob member=%d mallory member=%d\n", bob, mallory);

    if (sociacl_remint(plane, "panopticon", "bob", reason, sizeof reason) != 1) {
        die(reason);
    }
    printf("remint %s\n", reason);

    if (sociacl_censure(
            plane, "alice", "panopticon", "bob", "active-sabotage", reason, sizeof reason
        ) != 0) {
        die(reason);
    }
    char audit[256];
    if (sociacl_audit_at(plane, "panopticon", 0, audit, sizeof audit) != 0) {
        die(audit);
    }
    bob = sociacl_check(
        plane, "read", "panopticon", "bob", "same-network", reason, sizeof reason
    );
    printf("after censure bob=%d audit=%s\n", bob, audit);

    sociacl_add_object(plane, "doc", "alice");
    if (sociacl_write_will(
            plane,
            "will secret for object doc\nwritten-by alice\ndestroy if-no-heir keys\n",
            reason,
            sizeof reason
        ) != 0) {
        die(reason);
    }
    if (sociacl_discover(plane, "doc", reason, sizeof reason) != 0) {
        die(reason);
    }
    printf("discover %s\n", reason);
    if (sociacl_destroy(plane, "doc", reason, sizeof reason) != 1) {
        die(reason);
    }
    printf("destroy %s\n", reason);

    sociacl_plane_free(plane);
    return 0;
}
