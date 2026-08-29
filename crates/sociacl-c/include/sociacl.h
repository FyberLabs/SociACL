#ifndef SOCIACL_H
#define SOCIACL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sociacl_plane sociacl_plane;
typedef struct sociacl_client sociacl_client;

sociacl_plane *sociacl_plane_new(void);
void sociacl_plane_free(sociacl_plane *plane);

int sociacl_add_person(sociacl_plane *plane, const char *id);
int sociacl_add_agent(sociacl_plane *plane, const char *id);
int sociacl_add_device(sociacl_plane *plane, const char *id);
int sociacl_add_group(sociacl_plane *plane, const char *id);
int sociacl_add_circle(sociacl_plane *plane, const char *id);
int sociacl_add_object(sociacl_plane *plane, const char *id, const char *owner);

/* key: predicate | group | circle | mode */
int sociacl_set_object_property(
    sociacl_plane *plane,
    const char *object,
    const char *key,
    const char *value
);

/* speaker states one side of (from, to, relation).
 * relation: owns | member-of | in-circle | object-group | object-circle | friend | trustee
 */
int sociacl_state_edge(
    sociacl_plane *plane,
    const char *speaker,
    const char *from,
    const char *to,
    const char *relation
);

/* kind: station | principal | device. Oracle accepts only enrolled issuers. */
int sociacl_enroll(sociacl_plane *plane, const char *issuer, const char *kind);

/* Both sides state, then advance past the privilege-up delay. */
int sociacl_jointly_state(
    sociacl_plane *plane,
    const char *from,
    const char *to,
    const char *relation
);

/* Returns 1 allow, 0 deny, -1 error. reason_out receives the predicate id.
 * predicate must match the object's named predicate.
 */
int sociacl_check(
    sociacl_plane *plane,
    const char *action,
    const char *object,
    const char *accessor,
    const char *predicate,
    char *reason_out,
    size_t reason_len
);

/* predicate and attestation may be NULL. NULL predicate uses the object's.
 * attestation is a claim id (identity-live | device-live | station-liveness),
 * not a grant. Unenrolled or forbidden claims fail closed.
 */
int sociacl_check_ex(
    sociacl_plane *plane,
    const char *action,
    const char *object,
    const char *accessor,
    const char *predicate,
    const char *attestation,
    char *reason_out,
    size_t reason_len
);

/* Durable Case C bundle. bytes_out NULL returns the size in written_out.
 * Too-small bytes_out writes the size and returns -1 (reason buffer-too-small).
 */
int sociacl_export_bundle(
    sociacl_plane *plane,
    const char *holder,
    unsigned char *bytes_out,
    size_t bytes_len,
    size_t *written_out,
    char *reason_out,
    size_t reason_len
);

int sociacl_export_bundle_file(
    sociacl_plane *plane,
    const char *holder,
    const char *path,
    char *reason_out,
    size_t reason_len
);

/* Open a client from durable bytes or a file. NULL on error. */
sociacl_client *sociacl_client_open(
    const unsigned char *bytes,
    size_t len,
    char *reason_out,
    size_t reason_len
);
sociacl_client *sociacl_client_open_file(
    const char *path,
    char *reason_out,
    size_t reason_len
);
void sociacl_client_free(sociacl_client *client);

/* Returns 1 allow, 0 deny, -1 error. Same reason rules as sociacl_check. */
int sociacl_client_check(
    sociacl_client *client,
    const char *action,
    const char *object,
    const char *accessor,
    const char *predicate,
    char *reason_out,
    size_t reason_len
);

/* Returns 1 reminted, -1 error. reason_out is "remint" on success. */
int sociacl_client_remint(
    sociacl_client *client,
    const char *object,
    const char *principal,
    char *reason_out,
    size_t reason_len
);

/* Always -1. Silence is not Elect. */
int sociacl_client_elect(
    sociacl_client *client,
    const char *object,
    char *reason_out,
    size_t reason_len
);

#ifdef __cplusplus
}
#endif

#endif
