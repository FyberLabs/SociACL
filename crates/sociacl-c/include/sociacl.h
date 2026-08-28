#ifndef SOCIACL_H
#define SOCIACL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sociacl_plane sociacl_plane;

sociacl_plane *sociacl_plane_new(void);
void sociacl_plane_free(sociacl_plane *plane);

int sociacl_add_person(sociacl_plane *plane, const char *id);
int sociacl_add_agent(sociacl_plane *plane, const char *id);
int sociacl_add_device(sociacl_plane *plane, const char *id);
int sociacl_add_group(sociacl_plane *plane, const char *id);
int sociacl_add_circle(sociacl_plane *plane, const char *id);
int sociacl_add_object(sociacl_plane *plane, const char *id, const char *owner);

/* speaker states one side of (from, to, relation).
 * relation: owns | member-of | in-circle | object-group | object-circle
 */
int sociacl_state_edge(
    sociacl_plane *plane,
    const char *speaker,
    const char *from,
    const char *to,
    const char *relation
);

/* Returns 1 allow, 0 deny, -1 error. reason_out receives the predicate id. */
int sociacl_check(
    sociacl_plane *plane,
    const char *action,
    const char *object,
    const char *accessor,
    const char *predicate,
    char *reason_out,
    size_t reason_len
);

#ifdef __cplusplus
}
#endif

#endif
