#ifndef SOCIACL_H
#define SOCIACL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SOCIACL_VERIFY_KEY_LEN 32
#define SOCIACL_ISSUER_SECRET_LEN 32
#define SOCIACL_HOLDER_SECRET_LEN 32
#define SOCIACL_SIGNATURE_LEN 64

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
 * relation: owns | member-of | in-circle | object-group | object-circle | friend | trustee | delegate
 */

/* Owner-authorized keep-operating grant. Owner speaks for the object;
 * the call records the delegate accept and advances past the
 * privilege-up delay (same as jointly_state). actions: comma list or
 * compact rwx (read, write, execute). until_tick 0 means no expiry.
 * Expiry is grant expiry, not dead-hand ownership. Owner stays owner.
 */
int sociacl_delegate(
    sociacl_plane *plane,
    const char *owner,
    const char *principal,
    const char *object,
    const char *actions,
    uint64_t until_tick
);

/* Owner-only cancel. Privilege-down is immediate. */
int sociacl_undelegate(
    sociacl_plane *plane,
    const char *owner,
    const char *principal,
    const char *object
);
int sociacl_state_edge(
    sociacl_plane *plane,
    const char *speaker,
    const char *from,
    const char *to,
    const char *relation
);

/* kind: station | principal | device. pubkey is 32-byte Ed25519.
 * NULL or invalid fails closed. The caller keeps the signing key.
 */
int sociacl_enroll(
    sociacl_plane *plane,
    const char *issuer,
    const char *kind,
    const unsigned char *pubkey,
    size_t pubkey_len
);

/* Edge helper. Caller holds sk. The plane does not store it. */
int sociacl_issuer_keygen(unsigned char *pk_out, unsigned char *sk_out);

/* Same 32-byte Ed25519 shape. Used to wrap share keys
 * (XChaCha20-Poly1305) and sign the durable bundle. The file does
 * not store this. */
int sociacl_holder_keygen(unsigned char *pk_out, unsigned char *sk_out);

/* Named will macros onto an object the owner holds. Not a will VM.
 * src is the same language as Will::parse. */
int sociacl_write_will(
    sociacl_plane *plane,
    const char *src,
    char *reason_out,
    size_t reason_len
);

/* Load the will source on an object. src_out NULL returns the size in
 * written_out. Too-small src_out writes the size and returns -1. */
int sociacl_will(
    sociacl_plane *plane,
    const char *object,
    char *src_out,
    size_t src_len,
    size_t *written_out,
    char *reason_out,
    size_t reason_len
);

/* Sign a claim bound to the object's current snapshot. */
int sociacl_sign_claim(
    sociacl_plane *plane,
    const unsigned char *sk,
    size_t sk_len,
    const char *issuer,
    const char *subject,
    const char *claim,
    const char *object,
    unsigned char *sig_out,
    size_t sig_len
);

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
 * not a grant. A present claim requires a 64-byte Ed25519 signature.
 * Unenrolled, unsigned, or forbidden claims fail closed.
 */
int sociacl_check_ex(
    sociacl_plane *plane,
    const char *action,
    const char *object,
    const char *accessor,
    const char *predicate,
    const char *attestation,
    const unsigned char *signature,
    size_t signature_len,
    char *reason_out,
    size_t reason_len
);

/* Durable Case C bundle. holder_sk wraps share keys and signs the frame.
 * NULL or wrong length fails closed. bytes_out NULL returns the size in
 * written_out. Too-small bytes_out writes the size and returns -1
 * (reason buffer-too-small).
 */
int sociacl_export_bundle(
    sociacl_plane *plane,
    const char *holder,
    const unsigned char *holder_sk,
    size_t holder_sk_len,
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
    const unsigned char *holder_sk,
    size_t holder_sk_len,
    char *reason_out,
    size_t reason_len
);

/* Open a client from durable bytes or a file. holder_sk required.
 * NULL on error.
 */
sociacl_client *sociacl_client_open(
    const unsigned char *bytes,
    size_t len,
    const unsigned char *holder_sk,
    size_t holder_sk_len,
    char *reason_out,
    size_t reason_len
);
sociacl_client *sociacl_client_open_file(
    const char *path,
    const unsigned char *holder_sk,
    size_t holder_sk_len,
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

/* Report the bundled will. Does not install an owner.
 * reason_out is "heir <id>", "elect-among <id>", or "stay-secret".
 * Returns 0 on report, -1 on error.
 */
int sociacl_client_discover(
    sociacl_client *client,
    const char *object,
    char *reason_out,
    size_t reason_len
);

/* Erase local key material when the will allows. Does not install an
 * owner. Returns 1 erased, -1 error. reason_out is "destroy" on success.
 */
int sociacl_client_destroy(
    sociacl_client *client,
    const char *object,
    char *reason_out,
    size_t reason_len
);

/* Social Light hop frame (SLHP v1, same wire as socialight-hop).
 * Channel, opaque attestation bytes, optional share-token.
 * FyberLabs/socialight delivers. SociACL verifies. A hop is not a grant.
 *
 * channel: convention-badge | enrolled-station
 * share_token may be NULL.
 * bytes_out NULL returns the size in written_out.
 */
int sociacl_social_light_encode(
    sociacl_plane *plane,
    const char *channel,
    const unsigned char *sk,
    size_t sk_len,
    const char *issuer,
    const char *subject,
    const char *claim,
    const char *object,
    const char *share_token,
    unsigned char *bytes_out,
    size_t bytes_len,
    size_t *written_out,
    char *reason_out,
    size_t reason_len
);

/* Decode and verify. Does not mint an edge. Returns 0, reason is the
 * channel id. */
int sociacl_social_light_accept(
    sociacl_plane *plane,
    const unsigned char *frame,
    size_t frame_len,
    char *reason_out,
    size_t reason_len
);

/* Check using a hop frame as a factor. Returns 1 allow, 0 deny, -1
 * error. predicate may be NULL. */
int sociacl_social_light_check(
    sociacl_plane *plane,
    const char *action,
    const char *object,
    const char *accessor,
    const char *predicate,
    const unsigned char *frame,
    size_t frame_len,
    char *reason_out,
    size_t reason_len
);

/* Remint using an enrolled-station frame. ACL must already name the
 * principal. Returns 1 reminted, -1 error. */
int sociacl_social_light_remint(
    sociacl_plane *plane,
    const char *object,
    const char *principal,
    const unsigned char *frame,
    size_t frame_len,
    char *reason_out,
    size_t reason_len
);

/* Discover from a convention-badge frame. Does not elect.
 * reason_out is "living-person <id>" or "... share <token>".
 * Returns 0 on report, -1 on error. */
int sociacl_social_light_discover(
    sociacl_plane *plane,
    const unsigned char *frame,
    size_t frame_len,
    char *reason_out,
    size_t reason_len
);

/* Always -1. A flash does not Elect. */
int sociacl_social_light_elect(
    sociacl_plane *plane,
    const char *object,
    const unsigned char *frame,
    size_t frame_len,
    char *reason_out,
    size_t reason_len
);

int sociacl_client_social_light_check(
    sociacl_client *client,
    const char *action,
    const char *object,
    const char *accessor,
    const char *predicate,
    const unsigned char *frame,
    size_t frame_len,
    char *reason_out,
    size_t reason_len
);

int sociacl_client_social_light_remint(
    sociacl_client *client,
    const char *object,
    const char *principal,
    const unsigned char *frame,
    size_t frame_len,
    char *reason_out,
    size_t reason_len
);

int sociacl_client_social_light_discover(
    sociacl_client *client,
    const unsigned char *frame,
    size_t frame_len,
    char *reason_out,
    size_t reason_len
);

int sociacl_client_social_light_elect(
    sociacl_client *client,
    const char *object,
    const unsigned char *frame,
    size_t frame_len,
    char *reason_out,
    size_t reason_len
);

/* Gun adapter. Hint is untrusted. Decode does not verify or mint.
 * Destination Check (including delegate) is the grant.
 * s3r.ch reimplements these types in TypeScript and does not import
 * the Rust crate. Surface is Check + delegate. Elect always fails.
 *
 * action: see | read | execute | write. see maps to read.
 * verb and context may be NULL. hint and hop may be NULL / 0.
 */

int sociacl_gun_hint_encode(
    const char *principal,
    const char *target,
    const char *verb,
    const char *context,
    unsigned char *bytes_out,
    size_t bytes_len,
    size_t *written_out,
    char *reason_out,
    size_t reason_len
);

/* Decode. Does not mint. Returns 0. reason is "hint <principal> <target>". */
int sociacl_gun_hint_accept(
    const unsigned char *hint,
    size_t hint_len,
    char *reason_out,
    size_t reason_len
);

/* Returns 1 allow, 0 deny, -1 error. reason is the predicate id. */
int sociacl_gun_check(
    sociacl_plane *plane,
    const char *action,
    const char *claim,
    const char *accessor,
    const unsigned char *hint,
    size_t hint_len,
    const unsigned char *hop,
    size_t hop_len,
    char *reason_out,
    size_t reason_len
);

int sociacl_gun_remint(
    sociacl_plane *plane,
    const char *claim,
    const char *principal,
    char *reason_out,
    size_t reason_len
);

/* Owner undelegate / unstate on the dest object. */
int sociacl_gun_cancel(
    sociacl_plane *plane,
    const char *owner,
    const char *principal,
    const char *claim
);

/* Always -1. Elect from a hint fails. */
int sociacl_gun_elect(
    sociacl_plane *plane,
    const char *claim,
    const unsigned char *hint,
    size_t hint_len,
    char *reason_out,
    size_t reason_len
);

/* Write s3rch/users/<wallet>. Returns 0. */
int sociacl_gun_user_soul(
    const char *wallet,
    char *dst,
    size_t dst_len
);

/* Normalize a permalink. A URL is not a Gun node. */
int sociacl_gun_normalize_url(
    const char *url,
    char *dst,
    size_t dst_len,
    char *reason_out,
    size_t reason_len
);

#ifdef __cplusplus
}
#endif

#endif
