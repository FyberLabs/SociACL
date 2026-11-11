# Fleet and Command report contract

Contract version: `forum-rollup-v1`. Types: `ForumRollupReport` and
`ForumParentLink` in `s3rch-check.d.ts`. Shared cases:
`vectors/mesh/forum-rollups.json`; the TypeScript contract suite executes every
case against signed object/ACL admission. This addresses SociACL #125's consume
surface; the application owns scheduling, publication and display.

A Squad report forwarded to Fleet is a new admitted object under
`s3rch/items/<id>`, with `kind=forum-report` and comma-separated tags
`forum:<destinationForum>,report`. Fleet to Command publishes another object.
Each publication checks the publisher's access to the source and permission to
write at the destination, then admits the new object using the normal signed
owner record and grants. A source grant, parent link or SGH1 handoff cannot
replace any of these checks. A viewer checks the destination report's own ACL
on every read. Looking up a source link requires a separate Check there.

The publisher explicitly selects the snapshot body allowed at the destination;
forwarding must never copy an entire private source implicitly. Source ACL
cancellation does not erase a separately published snapshot. Revoke each
published report's destination grants when that is intended. A current verifier
observes cancellation on its next Check; replayed older grant rows cannot undo
it. Already copied plaintext cannot be recalled.

`sourceForum`, `destinationForum` and `sourceObject` are provenance, not identity
or proof of permission. Forum ids are existing object ids. Parent metadata is
stored at `s3rch/forums/<forumId>/parent`, under the child's ACL. Traversal stops
on cycles, inaccessible nodes or a configured application bound. It never walks
an authority chain, inherits permissions or changes hopcap 1.

An emergency report points to the original need. Opening, resolving or
reopening that need uses its original current ACL and transition rules. A
projection's `stated` controls its display only. Resolving a projection cannot
accept an offer, resolve the source need, admit a new owner, or Elect. A pinned
alarm and an SGH1 hint merely tell a permitted viewer where to re-check.

The shared vectors use separate Squad, Fleet and Command report objects and
independently signed destination grants. Cases cover hint-only denial, source
access without destination access, grant/cancel/replay at Fleet, independent
Command admission, and resolution without owner changes. No live forwarding
acceptance is implied by these contract tests.
