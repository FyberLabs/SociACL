import { parseTenantId, mintObjectId, objectSoul, grantSoul, type ObjectId } from 'sociacl-ids';
const tenant = parseTenantId('01234567-89ab-cdef-0123-456789abcdef');
if (!tenant.ok) throw Error(tenant.reason);
const created = mintObjectId('room');
if (!created.ok) throw Error(created.reason);
const object: ObjectId = created.value;
if (!objectSoul('rooms', object).startsWith('s3rch/rooms/room_')) throw Error('consumer failed');
console.log('Installed tarball parsers and declarations work');
// @ts-expect-error Strings cannot be supplied as validated object ids.
const rejectUnparsed: ObjectId = 'raw';
void rejectUnparsed;

if (false) {
  // @ts-expect-error Packed declarations reject all three raw grant components.
  grantSoul('a', 'b', 'c');
}
