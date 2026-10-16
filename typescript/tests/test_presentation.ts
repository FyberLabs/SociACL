import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  authorFastMatches,
  epochStatusBytes,
  epochStatusSha256,
  grantCommitmentBytes,
  grantCommitmentHash,
  grantPayloadBytes,
  grantPayloadDigest,
  presenterBindingBytes,
  presenterBindingSha256,
  type EpochStatusBody,
  type GrantPayloadBody,
} from "../contract/canonical.ts";
import {
  AuthenticatedPresenterChannel,
  presenterChannelMatches,
} from "../contract/presenter.ts";

type GrantJson = {
  object: string;
  accessor: string;
  from: number;
  until: number;
  stated: number;
  epoch: number;
  owner: string;
  grantRevision: number;
};

type VectorCase = {
  name: string;
  kind: string;
  sha256?: string;
  encodedLen?: number;
  blinding?: string;
  itemCiphertextDigest?: string;
  nonce?: string;
  commitment?: string;
  audience?: string;
  concatenatedSha256?: string;
  body?: {
    object: string;
    epoch: number;
    revisionId: string;
    accessor: string;
    grantRevision: number;
    stated: number;
    signedAt: number;
    maxAgeMs: number;
    zookie: { object: string; objectVersion: number; snapshotHash: string };
  };
  object?: string;
  epoch?: number;
  revisionId?: string;
  displacedRevisionId?: string;
};

const document = JSON.parse(
  readFileSync(
    new URL("../../vectors/encrypted-discovery/presentation.json", import.meta.url),
    "utf8",
  ),
) as {
  unsaltedPayloadSha256: string;
  grant: GrantJson;
  cases: VectorCase[];
};

function grantBody(item: string): GrantPayloadBody {
  return {
    object: document.grant.object,
    accessor: document.grant.accessor,
    from: document.grant.from,
    until: document.grant.until,
    stated: document.grant.stated,
    epoch: document.grant.epoch,
    owner: document.grant.owner,
    grantRevision: document.grant.grantRevision,
    itemCiphertextDigest: item,
  };
}

test("presentation vectors match the shared fixture", () => {
  assert.ok(document.cases.length >= 7);
  const commitments = new Map<string, string>();
  for (const row of document.cases) {
    if (row.kind === "grantCommitment") {
      assert.equal(typeof row.blinding, "string", row.name);
      assert.equal(typeof row.itemCiphertextDigest, "string", row.name);
      const body = grantBody(row.itemCiphertextDigest as string);
      const bytes = grantCommitmentBytes(row.blinding as string, body);
      const hash = grantCommitmentHash(row.blinding as string, body);
      assert.equal(hash, row.sha256, row.name);
      assert.equal(bytes.length, row.encodedLen, row.name);
      commitments.set(row.name, hash);
    } else if (row.kind === "grantPayload") {
      const body = grantBody(row.itemCiphertextDigest as string);
      const bytes = grantPayloadBytes(body);
      const hash = grantPayloadDigest(body);
      assert.equal(hash, row.sha256, row.name);
      assert.equal(bytes.length, row.encodedLen, row.name);
      assert.equal(hash, document.unsaltedPayloadSha256);
    } else if (row.kind === "presenterBinding") {
      const nonce = row.nonce as string;
      const commitment = row.commitment as string;
      const audience = row.audience as string;
      const bytes = presenterBindingBytes(nonce, commitment, audience);
      const hash = presenterBindingSha256(nonce, commitment, audience);
      assert.equal(hash, row.sha256, row.name);
      assert.equal(bytes.length, row.encodedLen, row.name);
      const concatenated = createHash("sha256")
        .update(`s3rch-presenter-binding-v1${nonce}${commitment}${audience}`)
        .digest("hex");
      assert.equal(concatenated, row.concatenatedSha256, row.name);
      assert.notEqual(hash, concatenated);
    } else if (row.kind === "epochStatus") {
      const body = row.body;
      assert.ok(body, row.name);
      const status: EpochStatusBody = {
        object: body.object,
        epoch: body.epoch,
        revisionId: body.revisionId,
        accessor: body.accessor,
        grantRevision: body.grantRevision,
        stated: body.stated,
        signedAt: body.signedAt,
        maxAgeMs: body.maxAgeMs,
        zookieObject: body.zookie.object,
        zookieVersion: body.zookie.objectVersion,
        zookieSnapshot: body.zookie.snapshotHash,
      };
      const bytes = epochStatusBytes(status);
      const hash = epochStatusSha256(status);
      assert.equal(hash, row.sha256, row.name);
      assert.equal(bytes.length, row.encodedLen, row.name);
    } else if (row.kind === "authorFast") {
      const record = {
        object: row.object as string,
        revisionId: row.revisionId as string,
      };
      assert.equal(authorFastMatches(record, record.object, record.revisionId), true);
      assert.equal(
        authorFastMatches(record, record.object, row.displacedRevisionId as string),
        false,
      );
      assert.equal(row.epoch, 2);
    } else {
      assert.fail(`unknown vector kind ${row.kind}`);
    }
  }
  assert.notEqual(commitments.get("commitment-blind-a"), commitments.get("commitment-blind-b"));
  assert.notEqual(commitments.get("commitment-blind-a"), document.unsaltedPayloadSha256);
});

test("presenter channel brand is unforgeable", () => {
  const pub = "YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y.eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk";
  const real = AuthenticatedPresenterChannel.open("0xbob", pub);
  assert.equal(real instanceof AuthenticatedPresenterChannel, true);
  assert.equal(real.hasTransportBrand(), true);
  assert.equal(Object.isFrozen(real), true);
  assert.equal(presenterChannelMatches(real, "0xbob", pub), true);
  assert.equal(presenterChannelMatches(real, "0xcarol", pub), false);
  assert.equal(presenterChannelMatches(real, "0xbob", "other-pub"), false);
  assert.throws(() => {
    (real as { accessor: string }).accessor = "0xcarol";
  });

  const literal = {
    accessor: "0xbob",
    readerPub: pub,
    hasTransportBrand() {
      return true;
    },
  };
  assert.equal(literal instanceof AuthenticatedPresenterChannel, false);
  assert.equal(presenterChannelMatches(literal, "0xbob", pub), false);

  const copy = Object.assign(Object.create(AuthenticatedPresenterChannel.prototype), {
    accessor: "0xbob",
    readerPub: pub,
  }) as AuthenticatedPresenterChannel;
  assert.equal(copy instanceof AuthenticatedPresenterChannel, true);
  assert.equal(copy.hasTransportBrand(), false);
  assert.equal(presenterChannelMatches(copy, "0xbob", pub), false);
  assert.throws(() => AuthenticatedPresenterChannel.open("", pub));
  assert.throws(() => AuthenticatedPresenterChannel.open("0xbob", ""));
});
