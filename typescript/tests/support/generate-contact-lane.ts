/**
 * Rebuild vectors/encrypted-discovery/contact-lane.json.
 *
 * From the repository root, with Node 24:
 *
 *   node --experimental-strip-types typescript/tests/support/generate-contact-lane.ts
 *
 * The HKDF input is the pinned contact-lane secret on the genesis keyring,
 * not the disclosed base lane id. The grant ephemeral and nonce are fixed
 * so both language suites match these bytes.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { p256 } from "@noble/curves/nist.js";
import { bytesToHex, hexToBytes, seaPoint } from "../../contract/account-key-seal.ts";
import { importGenesis } from "../../contract/account-key.ts";
import { AccountKeyring } from "../../contract/account-keyring.ts";
import {
  CONTACT_LANE_DOMAIN,
  CONTACT_LANE_GRANT_DOMAIN,
  CONTACT_LANE_GRANT_SIG_DOMAIN,
  CONTACT_LANE_VERSION,
  contactLaneGrantAad,
  contactLaneGrantPlaintext,
  contactLaneGrantSignatureMessage,
  contactLaneInfo,
  deriveContactLane,
  sealContactLaneGrantWith,
} from "../../contract/contact-lane-seal.ts";
import { historyState, type Jwks, type PrincipalId, type ResolutionContext } from "../../ids/src/index.js";

const root = new URL("../../../", import.meta.url);
const ring = JSON.parse(readFileSync(new URL("vectors/encrypted-discovery/account-keyring.json", root), "utf8")) as {
  genesis: {
    laneId: string;
    signingPub: string;
    signingPriv: string;
    epub: string;
    epriv: string;
    contactLaneSecret: string;
  };
  mint: { signingPub: string; epub: string; epriv: string };
  genesisBinding: unknown;
};
const records = JSON.parse(readFileSync(new URL("vectors/ids/records.json", root), "utf8")) as {
  context: {
    jwks: Jwks;
    pinnedIss: string[];
    now: number;
    links: [string, unknown][];
    policy: ResolutionContext["policy"];
    authenticatedAccounts: string[];
  };
};

function scalarPub(n: number): string {
  const bytes = new Uint8Array(32);
  bytes[31] = n & 0xff;
  const pub = seaPoint(bytes);
  bytes.fill(0);
  return pub;
}

const recipient = ring.genesis.signingPub;
const sender = ring.mint.signingPub;
const otherSender = scalarPub(3);
const secret = ring.genesis.contactLaneSecret;
const baseLaneId = ring.genesis.laneId;
const priorSecretHex = "11".repeat(32);
const wrongSecretHex = "22".repeat(32);
const info = contactLaneInfo(recipient, sender);
const swappedInfo = contactLaneInfo(sender, recipient);
const laneId = deriveContactLane(secret, recipient, sender);
const ephemeralScalarHex = `${"00".repeat(31)}0c`;
const nonceHex = "22".repeat(12);
const history = (principal: PrincipalId, at: number, until: number) =>
  records.context.authenticatedAccounts.includes(principal)
    ? { ok: true as const, value: historyState(principal, [], at, until) }
    : { ok: false as const, reason: "missing-history" as const };
const context = {
  jwks: records.context.jwks,
  links: new Map(records.context.links),
  revocations: [],
  now: records.context.now,
  policy: records.context.policy,
  pinnedIss: new Set(records.context.pinnedIss),
  history,
  genesisEpubBindings: [ring.genesisBinding],
} as ResolutionContext;
const keyring = AccountKeyring.fromGenesis(
  importGenesis(baseLaneId, ring.genesis.signingPub, ring.genesis.signingPriv, ring.genesis.epub, ring.genesis.epriv),
  secret,
);
const ephemeral = hexToBytes(ephemeralScalarHex);
const nonce = hexToBytes(nonceHex);
const grant = sealContactLaneGrantWith(keyring, sender, ring.mint.epub, ephemeral, nonce, [], context);
nonce.fill(0);
const ephemeralPub = seaPoint(ephemeral);
const signing = new Uint8Array(Buffer.from(ring.genesis.signingPriv, "base64url"));
const signatureHex = bytesToHex(
  p256.sign(contactLaneGrantSignatureMessage(laneId, recipient, sender, ring.mint.epub, 0), signing, {
    lowS: true,
    prehash: true,
  }),
);
signing.fill(0);
ephemeral.fill(0);
const vector = {
  v: 1,
  family: "contact-lane",
  domain: CONTACT_LANE_DOMAIN,
  version: CONTACT_LANE_VERSION,
  saltHex: "00".repeat(32),
  hash: "HKDF-SHA256",
  outputBytes: 32,
  infoOrder: ["domain", "version", "recipient", "sender"],
  recipient,
  sender,
  otherSender,
  baseLaneId,
  contactLaneSecretHex: secret,
  baseLaneHkdf: deriveContactLane(baseLaneId, recipient, sender),
  infoHex: bytesToHex(info),
  infoLength: info.length,
  laneId,
  swappedInfoHex: bytesToHex(swappedInfo),
  swappedLaneId: deriveContactLane(secret, sender, recipient),
  otherLaneId: deriveContactLane(secret, recipient, otherSender),
  priorSecretHex,
  priorLaneId: deriveContactLane(priorSecretHex, recipient, sender),
  wrongSecretHex,
  wrongSecretLaneId: deriveContactLane(wrongSecretHex, recipient, sender),
  grant: {
    domain: CONTACT_LANE_GRANT_DOMAIN,
    sigDomain: CONTACT_LANE_GRANT_SIG_DOMAIN,
    ephemeralScalarHex,
    nonceHex,
    senderEpub: ring.mint.epub,
    rotationSeq: 0,
    signatureHex,
    plaintextHex: bytesToHex(contactLaneGrantPlaintext(laneId, recipient, 0, signatureHex)),
    aadHex: bytesToHex(contactLaneGrantAad(recipient, sender, ring.mint.epub, ephemeralPub, 0)),
    ciphertextHex: grant.ciphertextHex,
  },
  openError: "lane-grant-rejected",
  generator: "typescript/tests/support/generate-contact-lane.ts",
};
if (vector.laneId === vector.baseLaneHkdf) throw new Error("base lane produced the contact lane");
if (grant.ciphertextHex.includes(secret) || grant.ciphertextHex.includes(baseLaneId)) {
  throw new Error("grant hex contains a lane secret");
}
const out = new URL("vectors/encrypted-discovery/contact-lane.json", root);
writeFileSync(out, `${JSON.stringify(vector, null, 2)}\n`);
console.log(`wrote ${out.pathname}`);
