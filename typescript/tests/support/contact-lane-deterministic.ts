/**
 * Deterministic contact-lane grant wrapper for tests and the vector generator.
 * Not imported by typescript/src and not listed in the package exports.
 * The production module does not re-export these.
 */
export {
  CONTACT_LANE_DOMAIN,
  CONTACT_LANE_GRANT_DOMAIN,
  CONTACT_LANE_GRANT_SIG_DOMAIN,
  CONTACT_LANE_VERSION,
  contactLaneGrantAad,
  contactLaneGrantPlaintext,
  contactLaneGrantSignatureMessage,
  contactLaneInfo,
  sealContactLaneGrantWith,
} from "../../contract/contact-lane-seal.ts";
