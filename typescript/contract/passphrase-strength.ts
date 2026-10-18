/**
 * Seal-time passphrase strength.
 *
 * Open does not call this. A copy sealed before the gate, or under a
 * passphrase this gate would now refuse, still opens.
 *
 * The length and hidden-character rules match the Rust checker. The zxcvbn
 * score is advisory: this package and the `zxcvbn` crate can disagree near
 * the threshold. The shared vector pins clear pass and fail rows only.
 *
 * The error carries the score and feedback for the UI. It does not carry
 * the passphrase. Callers must not log the passphrase.
 */
import { ZxcvbnFactory } from "@zxcvbn-ts/core";
import { adjacencyGraphs, dictionary as commonDictionary } from "@zxcvbn-ts/language-common";
import { dictionary as englishDictionary, translations } from "@zxcvbn-ts/language-en";
import { passphraseHidden } from "./unicode16.ts";

const MIN_VISIBLE = 12;
const MIN_SCORE = 3;

const estimator = new ZxcvbnFactory({
  translations,
  graphs: adjacencyGraphs,
  dictionary: { ...commonDictionary, ...englishDictionary },
});

export class RecoveryWeakPassphraseError extends Error {
  readonly score: number;
  readonly warning: string;
  readonly suggestions: readonly string[];

  constructor(score: number, warning: string, suggestions: readonly string[]) {
    super("recovery-weak-passphrase");
    this.name = "RecoveryWeakPassphraseError";
    this.score = score;
    this.warning = warning;
    this.suggestions = suggestions;
  }
}

export function checkRecoveryPassphrase(
  passphrase: Uint8Array,
  principal: string,
  handle?: string,
): void {
  let text: string;
  try {
    // U+FEFF is a passphrase character. The UTF-8 BOM must stay in the text.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(passphrase);
  } catch {
    throw new RecoveryWeakPassphraseError(0, "passphrase must be Unicode text", []);
  }
  const nfc = text.normalize("NFC");
  const chars = [...nfc];
  if (chars.some((ch) => passphraseHidden(ch.codePointAt(0) ?? -1))) {
    throw new RecoveryWeakPassphraseError(0, "passphrase contains a hidden character", []);
  }
  if (chars.length < MIN_VISIBLE) {
    throw new RecoveryWeakPassphraseError(0, "passphrase needs at least 12 visible characters", []);
  }
  const inputs = [principal];
  if (handle && handle.length > 0 && handle.toLowerCase() !== principal.toLowerCase()) {
    inputs.push(handle);
  }
  const result = estimator.check(nfc, inputs);
  if (result.score >= MIN_SCORE) return;
  throw new RecoveryWeakPassphraseError(
    result.score,
    result.feedback.warning ?? "",
    result.feedback.suggestions,
  );
}
