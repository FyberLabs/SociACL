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
import { passphraseHidden } from "./unicode16.ts";

const MIN_VISIBLE = 12;
const MIN_SCORE = 3;

type Estimator = InstanceType<typeof import("@zxcvbn-ts/core").ZxcvbnFactory>;
let estimatorPromise: Promise<Estimator> | undefined;

function loadEstimator(): Promise<Estimator> {
  if (!estimatorPromise) {
    estimatorPromise = Promise.all([
      import("@zxcvbn-ts/core"),
      import("@zxcvbn-ts/language-common"),
      import("@zxcvbn-ts/language-en"),
    ]).then(([{ ZxcvbnFactory }, common, english]) => new ZxcvbnFactory({
      translations: english.translations,
      graphs: common.adjacencyGraphs,
      dictionary: { ...common.dictionary, ...english.dictionary },
    })).catch((error: unknown) => {
      estimatorPromise = undefined;
      throw error;
    });
  }
  return estimatorPromise;
}

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

/** Await this gate before sealing; import failures reject rather than skip the check. */
export async function checkRecoveryPassphrase(
  passphrase: Uint8Array,
  principal: string,
  handle?: string,
): Promise<void> {
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
  const estimator = await loadEstimator();
  const result = estimator.check(nfc, inputs);
  if (result.score >= MIN_SCORE) return;
  throw new RecoveryWeakPassphraseError(
    result.score,
    result.feedback.warning ?? "",
    result.feedback.suggestions,
  );
}
