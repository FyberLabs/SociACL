/**
 * Transport brand for AuthenticatedWriterChannel.
 *
 * s3r.ch copies docs/s3rch-check.d.ts and reimplements this class. It
 * does not import this file and it does not import the Rust crate.
 * The brand is the ECMAScript private field #channelBrand and the
 * module WeakSet filled by the constructor. writer and writerPub are
 * frozen. A copy is not in the set. This value is not a grant and it
 * is not a writer pub on the stored row.
 */

const writerChannelBrand = Symbol("s3rch-writer-channel");
const writerChannelInstances = new WeakSet<AuthenticatedWriterChannel>();

const FORBIDDEN = ["itar", "lightiff", "light-iff", "saas"];

export class AuthenticatedWriterChannel {
  readonly writer: string;
  readonly writerPub: string;
  readonly #channelBrand = writerChannelBrand;

  private constructor(writer: string, writerPub: string) {
    this.writer = writer;
    this.writerPub = writerPub;
    Object.freeze(this);
    writerChannelInstances.add(this);
  }

  /**
   * Transport mint. The private constructor is the only other path,
   * and it is not callable outside this class.
   */
  static open(writer: string, writerPub: string): AuthenticatedWriterChannel {
    const name = writer.trim().toLowerCase();
    if (
      writer.length === 0 ||
      writerPub.length === 0 ||
      FORBIDDEN.includes(name) ||
      name.includes("lightiff") ||
      name.includes("itar")
    ) {
      throw new Error("channel rejected");
    }
    return new AuthenticatedWriterChannel(writer, writerPub);
  }

  hasTransportBrand(): boolean {
    try {
      return (
        this.#channelBrand === writerChannelBrand &&
        writerChannelInstances.has(this)
      );
    } catch {
      return false;
    }
  }
}

/**
 * Runtime check for an append channel. An object literal fails
 * instanceof. A prototype copy fails the private field and the set.
 */
export function writerChannelMatches(
  channel: unknown,
  writer: string,
  enrolledPub: string,
): boolean {
  if (!(channel instanceof AuthenticatedWriterChannel)) {
    return false;
  }
  if (!channel.hasTransportBrand()) {
    return false;
  }
  return channel.writer === writer && channel.writerPub === enrolledPub;
}
