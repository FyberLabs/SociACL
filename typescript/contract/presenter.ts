/**
 * Transport brand for AuthenticatedPresenterChannel.
 *
 * s3r.ch copies docs/s3rch-check.d.ts and reimplements this class. It
 * does not import this file and it does not import the Rust crate.
 * The brand is the ECMAScript private field #channelBrand and the
 * module WeakSet filled by the constructor. accessor and readerPub are
 * frozen. A copy is not in the set. This value is not a grant.
 */

const presenterChannelBrand = Symbol("s3rch-presenter-channel");
const presenterChannelInstances = new WeakSet<AuthenticatedPresenterChannel>();

export class AuthenticatedPresenterChannel {
  readonly accessor: string;
  readonly readerPub: string;
  readonly #channelBrand = presenterChannelBrand;

  private constructor(accessor: string, readerPub: string) {
    this.accessor = accessor;
    this.readerPub = readerPub;
    Object.freeze(this);
    presenterChannelInstances.add(this);
  }

  /**
   * Transport mint. The private constructor is the only other path,
   * and it is not callable outside this class.
   */
  static open(accessor: string, readerPub: string): AuthenticatedPresenterChannel {
    if (accessor.length === 0 || readerPub.length === 0) {
      throw new Error("channel rejected");
    }
    return new AuthenticatedPresenterChannel(accessor, readerPub);
  }

  hasTransportBrand(): boolean {
    try {
      return (
        this.#channelBrand === presenterChannelBrand &&
        presenterChannelInstances.has(this)
      );
    } catch {
      return false;
    }
  }
}

/**
 * Runtime check named by checkPresentedGrant. An object literal fails
 * instanceof. A prototype copy fails the private field and the set.
 * A channel for another principal fails closed.
 */
export function presenterChannelMatches(
  channel: unknown,
  accessor: string,
  enrolledPub: string,
): boolean {
  if (!(channel instanceof AuthenticatedPresenterChannel)) {
    return false;
  }
  if (!channel.hasTransportBrand()) {
    return false;
  }
  return channel.accessor === accessor && channel.readerPub === enrolledPub;
}
