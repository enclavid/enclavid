// A policy whose state is a value of its own type rather than bytes.
//
// The runtime calls a policy's `handle` once per event, with the bytes the
// round before returned as its state, and keeps whatever this round returns,
// sealed, for the next. The first round has no state and the event `start`.
// `definePolicy` turns those bytes into the policy's own value and back, so the
// policy never sees them; `withStart` gives the first round a function of its
// own.
//
// The event `E` and the action `A` are whatever the policy's world says, as
// `jco guest-types` writes them; this package names neither.

import * as devalue from "devalue";

/** One round over a state of type `S`, which is `undefined` on the first. */
export type Handle<S, E, A> = (state: S | undefined, event: E) => [S, A];

/** A policy over a state of type `S`, its first round apart from the rest. */
export interface StartAndHandle<S, E, A> {
  /** The session's first round, when there is no state yet. */
  start(): [S, A];
  /** Every round after it, with the state the round before returned. */
  handle(state: S, event: Exclude<E, { tag: "start" }>): [S, A];
}

/** What the runtime calls: the state as the bytes it keeps. */
export interface Reducer<E, A> {
  handle(state: Uint8Array, event: E): [Uint8Array, A];
}

/**
 * A state: an object, a union of objects, or a primitive, whose every field is
 * a {@link StorableValue}. A state that is not does not compile, and the error
 * names the field.
 */
export type Storable<S> = { [K in keyof S]: StorableValue<S[K]> };

/**
 * What a state may hold, which comes back as it went: primitives, BigInt,
 * `undefined`, `Date`, `RegExp`, binary data, and `Map`, `Set`, arrays and
 * objects of these.
 *
 * Not a function, not an object with private members, and not a resource — a
 * `Blob`, a ref a plugin hands out — which lives for one round only and has
 * methods where a state has none. Keep what names it instead, such as a blob's
 * `hash()`, and make it again with `new Blob(hash)`.
 */
export type StorableValue<T> = T extends
  | string
  | number
  | boolean
  | bigint
  | null
  | undefined
  | Date
  | RegExp
  | ArrayBuffer
  | ArrayBufferView
  ? T
  : T extends ReadonlyMap<infer K, infer V>
    ? ReadonlyMap<StorableValue<K>, StorableValue<V>>
    : T extends ReadonlySet<infer U>
      ? ReadonlySet<StorableValue<U>>
      : T extends (...args: never[]) => unknown
        ? never
        : T extends object
          ? // Its public fields alone make a `T` unless it has private ones.
            { [K in keyof T]: T[K] } extends T
            ? { [K in keyof T]: StorableValue<T[K]> }
            : never
          : never;

/**
 * The reducer for `handle`, its state kept with `devalue` in UTF-8. Needs
 * `TextEncoder` and `TextDecoder`.
 */
export function definePolicy<S extends Storable<S>, E, A>(handle: Handle<S, E, A>): Reducer<E, A> {
  return {
    handle(state, event) {
      // Any state, `undefined` included, encodes to some bytes, so no bytes
      // means none yet.
      const [next, action] = handle(state.length === 0 ? undefined : decode<S>(state), event);
      return [encode(next), action];
    },
  };
}

/**
 * One `handle` for `definePolicy` that calls `start` on the event `start`
 * alone. `E` is any event with `{ tag: "start" }` among its cases.
 */
export function withStart<
  S extends Storable<S>,
  E extends ({ tag: "start" } extends E ? { tag: string } : { tag: "start" }),
  A,
>(policy: StartAndHandle<S, E, A>): Handle<S, E, A> {
  // Only the first round has the event `start`, and every round after it has
  // the state the round before returned: an `S`, whatever `S` admits.
  return (state, event) =>
    event.tag === "start"
      ? policy.start()
      : policy.handle(state as S, event as Exclude<E, { tag: "start" }>);
}

/** `state` as the bytes the runtime keeps. */
export function encode<S>(state: S): Uint8Array {
  return new TextEncoder().encode(devalue.stringify(state));
}

/** The state `bytes` hold. */
export function decode<S>(bytes: Uint8Array): S {
  return devalue.parse(new TextDecoder().decode(bytes)) as S;
}
