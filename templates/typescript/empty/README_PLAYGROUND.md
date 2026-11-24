# Empty

A policy to write your own on. It asks the applicant nothing and discloses
nothing: the session ends for review at once.

## Files

- `policy.ts` — the policy.
- `world.wit` — what it imports and exports, and its slot: the keys of its
  texts, the fields it may disclose, and its props. WIT has no empty enum or
  record, so each holds a placeholder, `example`, which nothing uses: replace
  it with the policy's own, or leave out what the policy has no use for.
- `i18n.json` — its texts, each language under its tag: the placeholder's.

`AGENTS.md` says how a policy works and how to change one; the other templates
show a policy at work.

## Plugins

None yet. The playground has the WIT of `enclavid:well-known`,
`enclavid:face-detect`, `enclavid:face-age` and `enclavid:face-liveness`:
import an interface in `world.wit` and in `policy.ts`, then Build.

## Props

Set in Sessions, before a run:

```json
{}
```

## To try

- Ask for a selfie, and approve the session once it comes.
- Show a consent screen with a field of your own, and read what it disclosed.
- Take a prop that decides between approved and rejected.
