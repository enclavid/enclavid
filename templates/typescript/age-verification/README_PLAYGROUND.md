# Age verification

The applicant takes a selfie; the policy reads the age of the face in it; the
session ends approved when that age is at least the consumer's `min-age`, and
rejected when it is not. A selfie whose face does not fill the oval — half a
face, a face off to the side, two faces — is asked for again. Nothing is
disclosed and nothing is kept: the consumer learns the decision alone.

## Files

- `policy.ts` — the policy.
- `world.wit` — what it imports (the plugins below and its props) and exports.
- `i18n.json` — its texts: none, since the selfie's texts are well-known's.

`AGENTS.md` says how a policy works and how to change one.

## Plugins

- `enclavid:well-known` — the selfie's capture spec, with the oval the page
  takes it in.
- `enclavid:face-detect` — reads the face against that oval: whether it fills
  it, the only face there.
- `enclavid:face-age` — reads the face's age.

## Props

Set in Sessions, before a run:

```json
{ "min-age": 18 }
```

A face's age is an estimate, so a check of 18 may ask for more.

## To try

- Run it with `min-age` at 60, and see it rejected.
- Send an age close to the limit to review instead of rejecting it.
- Ask for a passport before the selfie.
