# KYC

The applicant takes a photo of their passport, then a selfie unless the
consumer turned it off, then sees a consent screen with the fields the
consumer receives if they accept. The session ends approved on accept and
rejected on decline.

The template shows the flow, and is not a whole KYC. It does not:

- read the passport: the fields are fixed sample values;
- check that the passport is genuine, not forged or altered;
- match the selfie's face to the passport's photo;
- screen the applicant against sanctions lists.

## Files

- `policy.ts` — the policy.
- `world.wit` — what it imports and exports, and its slot: the keys of its
  texts, the fields it may disclose, and its props.
- `i18n.json` — its texts, each language under its tag.

`AGENTS.md` says how a policy works and how to change one.

## Plugins

- `enclavid:well-known` — the capture specs of the passport and the selfie, and
  the labels of the disclosed fields.

## Props

Set in Sessions, before a run:

```json
{ "selfie": true }
```

`false` skips the selfie.

## To try

- Run it with `selfie` off, and see the selfie skipped.
- Change the consent screen's reason, in English and another language.
- Ask for an ID card instead of the passport.
