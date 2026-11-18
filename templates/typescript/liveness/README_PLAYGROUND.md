# Liveness

The applicant records a short video of a check by turns: their face in an oval
of a size picked at random, then a turn of the head to one side and to the
other, the first side picked at random. The session ends approved when the
applicant followed every guide and the face held in the oval looks live, and
rejected when not. A video not taken within its time limit is asked for once
more, with new values. Nothing is disclosed and nothing is kept: the consumer
learns the decision alone.

It stops a photo or a print held up to the camera, a replay on a screen, and a
video recorded beforehand: the page is given the oval's size and the turns only
once the applicant starts. It does not tell whether the face is the one a
document shows: matching faces is a plugin of its own.

## Files

- `policy.ts` — the policy. The constants at its top are what to tune: the
  attempts, and how live the face must look.
- `world.wit` — what it imports (the plugins below) and exports. It takes no
  props.
- `i18n.json` — its texts: none, since the video's texts are well-known's.

`AGENTS.md` says how a policy works and how to change one.

## Plugins

- `enclavid:well-known` — the guides of a check by turns, and the video step
  that asks them.
- `enclavid:face-detect` — reads the face in the frames of each guide: whether
  it filled the oval and turned as asked.
- `enclavid:face-liveness` — how live the face held in the oval looks.

## To try

- Raise how live the face must look, and see a replay rejected.
- Take the threshold from props, so each session can set its own.
- Send a face that looks barely live to review instead of rejecting it.
