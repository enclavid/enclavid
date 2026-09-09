# The launch digest, handed to the hardware as a preconditon.
#
# `image/default.nix` computes what a role's digest WILL be and `image/ovmf`
# builds part of what goes into it, but nothing so far connects either to the
# machine that actually starts. The launch line is written by whoever starts the
# guest, and the devices, the vCPU count and the paths on it are not covered by
# anything. That gap has already cost this fleet once — the header of
# `image/default.nix` records launchers disagreeing about a vCPU count while the
# recorded measurement had been taken with a third value.
#
# An SNP ID block closes it from the other side. The block carries an LD field,
# and per the SEV-SNP ABI (56860, SNP_LAUNCH_FINISH) the firmware "checks that
# the LD field of the ID block is equal to GCTX.LD". A launch whose real digest
# is not the number nix computed does not start:
#
#   LAUNCH_FINISH ret=-5 fw_error=11 'Bad measurement'
#
# Verified on hardware. The first run of that experiment failed on the correct
# block too, because the measurement had been computed with one initramfs and
# the guest launched with another — which is the whole point, demonstrated by
# accident.
#
# WHAT THIS IS NOT. It is not a defence against a hostile host: a host that
# wants to run something else omits the block, and the guest starts without one
# (also verified). What stops that is peers pinning the measurement in the
# report. This catches a launch line that does not match its own build, which is
# a mistake rather than an attack, and mistakes here are silent.
#
# The block is applied AFTER the digest exists and is not a measured page, so
# adding it does not move the number it asserts.
#
# The keys are not a trust root here and are not treated as one. Signing is what
# makes the block well-formed; the firmware checks LD against GCTX.LD whoever
# signed it. `docs` and `[[project-snp-id-block-publisher-binding]]` describe
# the OTHER use of the same block — a consumer pinning `author_key_digest` to
# bind a publisher rather than a measurement — and THAT use does need offline
# custody. Do not conflate the two by pointing this at those keys.
{ pkgs, keys }:

measurementHex:

pkgs.runCommand "enclavid-id-block"
{
  nativeBuildInputs = [ pkgs.sev-snp-measure pkgs.coreutils ];
} ''
  # snp-create-id-block takes the digest base64, and `measure` in
  # image/default.nix emits lowercase hex with no trailing newline. basenc
  # decodes base16 uppercase only, hence the tr.
  b64=$(tr 'a-f' 'A-F' < ${measurementHex} | basenc --base16 -d | base64 -w0)

  mkdir -p $out
  snp-create-id-block \
    --measurement "$b64" \
    --idkey ${keys}/id.pem \
    --authorkey ${keys}/author.pem \
    > $out/tool-output

  # The first line is already in QEMU property form: `id-block=..,id-auth=..`.
  head -1 $out/tool-output > $out/props
  grep -q '^id-block=' $out/props || {
    echo "snp-create-id-block changed its output format" >&2
    exit 1
  }
''
