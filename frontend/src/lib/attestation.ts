// What the page checks of where it runs, in the applicant's browser, against
// keys only AMD holds and against its own address:
//
//   * the gateway's quote, served at `/.well-known/enclavid-attestation` on the
//     same name the page came from — the enclave the name's TLS ends in;
//   * the session's quote, served by api — minted over the session's id when
//     the session was created, by the build that runs it.
//
// These are the checks enclavid's own verifier makes of a quote
// (`crates/attestation/src/snp.rs`), on Milan, the product line it pins. What no
// page can check is which key its own connection uses, so the gateway's quote
// is not tied here to the connection it arrived on: `AttestationModal` says so,
// and where to check it without this page.
//
// Free of the page's own modules, so it runs as it is in Node as well.
import { decode as decodeCbor } from "cborg";
import * as asn1js from "asn1js";
import { Certificate } from "pkijs";

/// AMD's root for Milan, as the `sev` crate ships it: what every chain has to
/// end at. Valid until 2045-10-22.
const ARK_MILAN = `
MIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC
BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS
BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg
Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp
Y2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy
MTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS
BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j
ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg
W41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta
1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2
SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0
60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05
gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg
bKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs
+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi
Qi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ
eTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18
fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j
WhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI
rFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG
KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG
SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI
AWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel
ETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw
STjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK
dHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq
zT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp
KGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e
pmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq
HnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh
3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn
JZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH
CViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4
AFZEAwoKCQ==`;

/// AMD's intermediate for Milan, as the `sev` crate ships it — the one
/// `MILAN_ASK` in `crates/attestation` names. The gateway's quote travels
/// without AMD's chain, and this is the half of it that is the same for every
/// Milan part. Valid until 2045-10-22.
const ASK_MILAN = `
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`;

/// Where AMD issues the certificate of a Milan part's key, for the part and the
/// firmware a report names. Asked only when the gateway runs on another part
/// than the session, whose quote then brings no certificate for it.
const AMD_VCEK = "https://kdsintf.amd.com/vcek/v1/Milan";

/// The platform firmware floor enclavid's verifier holds a report to: every
/// component at least this, as the platform runs now and as it launched the
/// enclave.
const MIN_TCB: Tcb = { bootloader: 4, tee: 0, snp: 29, microcode: 222 };

/// What opens the preimage of a session's report data (`ReportData::hash`).
const SESSION_TAG = new TextEncoder().encode("enclavid/report-data/session\0");

/// The report as the firmware writes it: this many bytes, of which the
/// signature covers those before it.
const REPORT_BYTES = 0x4a0;
const SIGNED_BYTES = 0x2a0;

/// The report's signature algorithm: ECDSA P-384 with SHA-384.
const ECDSA_P384_SHA384 = 1;

/// The guest policy's bits for a migration agent and for debugging.
const POLICY_MIGRATE_MA = 1n << 18n;
const POLICY_DEBUG = 1n << 19n;

/// What a VCEK names, by AMD's extensions: the part it was issued to, the
/// product, and the firmware it was derived at.
const OID_HWID = "1.3.6.1.4.1.3704.1.4";
const OID_PRODUCT = "1.3.6.1.4.1.3704.1.2";
const OID_TCB: Record<keyof Tcb, string> = {
  bootloader: "1.3.6.1.4.1.3704.1.3.1",
  tee: "1.3.6.1.4.1.3704.1.3.2",
  snp: "1.3.6.1.4.1.3704.1.3.3",
  microcode: "1.3.6.1.4.1.3704.1.3.8",
};

/// What is checked, in the order it is: the reports are signed by parts AMD
/// endorses; the gateway's is; the session's was made for this session by the
/// build the page's address names; neither enclave can be read by its host;
/// the firmware is at the floor. How each is put to the applicant is the
/// page's, not this module's.
export type CheckId = "hardware" | "connection" | "build" | "sealed" | "firmware";

/// One thing checked, how it came out, and — in the verifier's own terms —
/// what was found: what held, or why not.
export type Check = { id: CheckId; ok: boolean; detail: string };

/// What a report says, as it is shown, once AMD's chain signs it.
export type Facts = {
  measurement: string;
  chipId: string;
  product: string;
  reportedTcb: string;
  launchTcb: string;
  policy: string;
  version: number;
};

export type Enclave = {
  checks: Check[];
  /// What each report says, for those whose signature held.
  gateway: Facts | null;
  session: Facts | null;
};

/// What the page checks with.
export type Evidence = {
  /// The session's quote as api serves it, or null when it could not be had.
  session: { format: string; quote: string } | null;
  /// The gateway's attestation body as served, or null when it could not be had.
  gateway: Uint8Array | null;
  /// The session the page's address names.
  sessionId: string;
  /// The build the page's address names, or null where it names none.
  build: string | null;
};

/// Check the gateway and the session against AMD and the page's own address.
export async function checkEnclave(evidence: Evidence): Promise<Enclave> {
  const session = await readSession(evidence.session);
  const gateway = await readGateway(evidence.gateway, session.vcek);

  const checks = [
    hardware(gateway, session),
    connection(gateway),
    await ownBuild(session, evidence),
    sealed(gateway, session),
    firmware(gateway, session),
  ];
  return {
    checks,
    gateway: gateway.signed ? facts(gateway) : null,
    session: session.signed ? facts(session) : null,
  };
}

/// One report as read, and whether AMD's chain signs it.
type Read = {
  /// Which report it is, as a sentence about it starts.
  who: "the gateway" | "the session";
  raw: RawReport | null;
  vcek: Certificate | null;
  /// Null when the signature held, else why not.
  unsigned: string | null;
  signed: boolean;
};

async function readSession(served: Evidence["session"]): Promise<Read> {
  const who = "the session";
  const fail = (why: string, raw: RawReport | null = null): Read => ({
    who,
    raw,
    vcek: null,
    unsigned: why,
    signed: false,
  });
  if (!served) return fail("its quote could not be fetched");
  if (served.format !== "sev-snp") {
    return fail(`its quote is of the format ${served.format}, not a processor's`);
  }
  let raw: RawReport;
  let ask: Certificate;
  let vcek: Certificate;
  try {
    const envelope = readEnvelope(decodeCbor(fromBase64(served.quote)));
    raw = readReport(envelope.report);
    ask = Certificate.fromBER(bytes(envelope.ask));
    vcek = Certificate.fromBER(bytes(envelope.vcek));
  } catch (e) {
    return fail(`its quote could not be read: ${(e as Error).message}`);
  }
  const unsigned = await signedBy(raw, ask, vcek);
  return { who, raw, vcek, unsigned, signed: unsigned === null };
}

/// The gateway's quote travels without AMD's chain: the intermediate is the one
/// every Milan part shares, and the part's own certificate is the session's
/// when both run on the same part at the same firmware, else AMD's to give.
async function readGateway(served: Uint8Array | null, sessionVcek: Certificate | null): Promise<Read> {
  const who = "the gateway";
  const fail = (why: string, raw: RawReport | null = null): Read => ({
    who,
    raw,
    vcek: null,
    unsigned: why,
    signed: false,
  });
  if (!served) return fail("its attestation could not be fetched");
  let raw: RawReport;
  let carried: Uint8Array | null;
  try {
    const outer = decodeCbor(served) as Record<string, unknown>;
    if (outer?.format !== "sev-snp") {
      return fail(`its attestation is of the format ${String(outer?.format)}, not a processor's`);
    }
    if (!(outer.quote_blob instanceof Uint8Array)) throw new Error("it carries no quote");
    const inner = decodeCbor(outer.quote_blob) as Record<string, unknown>;
    if (!(inner?.report instanceof Uint8Array)) throw new Error("its quote carries no report");
    raw = readReport(inner.report);
    carried = inner.vcek_der instanceof Uint8Array && inner.vcek_der.length > 0 ? inner.vcek_der : null;
  } catch (e) {
    return fail(`its attestation could not be read: ${(e as Error).message}`);
  }

  let vcek: Certificate;
  try {
    if (carried) {
      vcek = Certificate.fromBER(bytes(carried));
    } else if (sessionVcek && issuedFor(sessionVcek, raw)) {
      vcek = sessionVcek;
    } else {
      vcek = await vcekFromAmd(raw);
    }
  } catch (e) {
    return fail(`AMD's certificate for its processor could not be had: ${(e as Error).message}`, raw);
  }
  const ask = Certificate.fromBER(bytes(fromBase64(ASK_MILAN.replace(/\s+/g, ""))));
  const unsigned = await signedBy(raw, ask, vcek);
  return { who, raw, vcek, unsigned, signed: unsigned === null };
}

/// AMD's certificate of the part `raw` names, at the firmware it reports.
async function vcekFromAmd(raw: RawReport): Promise<Certificate> {
  const spl = (n: number) => String(n).padStart(2, "0");
  const t = raw.reportedTcb;
  const url =
    `${AMD_VCEK}/${hex(raw.chipId)}` +
    `?blSPL=${spl(t.bootloader)}&teeSPL=${spl(t.tee)}&snpSPL=${spl(t.snp)}&ucodeSPL=${spl(t.microcode)}`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`AMD answered ${response.status}`);
  return Certificate.fromBER(new Uint8Array(await response.arrayBuffer()));
}

/// The chain from AMD's root to the part's key, that key's signature on the
/// report, and the key issued to the part the report names, at the firmware it
/// reports. Null when all of it holds, else why not.
async function signedBy(raw: RawReport, ask: Certificate, vcek: Certificate): Promise<string | null> {
  try {
    const ark = Certificate.fromBER(bytes(fromBase64(ARK_MILAN.replace(/\s+/g, ""))));
    if (!(await ask.verify(ark))) return "its intermediate certificate is not AMD's for Milan";
    if (!(await vcek.verify(ask))) return "its processor's key is not endorsed by AMD";
    if (raw.signatureAlgorithm !== ECDSA_P384_SHA384) {
      return `it is signed by algorithm ${raw.signatureAlgorithm}, not ECDSA P-384`;
    }
    if (raw.signingKey !== 0) return "it is signed by a key the host loaded, not the processor's own";
    const key = await crypto.subtle.importKey(
      "spki",
      vcek.subjectPublicKeyInfo.toSchema().toBER(false),
      { name: "ECDSA", namedCurve: "P-384" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      key,
      bytes(raw.signature),
      bytes(raw.signed),
    );
    if (!ok) return "its processor's key did not sign it";
    if (!issuedFor(vcek, raw)) return "its key was issued to another processor, or for other firmware";
    return null;
  } catch (e) {
    return `its certificates could not be checked: ${(e as Error).message}`;
  }
}

/// Whether `vcek` was issued to the part `raw` names, at the firmware it reports.
function issuedFor(vcek: Certificate, raw: RawReport): boolean {
  const hwid = extension(vcek, OID_HWID);
  if (!hwid || hwid.length !== 64 || !same(hwid, raw.chipId)) return false;
  return (Object.keys(OID_TCB) as (keyof Tcb)[]).every(
    (part) => tcbOf(vcek, part) === raw.reportedTcb[part],
  );
}

/// Both reports signed by parts AMD endorses.
function hardware(gateway: Read, session: Read): Check {
  const id = "hardware";
  const failed = [gateway, session].find((r) => !r.signed);
  if (failed) return { id, ok: false, detail: `${failed.who}: ${failed.unsigned}` };
  const chips = [...new Set([gateway, session].map((r) => hex(r.raw!.chipId).slice(0, 12)))];
  const product = productOf(session.vcek!) || "Milan";
  return {
    id,
    ok: true,
    detail: `both reports signed by AMD SEV-SNP parts endorsed up to AMD's root: ${product}, chip ${chips.map((c) => `${c}…`).join(" and ")}`,
  };
}

/// The gateway's report signed: an enclave holds this name's TLS key.
function connection(gateway: Read): Check {
  const id = "connection";
  if (!gateway.signed) return { id, ok: false, detail: `${gateway.who}: ${gateway.unsigned}` };
  return {
    id,
    ok: true,
    detail: `the gateway's report holds, build ${hex(gateway.raw!.measurement).slice(0, 16)}…`,
  };
}

/// The session's report made for this session, by the build the page's address
/// names — the one the gateway lets that address reach.
async function ownBuild(session: Read, evidence: Evidence): Promise<Check> {
  const id = "build";
  if (!session.signed) return { id, ok: false, detail: `${session.who}: ${session.unsigned}` };
  const raw = session.raw!;
  const encoded = new TextEncoder().encode(evidence.sessionId);
  const length = new Uint8Array(8);
  new DataView(length.buffer).setBigUint64(0, BigInt(encoded.length));
  const hash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes(concat(SESSION_TAG, length, encoded))),
  );
  const bound =
    same(raw.reportData.subarray(0, 32), hash) && raw.reportData.subarray(32).every((b) => b === 0);
  if (!bound) return { id, ok: false, detail: "the session's quote was made for another session" };
  const measured = hex(raw.measurement);
  if (!evidence.build) return { id, ok: false, detail: "this page's address names no build" };
  if (measured !== evidence.build) {
    return {
      id,
      ok: false,
      detail: `the processor measured ${measured.slice(0, 16)}…, not the build in the link`,
    };
  }
  return {
    id,
    ok: true,
    detail: `the session's report binds ${evidence.sessionId.slice(0, 12)}… and build ${measured.slice(0, 16)}…, the link's`,
  };
}

/// Neither enclave can be debugged, which would let the host read its memory,
/// nor moved by a migration agent out from under its measurement; and each
/// report made at the most privileged level.
function sealed(gateway: Read, session: Read): Check {
  const id = "sealed";
  const problems: string[] = [];
  for (const r of [gateway, session]) {
    if (!r.signed) {
      problems.push(`${r.who}: not checked, its signature did not hold`);
      continue;
    }
    const raw = r.raw!;
    if (raw.version < 2) problems.push(`${r.who}: report version ${raw.version}`);
    if (raw.vmpl !== 0) problems.push(`${r.who}: made at VMPL ${raw.vmpl}`);
    if ((raw.policy & POLICY_DEBUG) !== 0n) problems.push(`${r.who}: debugging allowed`);
    if ((raw.policy & POLICY_MIGRATE_MA) !== 0n) problems.push(`${r.who}: a migration agent allowed`);
  }
  if (problems.length > 0) return { id, ok: false, detail: problems.join("; ") };
  return { id, ok: true, detail: "both guests: debugging and the migration agent off, VMPL 0" };
}

/// The platform firmware at or above the floor, now and as it launched each
/// enclave.
function firmware(gateway: Read, session: Read): Check {
  const id = "firmware";
  const below = (tcb: Tcb) =>
    (Object.keys(MIN_TCB) as (keyof Tcb)[]).filter((part) => tcb[part] < MIN_TCB[part]);
  const problems: string[] = [];
  for (const r of [gateway, session]) {
    if (!r.signed) {
      problems.push(`${r.who}: not checked, its signature did not hold`);
      continue;
    }
    const raw = r.raw!;
    const parts = [
      ...below(raw.reportedTcb).map((p) => `${p} now`),
      ...below(raw.launchTcb).map((p) => `${p} at launch`),
    ];
    if (parts.length > 0) problems.push(`${r.who}: below the floor, ${parts.join(", ")}`);
  }
  if (problems.length > 0) return { id, ok: false, detail: problems.join("; ") };
  return {
    id,
    ok: true,
    detail: `at or above the floor, now and at launch: ${tcbText(session.raw!.reportedTcb)}`,
  };
}

function facts(read: Read): Facts {
  const raw = read.raw!;
  return {
    measurement: hex(raw.measurement),
    chipId: hex(raw.chipId),
    product: productOf(read.vcek!),
    reportedTcb: tcbText(raw.reportedTcb),
    launchTcb: tcbText(raw.launchTcb),
    policy: `0x${raw.policy.toString(16)}`,
    version: raw.version,
  };
}

/// A platform TCB: the security version of each firmware component.
type Tcb = { bootloader: number; tee: number; snp: number; microcode: number };

function tcbText(tcb: Tcb): string {
  return `bootloader ${tcb.bootloader}, TEE ${tcb.tee}, SNP ${tcb.snp}, microcode ${tcb.microcode}`;
}

/// The report's fields, read by their place in it.
type RawReport = {
  version: number;
  policy: bigint;
  vmpl: number;
  signatureAlgorithm: number;
  signingKey: number;
  reportData: Uint8Array;
  measurement: Uint8Array;
  reportedTcb: Tcb;
  chipId: Uint8Array;
  launchTcb: Tcb;
  signed: Uint8Array;
  /// r then s, each 48 bytes big-endian, as WebCrypto takes them.
  signature: Uint8Array;
};

function readReport(report: Uint8Array): RawReport {
  if (report.length !== REPORT_BYTES) {
    throw new Error(`a report of ${report.length} bytes, not ${REPORT_BYTES}`);
  }
  const view = new DataView(report.buffer, report.byteOffset, report.byteLength);
  // A TCB as Milan lays it out: bootloader, TEE, four reserved, SNP, microcode.
  const tcb = (at: number): Tcb => ({
    bootloader: report[at],
    tee: report[at + 1],
    snp: report[at + 6],
    microcode: report[at + 7],
  });
  // Each of r and s is 72 bytes, little-endian, of which a P-384 value takes
  // the low 48.
  const component = (at: number) => report.slice(at, at + 48).reverse();
  return {
    version: view.getUint32(0x00, true),
    policy: view.getBigUint64(0x08, true),
    vmpl: view.getUint32(0x30, true),
    signatureAlgorithm: view.getUint32(0x34, true),
    signingKey: (view.getUint32(0x48, true) >> 2) & 0b111,
    reportData: report.slice(0x50, 0x90),
    measurement: report.slice(0x90, 0xc0),
    reportedTcb: tcb(0x180),
    chipId: report.slice(0x1a0, 0x1e0),
    launchTcb: tcb(0x1f0),
    signed: report.slice(0, SIGNED_BYTES),
    signature: concat(component(0x2a0), component(0x2e8)),
  };
}

/// A session quote's CBOR envelope: the report, and the intermediate and the
/// part's key that endorse it.
function readEnvelope(decoded: unknown) {
  const envelope = decoded as Record<string, unknown>;
  const field = (name: string) => {
    const value = envelope?.[name];
    if (!(value instanceof Uint8Array) || value.length === 0) {
      throw new Error(`it carries no ${name}`);
    }
    return value;
  };
  return { report: field("report"), ask: field("ask_der"), vcek: field("vcek_der") };
}

/// The bytes of a certificate's extension, as its value holds them.
function extension(cert: Certificate, oid: string): Uint8Array | null {
  const found = cert.extensions?.find((e) => e.extnID === oid);
  return found ? new Uint8Array(found.extnValue.valueBlock.valueHexView) : null;
}

/// A firmware version a VCEK was derived at: the INTEGER its extension holds.
function tcbOf(cert: Certificate, part: keyof Tcb): number | null {
  const value = extension(cert, OID_TCB[part]);
  if (!value) return null;
  const parsed = asn1js.fromBER(bytes(value));
  return parsed.result instanceof asn1js.Integer ? parsed.result.valueBlock.valueDec : null;
}

/// The part's product name, as its VCEK says it.
function productOf(cert: Certificate): string {
  const value = extension(cert, OID_PRODUCT);
  if (!value) return "";
  const parsed = asn1js.fromBER(bytes(value));
  return parsed.result instanceof asn1js.IA5String ? parsed.result.valueBlock.value : "";
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/// `value` with an ArrayBuffer of its own, as WebCrypto and pkijs take one.
function bytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(value);
}

function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

function hex(value: Uint8Array): string {
  return Array.from(value, (b) => b.toString(16).padStart(2, "0")).join("");
}
