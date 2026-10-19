# Running the fleet on one host

A minimal way to run every Enclavid guest on one AMD SEV-SNP machine, together
with what the guests reach on the host, as systemd units that
[system-manager](https://github.com/numtide/system-manager) puts in place. It
is built from this commit: the images, the arguments they boot with, the
host-side programs and the gateway's configuration cannot come from different
places.

It is a starting point. It has a default for everything except what only you
can know — your public names, and who may call api as a consumer.

## What you need

- An AMD EPYC host with SEV-SNP enabled in the firmware and in the host kernel
  (`/dev/sev` present, `kvm_amd` loaded with SNP on), and `vhost_vsock` loaded.
- A systemd distribution system-manager supports — Ubuntu, Debian or NixOS.
- Nix, installed multi-user.
- Two EC P-384 keys for the images' ID blocks. They are not a trust root and
  need no custody; see `image/idblock`.

  ```sh
  mkdir keys
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out keys/id.pem
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out keys/author.pem
  ```

## Run it

Describe your host, starting from `example.nix`:

```nix
{
  enclavid = {
    names = {
      verify = "verify.example.com";   # where applicants are sent
      api = "api.example.com";         # where consumers call
    };
    hatch.authorize = "tcp:127.0.0.1:9100";  # your hook, or "none": see below
  };
}
```

Then build it and put it in place:

```sh
nix-build deploy --arg idKeys ./keys --arg configuration ./fleet.nix
sudo ./result/bin/enclavid-switch
```

`nix-build` changes nothing on the host: everything it builds — the images,
QEMU, the host-side programs, the units — goes into the Nix store, and nothing
comes from the distribution's packages. `enclavid-switch` is what puts it in
place: it checks the host can run the fleet, activates the new generation,
starts the fleet, and waits until every unit has settled, naming any that did
not come up.

The check runs on its own too, before anything is changed:

```sh
sudo ./result/bin/enclavid-preflight
```

It looks for SEV-SNP in the processor and in KVM, `/dev/sev`, `/dev/vhost-vsock`
(loading `vhost_vsock` if it can, and the fleet loads it at every boot after),
a QEMU that boots SNP guests, memory for every guest, and the public port free.
What it cannot do is turn any of them on: SEV-SNP is switched on in the
firmware setup and the host kernel.

Every other setting — the variant, the guests' memory, the storage disk's size,
where callers reach the gateway, whether the fleet starts at boot — is an option
in `fleet.nix`, with its default and what it does.

## What runs

The gateway and the release it serves, both `main` and built from this
checkout: the gateway's guest, and api with the four guests it reaches.

| unit | what it is |
| --- | --- |
| `enclavid-main-api`, `…-storage`, `…-compile-worker`, `…-execution-worker`, `…-hatch` | the release's guests |
| `enclavid-main-hatch-net` | the hatch's network interface, on this host's network |
| `enclavid-gateway-main` | the gateway's guest |
| `enclavid-gateway-main-push` | pushes the gateway its configuration after every start of the gateway |
| `enclavid-certificate-main` | keeps the gateway on an issued certificate, with `acme.issue` |
| `enclavid-relay-*` | the links between the guests, from the host into them, from the hatch to your hooks, and from the guests to their NTS servers |
| `enclavid-vcek` | keeps the certificate AMD issues this chip, which api is given at launch |
| `enclavid-fleet.target`, `enclavid-host.target` | all of the above |

Callers reach the gateway on `tcp:0.0.0.0:443` by default. On the host itself,
`127.0.0.1:18445` answers api's health, `127.0.0.1:18447` the gateway's, and
`127.0.0.1:18448` is the gateway's configuration port.

Every local account on the host reaches those ports — and each guest's own
vsock ports directly, with no relay, since Linux puts no permission on a
connection from the host into a guest. Whoever can push the gateway its
configuration decides where it routes and which certificate it presents. So
the host is one trust domain: give it no local account you would not give
root.

```sh
systemctl status 'enclavid-*'
journalctl -u enclavid-gateway-main-push
```

Every link a guest dials on the host takes calls only from the guests meant to
dial it, by their context IDs: storage, both workers and the hatch from their
api alone, api's two surfaces from the gateways, your hooks from the hatch. Any
other guest on the host — one that has broken out of what it runs, say —
reaches nothing through them. The NTS relays below take any guest: they reach
their servers and nothing else.

Each guest's own log is its serial console, in
`/var/log/enclavid/main-ROLE.serial` and `gateway-main.serial`; with
`variant = "debug"` it carries the kernel's console too, and what the guests'
dependencies log.

The hatch is the guest that reaches outside for the others. It fetches what
consumers name — their registries, and wherever a registry's token service or
its redirects lead; their key brokers — and asks your hooks. It is the one
guest with a network interface, carried by `enclavid-main-hatch-net`, a passt
on this host: each connection the hatch opens, TCP or UDP over IPv4, is opened
from this host's network, and none is taken in. Whatever this host reaches, a
consumer can have the hatch fetch — this host's own addresses among them,
though not its loopback — and whatever it reaches sees this host's address.
Names are looked up at this host's own resolver, which the hatch reaches at
one address and its DNS ports, or at `hatch.nameserver`. TLS to what it
fetches ends inside the hatch, against the roots in its measurement, and api
pins the hatch's measurement as it does every guest's it dials — so what the
hatch carries for a session is not this host's to read, but for which
registries and brokers it reaches, and how much. A registry or broker the
consumer writes `http://` is the exception: it is reached in the clear, and api
sends a bearer to none — a session naming one for it is refused.

The passt runs as a user of its own, given `CAP_SYS_ADMIN` to build its own
sandbox where unprivileged users may not make user namespaces; it drops that,
and every other capability, once the sandbox is made.

Every guest keeps its own clock from NTS servers, and starts its application
only once three of them agree. The `enclavid-relay-time-*` units carry that
from this host's network: for each server on a guest's list
(`crates/timesync/servers`), its key exchange on TCP port 4460 and its time
packets on UDP port 123. A guest that cannot reach three of them does not
start. The servers see this host's address, and nothing the relays carry can
be read or changed here — the key exchange ends inside the guest and every
time packet is authenticated — so what this host decides is only whether it
arrives. Every guest on the host shares these units, so each lets one guest
hold at most a few connections at once, lets a quiet one go, and spaces out
the packets one connection sends; and they run as a user of their own, with
no capability and bounded memory.

What lets anyone check a quote api mints is the certificate AMD issues this
chip at its firmware's reported versions, the VCEK. `enclavid-vcek` fetches it
from AMD's key distribution service, from this host's network, once per chip
and versions, and keeps it in `/var/lib/enclavid/vcek`; api is given it at
every launch. A firmware update makes it fetch the next one. With AMD out of
reach, the one already kept serves; with none kept, api does not start. api
checks it against the AMD root compiled in, so what this host keeps decides
only whether api starts.

## Who may call api, and how much

Neither is built in: the hatch asks two hooks, small HTTP services you run on
this host, as `crates/hatch/hooks.openapi.yaml` describes them. Each is reached
through a relay that takes calls from the hatch alone, at the address its
option names.

- `hatch.authorize`, which has no default: `"none"`, or your hook. The hatch
  hands it the `Authorization` header of every call to api, and has back the
  principal the caller is, or a refusal — api answers 401 for a credential the
  hook does not take and 403 for one it takes that may not call. A session is
  kept under its principal, and only calls the hook says are the same
  principal read it back, each with the session's own token. With `"none"`
  anyone who reaches api may call it, no credential is asked for, and a
  session's token alone guards reading it.
- `hatch.limits`, `null` by default for none. Asked at every session created,
  and every warmup a consumer asks for, with its principal: whether it may go
  on, and the terms the session is held to — how large its policy and plugins
  may be, before and after they are compiled; how long it lives; how long a
  pull may take. An applicant's preparing of a session asks nothing. How often
  a consumer may create sessions is the hook's to count, wherever it keeps the
  count — one store for several hosts makes one rate for all of them — and
  when it refuses, api answers 429 with the `Retry-After` it gives. With
  `authorize = "none"` every caller asks as no principal, so such a rate is
  one, shared by all of them: anyone can spend it for everyone. A session
  keeps the terms it was created under, and a term past the fleet's own
  ceiling is the ceiling.

A hook that does not answer within the hatch's `hook-deadline-secs` — a launch
setting, 10 by default — has the call answered 503, to be made again later.
What a hook answers is your word, which the hatch takes as it is: you run it,
and decide who may call in any case. What it cannot do is read a session —
that takes the session's own token, which api gives its creator alone.

## Certificates

The gateway serves on a key derived inside it, under a certificate of its own
that browsers do not trust. For one they do, let the fleet get it from an ACME
certificate authority:

```nix
enclavid.acme.issue = {
  enable = true;
  acceptTerms = true; # the authority's terms of service, which the account is opened under
  # server defaults to Let's Encrypt; its staging directory is worth a first run:
  # server = "https://acme-staging-v02.api.letsencrypt.org/directory";
};
```

The ACME account is the gateway's own: its key is derived inside the gateway,
as the serving key is, and never leaves it. `enclavid-certificate-main` runs the
protocol from the host and has the gateway sign each request; the gateway
writes what each one says, and its one request for a certificate is for the
gateway's serving key. The names are validated over TLS-ALPN-01, on the port
callers already reach, and the gateway answers the validator itself — so
nothing else has to be open, and no DNS credential is needed.

It checks the certificate after every start of the gateway, at every switch
and every six hours, and has it issued again when it lapses
within `renewDays` or the authority asks for it early, when a new gateway build
holds a new key, when the names changed, or when it came from another
directory than `server` — a staging run's is kept no longer than the switch
away from staging. A run that fails is tried again a quarter of an hour later —
except one the authority refused to validate, on CAA say, which waits for the
next check: refusals in a row get the account paused for the names (Let's
Encrypt pauses after about a thousand, and its error links to where to lift
it). A switch says which run failed, and fails nothing for it. Issued chains
are kept in `/var/lib/enclavid/certificates`, one per gateway key and named by
it, and a push carries the ones for the key the gateway serves on. Nothing of
the account is kept on the host.

Every gateway build derives its own keys, so every build that reaches the
gateway is a new certificate for the same names — and Let's Encrypt issues at
most five for one set of names in a week. Its staging directory allows far
more.

### Only the gateway's account

Whoever carries the traffic to port 443 of your names — the host, or a load
balancer in front of it — can pass TLS-ALPN-01 under an account of its own, and
have a certificate issued for a key of its own. A CAA record on each name
(RFC 8657) allows only the gateway's account to be issued one:

```text
verify.example.com.  CAA 0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123; validationmethods=tls-alpn-01"
verify.example.com.  CAA 0 issuewild ";"
```

and the same for the api name. Every run that issues logs the account's URL and
this record for it (`journalctl -u enclavid-certificate-main`).

That URL is the host's word, and the record is there to hold the host too. An
account is named by its URL, which only the authority maps to a key; the
gateway serves the key, at `/.well-known/enclavid-acme-account` beside its
quote. To confirm the URL without trusting the host, from a machine of your
own:

1. Read the key there, over a connection whose key you have checked against
   the gateway's quote.
2. Take a fresh nonce from the authority yourself — the `replay-nonce` of
   `curl -sI https://acme-v02.api.letsencrypt.org/acme/new-nonce`.
3. Have the gateway sign a new-account request with it, on the host:
   `curl -s -d '{"new-account": {"url": "https://acme-v02.api.letsencrypt.org/acme/new-acct", "nonce": "NONCE"}}' http://127.0.0.1:18448/acme/sign > jws`.
4. Check that the `jwk` in its protected header is the key from step 1, and
   send it yourself:
   `curl -si -H 'content-type: application/jose+json' --data-binary @jws https://acme-v02.api.letsencrypt.org/acme/new-acct`.
   The authority checks the signature against that key and answers with the
   URL of the account it holds, in `location`: the one to put in the record.

Checking the quote takes a verifier of SEV-SNP reports and the certificate AMD
issued the chip. Without one, the record rests on the host's word at each
gateway build — and Certificate Transparency is where a certificate for another
key shows: every certificate for your names should carry the key the gateway's
quote binds.

- The account belongs to the gateway build on this machine, and to `server`: a
  new gateway build, the gateway on another machine, or another directory —
  staging's and production's accounts differ — opens a new one. Its orders fail
  on CAA until its record is added beside the old one — meanwhile the gateway
  serves on its own certificate, which browsers refuse — so keep the records'
  TTL short, plan a switch to a new gateway build around the record, and run
  staging before any record is in place. Once the record is in,
  `sudo systemctl restart enclavid-certificate-main`; remove the old one when
  the old build is gone.
- A new gateway build can have all of that done before it serves anyone. The
  fleet runs as many gateways as `enclavid.gateways` names — this checkout's
  `main` by default, where `public.listen` says; a module beside `fleet.nix`
  can name others, each from its own tree and on a public port of its own
  (naming any replaces `main`, unless `main` is named too). Every certificate
  run arms every gateway on the host — the one listening at `public.listen`
  without fail — and each answers the validator for any account, so a new
  build on another port opens its account and has its certificate issued
  through the one callers reach, and can be tried on its own port. Switching
  is giving it `public.listen`. A gateway holds one answer for a name, so the
  runs on one host validate one at a time.
- Put the records on the names, not on the zone apex, unless nothing else under
  it is issued certificates another way.
- Point the names at whatever is in front of the gateway with A/AAAA records,
  never a CNAME to a name its operator controls: a CA reads the CAA records at
  the end of a CNAME.

With any other issuer, ask the gateway for a request — DER, which
`openssl req -inform DER` reads — have it issued, and leave the PEM chain where
the push picks it up, under any name ending in `.pem`:

```sh
curl -o gateway.csr 'http://127.0.0.1:18448/csr?names=verify.example.com,api.example.com'
# … have your issuer sign gateway.csr …
sudo install -D -m 0644 chain.pem /var/lib/enclavid/certificates/gateway.pem
sudo systemctl restart enclavid-gateway-main-push
```

A certificate for another key — a build the gateway no longer runs, or one not
yet switched to — is left out of the push, and so is one that has lapsed, or
covers no name a newer one does not. If what is left does not cover every
name, the gateway takes none of it and serves on its own until a certificate
that does is in place — so replace a file rather than add one beside it.

## Updating, rolling back, removing

Build and switch again. A unit whose definition changed is restarted; one that
did not is left alone. A newer commit whose api changed restarts it, and a
session the previous api build sealed cannot be read by the next one — storage
holds no key; api seals under one bound to its own measurement.

system-manager keeps the previous generations. To go back to the one before:

```sh
P=/nix/var/nix/profiles/system-manager-profiles/system-manager
sudo nix-env -p $P --rollback
sudo $P/bin/activate
sudo systemctl start enclavid-host.target enclavid-fleet.target
```

Activation logs an error that `userborn.service` is not found: system-manager
restarts it unconditionally, and here it is switched off. Nothing depends on it.

To stop everything, `sudo systemctl stop enclavid-fleet.target enclavid-host.target`;
to remove it, run the generation's `deactivate`:

```sh
sudo "$(nix-build deploy -A toplevel --arg idKeys ./keys --arg configuration ./fleet.nix)"/bin/deactivate
```

The storage disk, `/var/lib/enclavid/main/storage.img`, is left in place.

## Not here

Several hosts, a new release run beside the old one while its sessions finish,
and a network for the hatch that reaches nothing of this host — its passt run
in a network of its own — are yours to add, on the blocks in `lib.nix`, which
every module is given as `fleet`, and the units they make.
