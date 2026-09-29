# Running the fleet on one host

A minimal way to run every Enclavid guest on one AMD SEV-SNP machine, together
with what the guests reach on the host, as systemd units that
[system-manager](https://github.com/numtide/system-manager) puts in place. It
is built from this commit: the images, the arguments they boot with, the
host-side programs and the gateway's configuration cannot come from different
places.

It is a starting point. It has a default for everything except what only you
can know — your public names, and how your consumers' tokens are checked.

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
    hatch = {
      auth = "oidc";
      issuer = "https://auth.example.com/oidc";
      audience = "https://api.example.com";
    };
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

The gateway, and the release it serves — `main`, built from this checkout: api
and the three guests it reaches.

| unit | what it is |
| --- | --- |
| `enclavid-main-api`, `…-storage`, `…-compile-worker`, `…-execution-worker` | the release's guests |
| `enclavid-gateway` | the gateway's guest |
| `enclavid-gateway-push` | pushes the gateway its configuration after every start of the gateway |
| `enclavid-relay-*` | the links between the guests, and from the host into them |
| `enclavid-hatch` | what the guests reach outside: token checks, registry pulls |
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
journalctl -u enclavid-gateway-push
```

Each guest's own log is its serial console, in
`/var/log/enclavid/main-ROLE.serial` and `gateway.serial`; with
`variant = "debug"` it carries the kernel's console too, and what the guests'
dependencies log.

## Certificates

The gateway serves on a key derived inside it, under a certificate of its own
that browsers do not trust. For one they do, let the fleet get it from an ACME
certificate authority:

```nix
enclavid.acme.issue = {
  enable = true;
  email = "ops@example.com";
  # server defaults to Let's Encrypt; its staging directory is worth a first run:
  # server = "https://acme-staging-v02.api.letsencrypt.org/directory";
};
```

The names are validated over TLS-ALPN-01, on the port callers already reach:
the gateway recognises a validator and carries its connection, unopened, to the
ACME client on the host — so nothing else has to be open, and no DNS credential
is needed. The key never leaves the gateway: the client is handed the gateway's
own request. `enclavid-certificate` checks the certificate after every start of
the gateway and daily, and has it issued again when it lapses within
`renewDays`, when a new gateway build holds a new key, or when the names
changed. The issued chain is kept in `/var/lib/enclavid/certificates`, the ACME
account in `/var/lib/enclavid/acme`.

Every gateway build derives its own key, so every build that reaches the
gateway is a new certificate for the same names — and Let's Encrypt issues at
most five for one set of names in a week. Its staging directory allows far
more.

With any other issuer, ask the gateway for a request — DER, which
`openssl req -inform DER` reads — have it issued, and leave the PEM chain where
the push picks it up:

```sh
curl -o gateway.csr 'http://127.0.0.1:18448/csr?names=verify.example.com,api.example.com'
# … have your issuer sign gateway.csr …
sudo install -D -m 0644 chain.pem /var/lib/enclavid/certificates/gateway.pem
sudo systemctl restart enclavid-gateway-push
```

A certificate the gateway refuses — one for the key of a build it no longer
runs — is left out of the push, and the gateway serves on its own until a new
one is in place.

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

Several hosts, and a new release run beside the old one while its sessions
finish, are yours to add — on the blocks in `lib.nix`, which every module is
given as `fleet`.
