# Keep a gateway on a certificate issued for its names to its own ACME
# account: issue one when there is none for the key it serves on — a new
# gateway build derives a new one — when the one kept does not cover every
# name, came from another directory than SERVER, or lapses within RENEW_DAYS
# or its issuer asks for it to be renewed; then push it, if a table is given.
#
# The ACME account is the gateway's: its key is derived inside the gateway and
# never leaves it. So this job speaks ACME to the issuer itself and has the
# gateway sign each request — of a few kinds, whose content the gateway writes,
# and whose one request for a certificate is for the gateway's own key. The
# issuer validates the names over TLS-ALPN-01 on the port callers reach, and
# the gateway listening there answers: this job arms it with each challenge,
# and every other gateway on the host too, since each answers for any account.
#
#   enclavid-certificate --for CONFIG [--reached CONFIG,…] [--also CONFIG,…] [--push TABLE]
#
# Each CONFIG is a gateway's configuration port, as a URL: `--for` the one the
# certificate is for, `--reached` the ones callers reach — each must take the
# challenge, or the run stops before the issuer validates anything — and
# `--also` the others, armed where they answer. With no `--reached`, one of
# them answering is enough. `--push` gives the table to push the gateway with
# its certificate. Certificates are kept one per key and named by it, so a
# gateway finds its own there whenever it comes to serve on that key.
#
# It exits 3 when the issuer refused to validate the names — on CAA, say — and
# 1 for anything else: the unit tries the others again soon, and a refusal
# only at its next check, since refusals in a row get the account paused.
fail() {
  echo "$*" >&2
  exit 1
}

config="" table="" reached=() also=()
while [ $# -gt 0 ]; do
  case "$1" in
    --for) config=$2 ;;
    --reached) IFS=, read -r -a reached <<<"$2" ;;
    --also) IFS=, read -r -a also <<<"$2" ;;
    --push) table=$2 ;;
    *) fail "enclavid-certificate: what is $1?" ;;
  esac
  shift 2
done
[ -n "$config" ] || fail "enclavid-certificate: --for names the gateway"
dir=/var/lib/enclavid/certificates
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# What every request to the issuer is made with.
issuer=(--max-time 30)
[ -z "$CA_BUNDLE" ] || issuer+=(--cacert "$CA_BUNDLE")
# The whole run within what the unit allows it, ten minutes, with room to say
# why it stopped.
deadline=$((SECONDS + 540))

# Push the gateway its table and its certificate, when there is a table, and
# fail if it did not take the certificate — this run's, or one an earlier run
# issued and a push since left out.
deliver() {
  local pushed
  [ -n "$table" ] || return 0
  pushed=$(enclavid-push-gateway "$config" "$table")
  echo "$pushed"
  case "$pushed" in
    *"issued certificate"*) ;;
    *) fail "the gateway did not take its certificate" ;;
  esac
}

# The gateway's request for exactly these names, signed by the key it holds
# now: what the certificate has to be for.
names=$(
  IFS=,
  echo "${NAMES[*]}"
)
code=""
for _ in $(seq 90); do
  code=$(curl -s -o "$work/request.der" -w '%{http_code}' "$config/csr?names=$names" || true)
  case "$code" in
    200) break ;;
    4?? | 5??) fail "the gateway refused a request for $names: $(cat "$work/request.der")" ;;
  esac
  sleep 1
done
[ "$code" = 200 ] || fail "the gateway's configuration port never answered"

# The key the certificate is for, and the files kept for it.
key=$(openssl req -inform DER -in "$work/request.der" -noout -pubkey)
id=$(openssl pkey -pubin -outform DER <<<"$key" | sha256sum | cut -c1-16)
pem=$dir/$id.pem
# Which directory issued it: one from another — staging's, say — is for the
# same key and names, and no browser takes it.
from=$dir/$id.server

# Read here, and needed only to issue — or to ask the issuer when to renew.
directory=$(curl -sf "${issuer[@]}" "$SERVER" || true)

# The certificate's identifier as ACME Renewal Information writes it: its
# issuer's key identifier and its serial, each in base64url.
certificate_id() {
  local key serial
  key=$(openssl x509 -in "$pem" -noout -ext authorityKeyIdentifier 2>/dev/null | tail -n +2 | head -n 1)
  key=${key//[[:space:]:]/}
  key=${key#keyid}
  serial=$(openssl x509 -in "$pem" -noout -serial | cut -d= -f2)
  [ -n "$key" ] && [ -n "$serial" ] || return 0
  # DER writes a serial in whole bytes, and one whose first bit is set with a
  # zero byte ahead of it.
  [ $((${#serial} % 2)) = 0 ] || serial="0$serial"
  case "$serial" in [89A-Fa-f]*) serial="00$serial" ;; esac
  echo "$(unhexed "$key").$(unhexed "$serial")"
}
unhexed() { printf '%s' "${1^^}" | basenc --base16 -d | basenc --base64url -w 0 | tr -d '='; }

# Whether the issuer asks for the certificate to be renewed by now, where it
# says: ACME Renewal Information.
renewal_asked() {
  local at id window
  at=$(jq -r '.renewalInfo // empty' <<<"$directory")
  id=$(certificate_id)
  [ -n "$at" ] && [ -n "$id" ] || return 1
  window=$(curl -sf "${issuer[@]}" "$at/$id" | jq -r '.suggestedWindow.start // empty') || return 1
  [ -n "$window" ] && [ "$(date -d "$window" +%s)" -le "$(date +%s)" ]
}

reason=""
replaces=""
if [ ! -s "$pem" ]; then
  reason="there is none for its key"
elif [ "$(cat "$from" 2>/dev/null || true)" != "$SERVER" ]; then
  reason="it was not issued from $SERVER"
elif [ "$key" != "$(openssl x509 -in "$pem" -noout -pubkey)" ]; then
  reason="the one kept for its key is for another"
else
  for name in "${NAMES[@]}"; do
    if ! openssl x509 -in "$pem" -noout -checkhost "$name" | grep -q "does match"; then
      reason="it does not cover $name"
      break
    fi
  done
  if [ -z "$reason" ]; then
    if ! openssl x509 -in "$pem" -noout -checkend $((RENEW_DAYS * 86400)) >/dev/null; then
      reason="it lapses within $RENEW_DAYS days"
    elif renewal_asked; then
      reason="its issuer asks for it to be renewed"
    fi
    # Its successor, told to an issuer that takes renewal information, which
    # may then count the order as a renewal. Only of one this account holds:
    # the gateway's own key.
    if [ -n "$reason" ] && [ -n "$(jq -r '.renewalInfo // empty' <<<"$directory")" ]; then
      replaces=$(certificate_id)
    fi
  fi
fi
if [ -z "$reason" ]; then
  echo "the certificate is current"
  deliver
  exit 0
fi

echo "issuing a certificate: $reason"
[ -n "$directory" ] || fail "the ACME directory at $SERVER did not answer"
new_nonce=$(jq -r .newNonce <<<"$directory")
new_account=$(jq -r .newAccount <<<"$directory")
new_order=$(jq -r .newOrder <<<"$directory")
thumbprint=$(curl -sf "$config/acme/account" | jq -r .thumbprint) ||
  fail "the gateway did not give its ACME account"
wanted=$(printf '%s\n' "${NAMES[@]}" | jq -Rsc 'split("\n") | map(select(. != ""))')

# A header of the last response, by name, without the spaces around it; empty
# if it has none.
header() {
  local value
  value=$({ grep -i "^$1:" "$work/head" || true; } | tail -n 1 | cut -d: -f2- | tr -d '\r')
  value=${value#"${value%%[![:space:]]*}"}
  printf '%s' "${value%"${value##*[![:space:]]}"}"
}
# The kind of problem the last response describes, if it describes one.
problem() { jq -r '.type? // empty' "$work/body" 2>/dev/null || true; }

# One request to the issuer: of kind $1, with the values in $2 — its url, and
# the account's kid once there is an account — signed by the gateway and
# posted. Sets `code` and leaves the response in $work/head and $work/body. A
# nonce the issuer refuses is traded for the one it sends back; a response that
# did not arrive whole is asked for again, a few times.
nonce=""
acme() {
  local kind=$1 fields=$2 url failed=0
  url=$(jq -r .url <<<"$fields")
  for _ in $(seq 8); do
    if [ -z "$nonce" ]; then
      curl -sfI "${issuer[@]}" "$new_nonce" >"$work/head" || fail "the issuer at $new_nonce gave no nonce"
      nonce=$(header replay-nonce)
    fi
    jq -c --arg kind "$kind" --arg nonce "$nonce" '{($kind): (. + {nonce: $nonce})}' \
      <<<"$fields" >"$work/asked"
    code=$(curl -s -o "$work/jws" -w '%{http_code}' --data-binary "@$work/asked" \
      "$config/acme/sign" || true)
    [ "$code" = 200 ] || fail "the gateway would not sign a $kind request: $(cat "$work/jws")"
    rm -f "$work/head" "$work/body"
    code=$(curl -s "${issuer[@]}" -D "$work/head" -o "$work/body" -w '%{http_code}' \
      -H 'content-type: application/jose+json' --data-binary "@$work/jws" "$url") || failed=$?
    nonce=$(header replay-nonce)
    if [ "$failed" != 0 ]; then
      echo "the issuer at $url did not answer in full (curl exit $failed); asking again" >&2
      failed=0
      sleep 5
      continue
    fi
    if [ "$code" = 400 ] && [ "$(problem)" = urn:ietf:params:acme:error:badNonce ]; then
      continue
    fi
    return 0
  done
  fail "the issuer at $url gave no usable answer to a $kind request"
}
to() { jq -nc --arg url "$1" --arg kid "$kid" '{url: $url, kid: $kid}'; }

# Arm every gateway given to answer the validator for $1 with key
# authorization $2. One that does not answer — stopped, say — is said and
# passed over: only the one callers reach has to be armed, and a validation
# it did not answer fails on its own.
arm() {
  local gateway armed=0
  jq -nc --arg name "$1" --arg key "$2" '{name: $name, key_authorization: $key}' >"$work/arming"
  for gateway in "${reached[@]}" "${also[@]}"; do
    code=$(curl -s --max-time 10 -o "$work/armed" -w '%{http_code}' -X PUT \
      --data-binary "@$work/arming" "$gateway/acme/tls-alpn-01" || true)
    if [ "$code" = 204 ]; then
      armed=$((armed + 1))
    elif [[ " ${reached[*]} " == *" $gateway "* ]]; then
      fail "the gateway callers reach, at $gateway, would not answer the challenge for $1 ($code): $(cat "$work/armed" 2>/dev/null || true)"
    else
      echo "the gateway at $gateway would not answer the challenge for $1 ($code); passed over" >&2
    fi
  done
  [ "$armed" -gt 0 ] || fail "no gateway would answer the challenge for $1"
}

acme new-account "$(jq -nc --arg url "$new_account" '{url: $url}')"
case "$code" in 200 | 201) ;; *) fail "the issuer refused the gateway's account: $(cat "$work/body")" ;; esac
kid=$(header location)
echo "ACME account: $kid"
caa=$(jq -r '.meta.caaIdentities[0] // empty' <<<"$directory")
[ -z "$caa" ] ||
  echo "  named by the CAA record: issue \"$caa; accounturi=$kid; validationmethods=tls-alpn-01\""

ordering() {
  jq -nc --arg url "$new_order" --arg kid "$kid" --argjson names "$wanted" --arg replaces "$1" \
    '{url: $url, kid: $kid, names: $names} + (if $replaces == "" then {} else {replaces: $replaces} end)'
}
acme new-order "$(ordering "$replaces")"
if [ "$code" != 201 ] && [ -n "$replaces" ]; then
  # The issuer may count it replaced already, by an order a run before this
  # one did not finish.
  echo "the issuer took no renewal of $replaces ($(problem)); ordering afresh"
  acme new-order "$(ordering "")"
fi
[ "$code" = 201 ] || fail "the issuer refused the order: $(cat "$work/body")"
order=$(header location)
cp "$work/body" "$work/order"
# The names are this job's: an order for any others is not validated.
[ "$(jq -c '[.identifiers[].value | ascii_downcase] | sort' "$work/order")" = \
  "$(jq -c 'map(ascii_downcase) | sort' <<<"$wanted")" ] ||
  fail "the order is for other names than $names: $(jq -c .identifiers "$work/order")"

authorizations=()
while IFS= read -r authorization; do
  authorizations+=("$authorization")
done < <(jq -r '.authorizations[]' "$work/order")

# A gateway holds one answer for a name, so the runs for this host's gateways
# validate one at a time: from arming until the order is ready, and within this
# run's deadline — past it, this run stops and is tried again.
exec 9>"$dir/.validating"
patience=$((deadline - SECONDS - 120))
[ "$patience" -ge 1 ] || patience=1
flock -w "$patience" 9 || fail "another gateway's certificate run held the validation throughout"
for authorization in "${authorizations[@]}"; do
  acme post-as-get "$(to "$authorization")"
  [ "$code" = 200 ] || fail "the issuer did not show an authorization: $(cat "$work/body")"
  name=$(jq -r .identifier.value "$work/body")
  status=$(jq -r .status "$work/body")
  case "$status" in
    valid) continue ;;
    pending) ;;
    *)
      echo "the authorization for $name is $status: $(jq -c '[.challenges[]? | .error? // empty]' "$work/body")" >&2
      exit 3
      ;;
  esac
  challenge=$(jq -c 'first(.challenges[] | select(.type == "tls-alpn-01")) // empty' "$work/body")
  [ -n "$challenge" ] || fail "the issuer offers no tls-alpn-01 challenge for $name"
  arm "$name" "$(jq -r .token <<<"$challenge").$thumbprint"
  acme challenge-ready "$(to "$(jq -r .url <<<"$challenge")")"
  [ "$code" = 200 ] || fail "the issuer would not validate $name: $(cat "$work/body")"
done

# Why the order is invalid, as the issuer says: its own problem, and each
# authorization's — or whatever it answered instead. The issuer refused to
# validate, so this exits 3.
invalid() {
  local said
  said="the order is invalid: $(jq -c '.error // {}' "$work/body" 2>/dev/null || true)"
  for authorization in "${authorizations[@]}"; do
    acme post-as-get "$(to "$authorization")"
    said="$said $(jq -c '{name: .identifier.value?, status: .status?, problems: [.challenges[]? | .error? // empty]}' \
      "$work/body" 2>/dev/null || echo "($authorization: HTTP $code)")"
  done
  echo "$said" >&2
  exit 3
}
# Read the order until it is $1, as often as the issuer asks, within the run's
# deadline.
wait_for() {
  local status="" pause until=$deadline
  while [ "$SECONDS" -lt "$until" ]; do
    acme post-as-get "$(to "$order")"
    [ "$code" = 200 ] || fail "the issuer did not show the order: $(cat "$work/body")"
    status=$(jq -r .status "$work/body")
    [ "$status" = "$1" ] && return 0
    [ "$status" = invalid ] && invalid
    # Seconds, or a date (RFC 9110); two seconds if neither.
    pause=$(header retry-after)
    if ! [[ "$pause" =~ ^[0-9]+$ ]]; then
      pause=$(($(date -d "$pause" +%s 2>/dev/null || date +%s) - $(date +%s)))
    fi
    [ "$pause" -ge 1 ] || pause=2
    [ "$pause" -le $((until - SECONDS)) ] || pause=$((until - SECONDS))
    [ "$pause" -ge 1 ] || pause=1
    sleep "$pause"
  done
  fail "the order was still $status, not $1"
}

wait_for ready
exec 9>&-
acme finalize "$(jq -nc --arg url "$(jq -r .finalize "$work/order")" --arg kid "$kid" \
  --argjson names "$wanted" '{url: $url, kid: $kid, names: $names}')"
[ "$code" = 200 ] || fail "the issuer would not finalize the order: $(cat "$work/body")"
wait_for valid
acme post-as-get "$(to "$(jq -r .certificate "$work/body")")"
[ "$code" = 200 ] || fail "the issuer did not give the certificate: $(cat "$work/body")"
install -D -m 0644 "$work/body" "$pem"
printf '%s\n' "$SERVER" >"$from"
echo "installed $pem: $(openssl x509 -in "$pem" -noout -serial -enddate | tr '\n' ' ')"

# What has lapsed is for no gateway any more, and another chain for this key —
# one put here by hand, say — would only stand beside this one.
for kept in "$dir"/*.pem; do
  [ "$kept" != "$pem" ] || continue
  if ! openssl x509 -in "$kept" -noout -checkend 0 >/dev/null 2>&1 ||
    [ "$(openssl x509 -in "$kept" -noout -pubkey 2>/dev/null || true)" = "$key" ]; then
    rm -f "$kept" "${kept%.pem}.server"
  fi
done

if [ -z "$table" ]; then
  echo "kept for the gateway to serve with once it serves on this key"
  exit 0
fi
deliver
