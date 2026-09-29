# Push the gateway its table once its configuration port answers — after every
# start of the gateway, which keeps no configuration across one. Certificates
# an issuer signed are taken from a directory at push time, so a renewal is a
# new file and a push, not a rebuild: those for the key the gateway serves on,
# and none for another — a gateway build before this one, or one after it
# whose certificate is issued ahead of its switch.
#
#   enclavid-push-gateway CONFIG TABLE
config=$1
table=$2
url=$config/config
certificates=/var/lib/enclavid/certificates
said=$(mktemp)
body=$(mktemp)
request=$(mktemp)
trap 'rm -f "$said" "$body" "$request"' EXIT

# Push $1: returns 0 if the gateway took it and 1 if it refused it.
push() {
  for _ in $(seq 90); do
    code=$(curl -s -o "$said" -w '%{http_code}' --max-time 5 -X PUT \
      --data-binary "@$1" "$url" || true)
    case "$code" in
      204) return 0 ;;
      4?? | 5??) return 1 ;;
    esac
    sleep 1
  done
  echo "the gateway's configuration port never answered" >&2
  exit 1
}

# The key the gateway serves on, as its request for a certificate over one of
# the names says: the port answers before any push, as long as a name is
# asked for.
key=""
name=$(jq -r '.names | keys | first // empty' "$table")
if [ -n "$name" ] && [ -d "$certificates" ]; then
  for _ in $(seq 90); do
    code=$(curl -s -o "$request" -w '%{http_code}' --max-time 5 "$config/csr?names=$name" || true)
    [ "$code" = 000 ] || break
    sleep 1
  done
  [ "$code" != 200 ] || key=$(openssl req -inform DER -in "$request" -noout -pubkey)
fi

# Of the chains for that key, a set the gateway takes: none lapsed, and each
# the first to cover one of the names — the gateway answers a name with the
# first chain that covers it, and refuses a set holding a chain that answers
# for none. The newest go first.
pems=()
if [ -n "$key" ]; then
  covered=()
  while read -r _ pem; do
    fresh=no
    while read -r served; do
      [ -n "$served" ] || continue
      case " ${covered[*]} " in *" $served "*) continue ;; esac
      if [[ "$(openssl x509 -in "$pem" -noout -checkhost "$served" 2>/dev/null)" == *"does match"* ]]; then
        covered+=("$served")
        fresh=yes
      fi
    done < <(jq -r '.names | keys[]' "$table")
    if [ "$fresh" = yes ]; then
      pems+=("$pem")
    fi
  done < <(
    for pem in "$certificates"/*.pem; do
      [ -e "$pem" ] || continue
      [ "$(openssl x509 -in "$pem" -noout -pubkey 2>/dev/null || true)" = "$key" ] || continue
      openssl x509 -in "$pem" -noout -checkend 0 >/dev/null 2>&1 || continue
      echo "$(date -d "$(openssl x509 -in "$pem" -noout -enddate | cut -d= -f2)" +%s) $pem"
    done | sort -rn
  )
fi

if [ ${#pems[@]} -gt 0 ]; then
  # Each file as one string, read by jq rather than passed to it: a chain
  # begins with dashes, which jq takes for an option wherever it stands.
  for pem in "${pems[@]}"; do jq -Rs . "$pem"; done |
    jq -s --slurpfile table "$table" '$table[0] + {certificates: .}' >"$body"
  if push "$body"; then
    echo "pushed, with ${#pems[@]} issued certificate(s)"
    exit 0
  fi
  # A set that covers not every name, or one the gateway refuses for any other
  # reason: serve on its own certificate rather than not at all.
  echo "the gateway refused the issued certificates: $(cat "$said"); pushing without them" >&2
fi

if push "$table"; then
  echo "pushed"
  exit 0
fi
echo "the gateway refused its configuration: $(cat "$said")" >&2
exit 1
