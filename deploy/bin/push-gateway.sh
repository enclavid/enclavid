# Push the gateway its table once its configuration port answers — after every
# start of the gateway, which keeps no configuration across one. Certificates
# an issuer signed are taken from a directory at push time, so a renewal is a
# new file and a push, not a rebuild.
#
#   enclavid-push-gateway TABLE
table=$1
url=http://127.0.0.1:18448/config
certificates=/var/lib/enclavid/certificates
said=$(mktemp)
body=$(mktemp)
trap 'rm -f "$said" "$body"' EXIT

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

pems=()
if [ -d "$certificates" ]; then
  for pem in "$certificates"/*.pem; do
    [ -e "$pem" ] && pems+=("$pem")
  done
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
  # A new gateway build serves on a new key, which the certificates on disk
  # were not issued for: serve on its own certificate rather than not at all.
  echo "the gateway refused the issued certificates: $(cat "$said"); pushing without them" >&2
fi

if push "$table"; then
  echo "pushed"
  exit 0
fi
echo "the gateway refused its configuration: $(cat "$said")" >&2
exit 1
