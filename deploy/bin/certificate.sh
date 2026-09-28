# Keep the gateway on a certificate an issuer signed for its names: issue one
# when there is none, when it lapses within RENEW_DAYS, when it is for another
# key than the one the gateway holds now — a new gateway build derives a new
# one — or when it does not cover every name; then push it.
#
#   enclavid-certificate TABLE
table=$1
config=http://127.0.0.1:18448
dir=/var/lib/enclavid/certificates
pem=$dir/gateway.pem
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The gateway's request for exactly these names, signed by the key it holds
# now: what the certificate has to be for.
names=$(IFS=,; echo "${NAMES[*]}")
code=""
for _ in $(seq 90); do
  code=$(curl -s -o "$work/request.der" -w '%{http_code}' "$config/csr?names=$names" || true)
  case "$code" in
    200) break ;;
    4?? | 5??)
      echo "the gateway refused a request for $names: $(cat "$work/request.der")" >&2
      exit 1
      ;;
  esac
  sleep 1
done
[ "$code" = 200 ] || {
  echo "the gateway's configuration port never answered" >&2
  exit 1
}

reason=""
if [ ! -s "$pem" ]; then
  reason="there is none"
elif ! openssl x509 -in "$pem" -noout -checkend $((RENEW_DAYS * 86400)) >/dev/null; then
  reason="it lapses within $RENEW_DAYS days"
elif [ "$(openssl req -inform DER -in "$work/request.der" -noout -pubkey)" != \
  "$(openssl x509 -in "$pem" -noout -pubkey)" ]; then
  reason="it is for another key than the gateway's"
else
  for name in "${NAMES[@]}"; do
    if ! openssl x509 -in "$pem" -noout -checkhost "$name" | grep -q "does match"; then
      reason="it does not cover $name"
      break
    fi
  done
fi
if [ -z "$reason" ]; then
  echo "the certificate is current"
  exit 0
fi

echo "issuing a certificate: $reason"
[ -z "$CA_BUNDLE" ] || export LEGO_CA_CERTIFICATES="$CA_BUNDLE"
lego --accept-tos --email "$EMAIL" --server "$SERVER" --path /var/lib/enclavid/acme \
  --csr "$work/request.der" --tls --tls.port "$LISTEN" run
issued=$(find /var/lib/enclavid/acme/certificates -name '*.crt' ! -name '*.issuer.crt' -newer "$work/request.der" | head -n 1)
[ -n "$issued" ] || {
  echo "the ACME client wrote no certificate" >&2
  exit 1
}
install -D -m 0644 "$issued" "$pem"
echo "installed $(openssl x509 -in "$pem" -noout -serial -enddate | tr '\n' ' ')"

# The push falls back to the gateway's own certificate when it refuses the one
# on disk — right for a push, wrong here: this one was just issued, and a later
# run would find it current and leave it. So a refusal fails this run.
pushed=$(enclavid-push-gateway "$table")
echo "$pushed"
case "$pushed" in
  *"issued certificate"*) ;;
  *)
    echo "the gateway did not take the certificate just issued" >&2
    exit 1
    ;;
esac
