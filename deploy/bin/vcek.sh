# Keeps the certificate AMD issues this machine's chip at its reported TCB —
# the VCEK, which api is given at launch and its quotes are checked by — where
# the launches read it, `vcek.der` in the unit's state directory. It is
# fetched from AMD's key distribution service once per chip and TCB and kept
# under a name of its address, so a start waits on AMD only after a firmware
# update, and a certificate already kept serves while AMD is out of reach.
#
# Nothing here is trusted: api checks the certificate against the AMD root
# compiled into it and against a report the chip has just made, so what this
# keeps decides only whether api starts.
#
#   STATE_DIRECTORY=/var/lib/enclavid/vcek enclavid-vcek
dir=${STATE_DIRECTORY:?the unit names its state directory}

url=$(snphost show vcek-url)
held=$(printf '%s' "$url" | sha256sum | cut -c1-32).der
if [ ! -s "$dir/$held" ]; then
  curl --fail --silent --show-error --proto '=https' --connect-timeout 10 \
    --max-time 30 --retry 5 --retry-delay 10 --retry-all-errors \
    -o "$dir/$held.new" "$url"
  # A certificate, not whatever answered: an error page kept here would be
  # served to every start until the TCB moves.
  openssl x509 -inform der -noout -in "$dir/$held.new"
  mv "$dir/$held.new" "$dir/$held"
fi
ln -sfn "$held" "$dir/vcek.der.new"
mv -T "$dir/vcek.der.new" "$dir/vcek.der"
echo "vcek: $url"
