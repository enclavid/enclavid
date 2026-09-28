# Put a built fleet in place and bring it up: check the host can run it,
# register it as the current generation, activate it, start the fleet, then wait
# for every Enclavid unit to settle and every health port to answer, and say
# which did not. The activation itself reports a failed unit only in its log,
# and stops waiting after thirty seconds.
#
#   sudo enclavid-switch
[ "$(id -u)" = 0 ] || {
  echo "enclavid-switch changes system units: run it as root" >&2
  exit 1
}

"$PREFLIGHT"
# What failed before this switch — in an earlier generation, perhaps one whose
# units are gone — is not this switch's to report.
systemctl reset-failed 'enclavid-*'
"$TOPLEVEL/bin/register-profile"
"$TOPLEVEL/bin/activate"
# Both, by name: starting a target that is already up starts what it wants
# that is not, but not what a target it wants wants — so a unit new to the
# host side would otherwise wait for the next boot.
systemctl start enclavid-host.target enclavid-fleet.target
# A unit this generation no longer has can fail on its way out — a timer whose
# service's file went first — and is no concern of the fleet now running.
for unit in $(systemctl list-units --all --plain --no-legend 'enclavid-*' | awk '$2 == "not-found" {print $1}'); do
  systemctl reset-failed "$unit"
done

for _ in $(seq 180); do
  systemctl list-units --all --plain --no-legend 'enclavid-*' | grep -q ' activating ' || break
  sleep 1
done

failing() {
  systemctl list-units --all --plain --no-legend --state=failed 'enclavid-*' | awk '{print $1}'
}

answer=""
whole() {
  # The connect inside the timeout as well: to a relay with a full backlog it
  # would otherwise wait out the kernel's SYN retries.
  answer=$(timeout 3 bash -c "cat </dev/tcp/${1%:*}/${1##*:}" 2>/dev/null) || answer=""
  [ -n "$answer" ] && ! grep -q false <<<"$answer"
}

# Then every unit meant to stay up has to be active, and every health port to
# answer whole — no field false — at once. No single look settles it: a guest
# is active as soon as its VM runs, though api can fail and power off seconds
# later, and a push the gateway refuses is tried again and again, since the
# gateway upholds it, so it is as often starting as failed. So they are waited
# for, until a unit has failed or the deadline passes.
deadline=$((SECONDS + 180))
while :; do
  down=()
  for unit in "${UNITS[@]}"; do
    systemctl is-active -q "$unit" || down+=("$unit")
  done
  unwell=()
  for addr in "${HEALTH[@]}"; do
    whole "$addr" || unwell+=("$addr answered ${answer:-nothing}")
  done
  if [ ${#down[@]} -eq 0 ] && [ ${#unwell[@]} -eq 0 ]; then
    break
  fi
  if [ "$SECONDS" -ge "$deadline" ] || [ -n "$(failing)" ]; then
    break
  fi
  sleep 1
done

systemctl list-units --all --plain --no-legend 'enclavid-*' |
  awk '{printf "  %-36s %s %s\n", $1, $3, $4}'
failed=$( { failing; printf '%s\n' "${down[@]}"; } | grep -v '^$' | sort -u || true)
[ -z "$failed" ] || echo "not running: $failed" >&2
for one in "${unwell[@]}"; do
  echo "not serving: $one" >&2
done
if [ -n "$failed" ] || [ ${#unwell[@]} -gt 0 ]; then
  exit 1
fi
