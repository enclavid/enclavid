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

# The certificate runs. Only its own gateway's push wants a run, so the
# activation starts one along with a push it starts, and not one new to this
# switch beside a push already up — as when issuance is first turned on; and one
# that failed before this switch is to try again now. A run in progress, or
# waiting a quarter of an hour to run again, is left to it.
mapfile -t certificates < <(systemctl list-unit-files --no-legend 'enclavid-certificate*.service' | awk '{print $1}')
for unit in "${certificates[@]}"; do
  case "$(systemctl show -p ActiveState --value "$unit")" in
    inactive | failed) systemctl start --no-block "$unit" ;;
  esac
done

# Everything starting is waited for — a certificate run too, but not its wait
# to be tried again: it serves nobody meanwhile, see below.
for _ in $(seq 180); do
  systemctl list-units --all --plain --no-legend 'enclavid-*' | awk '
    $3 == "activating" && !($1 ~ /^enclavid-certificate/ && $4 ~ /^auto-restart/) { starting = 1 }
    END { exit !starting }' || break
  sleep 1
done

# The certificate runs aside, which are said below and fail nothing.
failing() {
  systemctl list-units --all --plain --no-legend --state=failed 'enclavid-*' |
    awk '$1 !~ /^enclavid-certificate/ {print $1}'
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
# A certificate run depends on an issuer and CAA records the fleet does not
# control, and the gateway serves on what it holds meanwhile — so one that
# failed is said, and fails nothing.
for unit in "${certificates[@]}"; do
  if [ "$(systemctl show -p Result --value "$unit")" != success ] ||
    [[ "$(systemctl show -p SubState --value "$unit")" == auto-restart* ]]; then
    echo "the last certificate run failed: journalctl -u ${unit%.service}; it runs again on its own, or with sudo systemctl restart ${unit%.service}" >&2
  fi
done
if [ -n "$failed" ] || [ ${#unwell[@]} -gt 0 ]; then
  exit 1
fi
