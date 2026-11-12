# agent-safehouse-eval

An eval for [Agent Safehouse](https://agent-safehouse.dev/). It turns the
sandbox's security claims into a battery of ~200 unique probe commands with
expectations, runs them inside `safehouse bash`, and reports which claims
held. One probe per unique signal: the mechanism is the variable, the target
is representative.

## What it does

1. Builds a simulated system inside this package: a fake home directory, a fake
   project workdir, and a fake sibling repo, all seeded with fake credentials.
2. Renders Safehouse's policy against the fake home by launching with `HOME`
   pointed at it, and compiles the override (`profiles/override.sb`) with it.
   A policy that cannot load fails here, before anything runs.
3. Loads the override via `--append-profile`: credential denials (env files at
   any depth, agent token stores, `.claude.json`, `opencode.db`), read grants
   for agent config, and network rules.
4. Runs the battery (`probes/battery.sh`) inside `safehouse bash`: read attempts
   on every protected path class, interpreter-level reads (python, perl, node,
   osascript, dd, xxd, ...), copy-out escapes (cp, dd, ditto, tar, rsync, mv),
   symlink and hardlink tricks, path traversal, IPC to keychain/launchd/logd/
   Spotlight, network probes, and grant checks that must keep working.
   Names read as the action performed, e.g. `python3 reads ssh key` or
   `cat /etc/master.passwd`.
5. Spot-checks system trees (`tools/gen-spot.sh`): two sampled paths per tree,
   expectation, and operation, instead of a full walk. The trees' policy is
   uniform, so the sample tests the same signal.
6. Checks host-side escape artifacts: files written outside the sandbox, a
   changed crontab, a `defaults` write that landed, key bytes inside "stolen"
   copies.
7. Runs the hostname allowlist stage (`tools/allowlist-eval.sh`, `make
   allowlist`) separately: it records the host/IP/CIDR rule forms Seatbelt
   rejects, then measures a loopback CONNECT proxy as the only shape that
   filters by hostname.
8. Prints `PASS/FAIL` per probe and a final verdict. Exit code `0` means every
   claim held.

## Usage

```bash
make eval                     # run the eval, keep the rig for inspection
make eval version=0.14.0      # label the run with a version
make eval-clean               # run, then move the rig into rig/.trash/
make report version=0.13.0    # regenerate the CSV report from rig/results.txt
make allowlist                # hostname allowlist stage (loopback proxy)
make check                    # syntax-check the shell scripts
```

Results land in `rig/results.txt` and a CSV report in
`reports/eval-report-<version>.csv`, one file per Safehouse version so results
accumulate across versions in git. The version is the one passed to `--version`,
or the installed one detected from `safehouse --version`. Each row is a probe:
the command that ran, the result, and what was observed.

## What it never does

- Never touches your real home directory. The fake home is `rig/home`, inside
  the package, and that is the only home the sandbox sees.
- Never uses your real username. Username-shaped probes use a random fake
  identity generated per run.
- Never writes a real credential file. Every "secret" in the rig is fake.
- Never puts your real username in an output. Emitted paths are package-relative
  (`rig/...`, `reports/...`), the real home folds into `~`, and the run fails if
  the report still contains your username after sanitization.
- Never prints secret-shaped content into the report. Dump-style probes
  (`dscacheutil`, `nvram`, `lsof`, `mdfind`, `crontab`) output counts only.

## Requirements

- macOS
- [Agent Safehouse](https://agent-safehouse.dev/) on PATH
  (`brew install eugene1g/safehouse/agent-safehouse`)
- `python3` for the allowlist stage, and a free port 18090 for its proxy

No API keys, no agent install, no network credentials.

## Reading the results

| Expectation | Meaning |
| --- | --- |
| `deny` | The command must fail or return a denial error |
| `allow` | The command must succeed, the boundary must stay usable |
| `nodata` | The command may run but must return zero bytes of content |
| `enoent` | Must report the file missing, not a permission error |
| `any` | Both outcomes pass, the probe records behavior |

A `FAIL` means either a Safehouse regression, a new macOS version with different
behavior, or a broken probe. The failure line shows which, with the observed
output.

Known info-level surfaces the eval records as `any`: `nvram`, `dscacheutil`
user records, `~/.ssh` file name listing, `~/.gitconfig` / `~/.ssh/config`
contents, keychain search errors, and the sampled system trees that fail or
succeed per path. None of them carries a credential.

### Network posture (as measured)

Egress is closed with one rule per operation, appended after Safehouse's
generated `(allow network-outbound (remote ip))`:

```
(deny network-outbound (remote ip))
(deny network-bind     (local  ip))
(deny network-inbound  (local  ip))
```

Measured inside `safehouse bash` on 0.13.0 and 0.13.1: TCP 22, plaintext HTTP
80, UDP 443, ICMP, and direct-IP DNS all fail; TCP 443 works, so OpenCode and
websearch run; hostname lookups work through the system resolver socket
(mDNSResponder). Raw DNS clients (`dig`, `host`) fail because they bind their
own UDP socket, and nothing can listen on a port, local dev servers included.
A `(local ip "localhost:*")` re-allow matches every bind address, including
`0.0.0.0`, so it re-opens bind when added.

TLS also depends on chain building: a certificate whose root is missing from
`/etc/ssl/cert.pem` fails verification inside the sandbox because the system
trust store is unreachable, so the any-HTTPS-host probe uses
`captive.apple.com` rather than `example.com`.

### Hostname allowlists (as measured)

A network rule accepts `*` or `localhost` as the host. A hostname, literal IP,
or CIDR is rejected when the policy renders:

```
sandbox-exec: host must be * or localhost in network address
```

`make allowlist` records those three forms, then measures the shape that does
filter by hostname: close egress, allow only
`(allow network-outbound (remote ip "localhost:18090"))`, and run
`tools/proxy-allowlist.py` on that loopback port. The proxy accepts CONNECT for
the hostnames in its list and answers 403 for everything else. Measured with
`captive.apple.com` allowlisted: curl and python `urllib` through the proxy
return 200, `opencode.ai` gets `CONNECT tunnel failed, response 403`, direct
egress is refused, the resolver still answers, and connections to any other
loopback port are refused. The hostname decision happens in the proxy, not in
the sandbox.

The stage writes `rig/allowlist/results.txt` and
`reports/eval-report-<version>-allowlist.csv`. Its proxy log records one line
per decision (`allow captive.apple.com:443`, `deny opencode.ai:443`).

## License

Licensed under [Apache-2.0](LICENSE).
