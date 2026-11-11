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
7. Prints `PASS/FAIL` per probe and a final verdict. Exit code `0` means every
   claim held.

## Usage

```bash
make eval                     # run the eval, keep the rig for inspection
make eval version=0.14.0      # label the run with a version
make eval-clean               # run, then move the rig into rig/.trash/
make report version=0.13.0    # regenerate the CSV report from rig/results.txt
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
user records, `~/.ssh` file name listing, and `~/.gitconfig` / `~/.ssh/config`
contents. These are reachable by design in Safehouse 0.13.0 and none of them
carries a credential.

### Network posture (as measured)

Seatbelt cannot match hostnames, and Safehouse 0.13.0 emits a blanket
`(allow network-outbound (remote ip))` that dominates every rule appended after
it, so the override's network rules compile but do not restrict egress. The
eval verifies this by experiment and records the actual posture as `any`:
outbound TCP connects on any port (`nc github.com:22` succeeds), direct-IP DNS
(`dig @8.8.8.8` answers), and ICMP (`ping`) all work from inside the sandbox.
TLS 443 works (OpenCode and websearch run fine). The override carries
correctly-shaped rules (`(deny network* (remote ip "*:*"))`,
`(allow network-outbound (remote tcp "*:443"))`) that will start restricting
egress if Safehouse scopes its grant; re-run the eval after upgrading to catch
the flip.

## License

Licensed under [Apache-2.0](LICENSE).
