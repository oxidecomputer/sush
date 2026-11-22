# Oxide Support Shell

The Oxide Support Shell (`sush`, rhymes with "hush") is a tool that
runs jobs on an Oxide rack. Jobs must be authorized by Oxide support,
but support personnel need not have direct access to the rack;
see [RFD 620](https://rfd.shared.oxide.computer/rfd/620)
for requirements, design constraints, and intended use cases.

At the core of `sush` are _signed job requests_:

```json
{
  "payload": {
    "job_id": "caught-cream-rifle-void-river-snack-rural-sight",
    "command": "fortune"
  },
  "key_id": "much-hedgehog-cup-bleak-energy-village-lawn-pumpkin",
  "signature": {
    "r": "absorb-view-praise-light-gentle-casual-force-indicate-dignity-sense-woman-chapter-kiwi-slot-gown-measure-repeat-crater-crush-across-toilet-clarify-wage-toss",
    "s": "above-already-valve-educate-can-clutch-imitate-snap-chunk-quit-mask-canvas-stadium-attend-refuse-banner-helmet-step-hood-symptom-time-beyond-earth-render"
  }
}
```

These are job authorizations produced by Oxide (via the Online Signing Service)
and may be relayed to the customer, possibly over a low-bandwidth channel,
who then relays them to the rack (via the `sush` client). When Oxide support
runs a session directly, on our own racks or via a jumphost, the client can
reach both the signing service and the rack, so it performs the relay itself
and the signed requests never surface. Notice that all IDs and signature
components are encoded as human-readable codephrases.

Here is a simple job running across a four-sled racklette:

```
sush# job start hostname
👋 Please confirm user presence to sign with key `federal-worth-fee-seed-skin-interest-road-luggage`
✅ Session is now `front-edit-bless-suggest-defy-bacon-retire-person`
✅ Signed request for job `kingdom-owner-dilemma-craft-soda-hungry-lumber-festival`
✅ Started job `kingdom-owner-dilemma-craft-soda-hungry-lumber-festival`
   913-0000019:BRM23230010 stopped, exit 0 (5ms 545us 307ns), 12 B out, 0 B err
   913-0000019:BRM23230018 stopped, exit 0 (6ms 165us 887ns), 12 B out, 0 B err
   913-0000019:BRM27230037 stopped, exit 0 (5ms 927us 316ns), 12 B out, 0 B err
   913-0000023:2F8JEXDK    stopped, exit 0 (5ms 282us 774ns), 9 B out, 0 B err
 » 913-0000019:BRM23230010 stdout «
BRM23230010
 » 913-0000019:BRM23230018 stdout «
BRM23230018
 » 913-0000019:BRM27230037 stdout «
BRM27230037
 » 913-0000023:2F8JEXDK stdout «
2F8JEXDK
```

## Quickstart

`sush` should be enabled and available by default in all Omicron builds
past `ecc38a1041c9f5c4bd90b178bfae655380d55bf3`. To use it, you will need
three things: a client binary, a configuration that describes how jobs
should be signed and how to reach the rack, and an SSH identity.

### Client

On shared lab systems, there's usually a reasonably current illumos client
in `~alex/bin/sush` that you're welcome to use or copy. If you'd rather
fetch the client yourself, buildomat publishes Helios and Linux clients
on each commit:

```
https://buildomat.eng.oxide.computer/public/file/oxidecomputer/sush/linux/<commit>/sush
https://buildomat.eng.oxide.computer/public/file/oxidecomputer/sush/helios/<commit>/sush
```

You may also build it yourself from a repository checkout with
`cargo build --features permslip`.

### Client configuration

You can use a configuration file, environment variables, or command line
arguments to configure `sush` options. Options cascade in that order; e.g.,
the command line overrides the environment, which overrides a configuration
file. Config files are found via standard XDG path search; the usual
per-user location is `~/.config/sush/sush.toml`.

The basic options to configure are the Permission Slip address and key
used to authorize jobs, and the address of a technician port on the rack
(`sush` can also be used via a Nexus tunnel, but that takes a little more
setup and will be covered in a future document). Oxide engineers should
use a "Lab" key that will enable jobs to be run on staging-signed systems
(e.g., racklettes and other lab machines), while support personnel will
use a "Production" key that allows jobs to run on production-signed
(e.g., customer) systems.

Multiple racks and per-rack options may be configured via _profiles_
(named groups or "tables") in a config file, like this:

```
permslip-url = "https://signer-us-west.corp.oxide.computer"
permslip-key = "Support Shell Lab A1"
profile = "dublin"

[dublin]
url = "https://[fe80::aa40:25ff:fe05:2202%dublin_sw0tp0]:12352"

[madrid]
url = "https://[fe80::aa40:25ff:fe05:102%madrid_sw0tp0]:12352"
```

The default profile is set here as the global `profile` key;
you can also switch profiles with the `SUSH_PROFILE` environment
variable or the `--profile` argument.

Other racks or alternate switch addresses may be added by examining
the technician port addresses with `pilot tp ls`. On illumos especially,
it's important to also include the interface as a zone identifier
prefixed by `%` (per RFC 9844), since otherwise the kernel must guess
which interface to use, and usually guesses wrong. The port number
`12352` is assigned as `SUSH_PROXY_PORT` in Omicron's common address
list.

### SSH identity

`sush` uses an _attributive only_ authentication scheme. The
_authorization_ for a job comes exclusively from its signature;
separately, there is also an _authentication_ process that identifies
the actor that starts a session, runs a job, etc. These identities
are established by proving to the proxy that the user has current
possession of an SSH key via `ssh-agent`, and are managed in `sush`
using the `iam` command.

Any kind of Ed25519 or ECDSA SSH key will do, but we recommend using one
backed by a hardware token such as a YubiKey (but note that it does *not*
need to be one of the designated "Support YubiKeys"). See `ssh-add(1)`
for adding identities to your agent; `ssh-add -l` or `sush iam -l` will
show which identities are currently available. It may also be useful to
forward agent connections if you're logging in remotely (e.g., to Castle).

By default, only the identity that started a session may view or control
its jobs or their outputs. But `session allow <key_id>` may be used to
grant access to a session and its jobs; `session deny` removes such grants.

Fresh SSH identities cannot read jobs or their outputs, or who started a
session, and cannot start sessions or jobs without authorization. The only
data they can see is: each sled's baseboard ID, cubby number, and `sush`
server version; the ID of the current session; and the (public)
certificates of accepted job-signing keys.

### Client commands

The `sush` client has a couple of modes and a variety of sub-commands.
You can use it in batch mode by specifying the sub-command as an argument,
or in interactive mode by starting it with no arguments or with the `shell`
(alias `repl`) sub-command; you can also script it with JSON output using
the `-j` option. You can exit the interactive shell with `quit` or Ctrl-D.

A good first sub-command is `version`, which reports the version, status,
and cubby numbers of the `sush` servers running on each sled, as seen by the
server that answers. Green sleds are connected to that server over the
internal gossip network; yellow sleds are not connected, but their versions
are known; and red sleds are known only from the cubby map, which usually
means that no server is running there.

### Starting a session

Jobs exist within a _session_, and (except for exceptional circumstances)
only one session may be present on a given rack at once. So to run a job,
you must first start or attach to an existing session. Use `session start`
to start a new one; the client will prompt for confirmation before replacing
an existing session if there is one. That command requires authenticating
both to `sush` via your SSH identity, and also to the signing server via
Google OAuth:

```sh
sush# session start
👋 Please confirm user presence to sign with key `excite-cabbage-reject-wave-learn-police-that-glad`
🔑 Open this URL in your browser to authenticate to the signing service:
https://signer-us-west.corp.oxide.computer/google/fe38f0cb8fd621b15806bec086ee395a
✅ Created session
   Session ID:      story-diesel-fault-three-empty-legend-thought-laptop
   Signer nonce:    core-join-panel-ecology-mammal-abstract-alley-chaos
   Sequence number: borrow-regular-follow-bitter
```

### Running jobs

Once you've got a session, you can obtain and run signed jobs with `job start`:

```sh
sush# job start "zpool status -x"
✅ Signed request for job `script-tooth-raven-clump-grape-broken-meat-seminar`
✅ Started job `script-tooth-raven-clump-grape-broken-meat-seminar`
   913-0000019:BRM42220004 stopped, exit 0 (19ms 55us 427ns), 22 B out, 0 B err
   913-0000019:BRM42220007 stopped, exit 0 (19ms 375us 607ns), 22 B out, 0 B err
   913-0000019:BRM42220046 stopped, exit 0 (19ms 906us 956ns), 22 B out, 0 B err
   913-0000019:BRM42220081 stopped, exit 0 (21ms 879us 664ns), 22 B out, 0 B err
 » 913-0000019:BRM42220004 stdout «
all pools are healthy
 » 913-0000019:BRM42220007 stdout «
all pools are healthy
 » 913-0000019:BRM42220046 stdout «
all pools are healthy
 » 913-0000019:BRM42220081 stdout «
all pools are healthy
```

The default for `job start` is to run the job in batch mode across all
available servers. You can target specific sleds for a job using `job
start -T <targets>`, where `<targets>` is a comma-separated list of full
baseboard IDs, unambiguous serial numbers, or cubby numbers; `*` denotes
the default of all sleds.

You can also run interactive jobs (with a pseudoterminal) by supplying
the `-i` (`--interactive`) option. Interactive jobs only run on a single
target; the default is the scrimlet you're talking to:

```sh
sush# job start -i bash
✅ Signed request for job `door-west-sponsor-tuna-security-together-pact-answer`
✅ Started job `door-west-sponsor-tuna-security-together-pact-answer`
✅ Attached to job `door-west-sponsor-tuna-security-together-pact-answer`, detach with `^]`
BRM23230018 # 
```

Try running various interactive programs, detaching, re-attaching,
and using `session allow <key_id>` (from their `iam`) to invite your
friends along for the ride.

The last job mode is _streaming_, which you can select with `-S`.
Streaming jobs also run on a single target, with the same default,
and you must supply an output destination with `-f`:

```sh
sush# job start -S -T 16 -f messages.log "cat /var/adm/messages"
```

Completed jobs may be examined via `job status` and `job output`; note
especially `job status --full`. A list of jobs run so far (from the last
cold-boot of the rack) is available with `job history`.

## Local Testing

In the following, the local shell (`bash`) prompt is `$ `
and the Support Shell prompt is `sush# `.

In one terminal, start the server:

```
$ cargo run --bin=sush-server
     Running `target/debug/sush-server`
Aug 09 03:41:44.592 INFO managing state, component: state manager
Aug 09 03:41:44.594 INFO listening, local_addr: 0.0.0.0:44444
```

> [!NOTE]
> On NixOS you will have to pass the `--insecure-disable-path-isolation` flag to
> the server, otherwise spawning commands will fail.

In another terminal, point the client at the server and start it up:

```
$ export PERMSLIP_URL="https://your-permslip-server.example"
$ export SUSH_PERMSLIP_KEY="Your Signing Key"
$ export SUSH_URL="http://localhost:44444"
$ cargo run --bin=sush --features permslip
     Running `target/debug/sush`
✅ url = http://localhost:44444 (environment)
✅ ssh-auth-sock = /run/user/1000/ssh-agent.sock (environment)
sush# 
```
