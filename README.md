# Oxide Support Shell

The Oxide Support Shell (`sush`) is a tool that runs jobs on an
Oxide rack. Jobs must be authorized by Oxide support, but support
personnel need not have direct access to the rack;
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
sush# job start -w hostname
👋 Please confirm user presence to sign with key `federal-worth-fee-seed-skin-interest-road-luggage`
✅ Session is now `front-edit-bless-suggest-defy-bacon-retire-person`
✅ Signed request for job `kingdom-owner-dilemma-craft-soda-hungry-lumber-festival`
✅ Started job `kingdom-owner-dilemma-craft-soda-hungry-lumber-festival`
   913-0000019:BRM23230010  Stopped, exit 0 (5ms 545us 307ns), 12 B out, 0 B err
   913-0000019:BRM23230018  Stopped, exit 0 (6ms 165us 887ns), 12 B out, 0 B err
   913-0000019:BRM27230037  Stopped, exit 0 (5ms 927us 316ns), 12 B out, 0 B err
   913-0000023:2F8JEXDK     Stopped, exit 0 (5ms 282us 774ns), 9 B out, 0 B err
 » 913-0000019:BRM23230010 stdout «
BRM23230010
 » 913-0000019:BRM23230018 stdout «
BRM23230018
 » 913-0000019:BRM27230037 stdout «
BRM27230037
 » 913-0000023:2F8JEXDK stdout «
2F8JEXDK
```

## Local Testing Quickstart

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

With no command, `sush` starts its interactive REPL (aka shell).
Try `help` for a list of commands, or any `sush` sub-command,
such as `session`, `job`, etc. The REPL offers some convenient
features for running multiple jobs, such as transparent use of
the previous job ID, Nexus tunnel reuse, command history, etc.
Exit the REPL with `quit` or Ctrl-D.

You can begin a session with `session start`. You may be prompted
to touch your authentication token (e.g., YubiKey) and to authenticate
to the signing service:

```
sush# session start
👋 Please confirm user presence to sign with key `excite-cabbage-reject-wave-learn-police-that-glad`
🔑 Open this URL in your browser to authenticate to the signing service:
https://your-permslip-server.example/google/07c339c687e9ac919af7ab2ac5025881
✅ Created session
   Session ID:      slush-olympic-universe-ill-total-risk-host-suggest
   Signer nonce:    private-else-nut-erosion-trend-tube-token-man
   Sequence number: borrow-session-iron-author
```

Now you're ready to run a job. The server automatically sets some
environment variables for job processes, so as a simple test try
running the command `echo $SUSH_JOB_ID`:

```
sush# job start --wait "echo $SUSH_JOB_ID"
✅ Signed request for job `install-there-mutual-warfare-sound-live-order-man`
✅ Started job `install-there-mutual-warfare-sound-live-order-man`
   a part:0001  Stopped, exit 0 (68ms 190us 114ns), 50 B out, 0 B err
 » a part:0001 stdout «
install-there-mutual-warfare-sound-live-order-man
```

The `--wait` (`-w`) flag tells `sush` to wait for the job to stop before
returning, showing a live status line per sled while it runs; the default
behavior is to start the job and immediately return. You can check the
status of a (running) job with `job status`, watch it the same way with
`job status --wait`, or see the complete job status with
`job status --full`.

To run an interactive job with a pseudoterminal, you can use `job start
--interactive` (`-i`):

```
sush# job start --interactive bash
✅ Signed request for job `drop-fatigue-pink-spirit-eight-entry-praise-skill`
✅ Attached to interactive job `drop-fatigue-pink-spirit-eight-entry-praise-skill`, detach with `^]`
$ echo $SUSH_JOB_ID
drop-fatigue-pink-spirit-eight-entry-praise-skill
$ 
```

Job output may also be streamed using the `--streaming` flag, which
skips recording the job's standard output so that large core files
and other artifacts can leave the rack without exhausting output
storage (which may be on a ramdisk). Streamed output is written to
a local file (`--file` is required) and verified against the recorded
length and hash.

Jobs of any type take a `--target` option naming the sleds to run on.
The default target is `*`, meaning every sled. Comma-separated lists
of cubby numbers, serial numbers, and full baseboard IDs are also
accepted. Interactive and streaming jobs must target exactly one sled,
which defaults to the sled they are talking to.

The `version` command shows which versions of `sush` are running on
which sleds, as well as a visual indication of their health. Green means
the `sush` server is running and connected to the internal gossip network;
yellow means the server couldn't connect to the gossip network; and red
means that no `sush` server is running there at all.

## Configuration files and the options system

The `sush` client reads a configuration file in TOML format from the
standard XDG directories, e.g., `~/.config/sush/sush.toml`, or wherever
you point `--config` to. In such files, the keys are long option names,
and the values provide defaults for those options.

Top-level options provide global defaults, while tables in the config file
let you organize sets of options into named *profiles*, e.g., for different
environments. You can choose a profile via a top-level `profile` key, or
the `SUSH_PROFILE` environment variable, or the `--profile` global option:

```toml
permslip-url = "https://your-permslip-server.example"
permslip-key = "Your Signing Key"
profile = "local"

[local]
url = "http://localhost:44444"
permslip-key = "Local Signing Key"

[remote]
url = "https://somewhere-else.example"
```

Configuration files provide defaults for options in such a way that
environment variables override them, and explicit command line options
override those. You can see which options support environment variables
with `--help`; any of those may also be set in the config file, except
for ones whose values are secrets, such as `SUSH_NEXUS_TOKEN`.
