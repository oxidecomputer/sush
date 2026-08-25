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
✅ Job ID:      kingdom-owner-dilemma-craft-soda-hungry-lumber-festival
   913-0000019:BRM23230010  Stopped, exit 0 (5ms 545us 307ns), 12 B out, 0 B err
   913-0000019:BRM23230018  Stopped, exit 0 (6ms 165us 887ns), 12 B out, 0 B err
   913-0000019:BRM27230037  Stopped, exit 0 (5ms 927us 316ns), 12 B out, 0 B err
   913-0000023:2F8JEXDK     Stopped, exit 0 (5ms 282us 774ns), 9 B out, 0 B err
 » 913-0000019:BRM23230010 «
✅ Job stdout:
BRM23230010
 » 913-0000019:BRM23230018 «
✅ Job stdout:
BRM23230018
 » 913-0000019:BRM27230037 «
✅ Job stdout:
BRM27230037
 » 913-0000023:2F8JEXDK «
✅ Job stdout:
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

In another terminal, point the client at the server and start it up
in REPL mode. Signing job requests needs a client built with the
`permslip` feature and a reachable Permission Slip instance holding
your signing key:

```
$ export PERMSLIP_URL="https://your-permslip-server.example"
$ export SUSH_PERMSLIP_KEY="Your Signing Key"
$ export SUSH_URL="http://localhost:44444"
$ cargo run --bin=sush --features permslip -- repl
     Running `target/debug/sush repl`
✅ Output format set to `text`
✅ Server URL set to `http://localhost:44444`
✅ SSH agent socket set to `/run/user/1000/ssh-agent.sock`
✅ SSH key ID unset
sush# 
```

We can explicitly start a session with `session start`, or we can
let `job start` implicitly start one for us. The server automatically
sets some environment variables for job processes, so as a simple
test try running the command `echo $SUSH_JOB_ID`:

```
sush# job start --wait "echo $SUSH_JOB_ID"
✅ Signed request for job `install-there-mutual-warfare-sound-live-order-man`
✅ Job ID:    install-there-mutual-warfare-sound-live-order-man
   a part:0001  Stopped, exit 0 (68ms 190us 114ns), 50 B out, 0 B err
✅ Job stdout:
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

The `version` command shows which versions of `sush` are running where
in the rack. See `help` for a list of other commands.
