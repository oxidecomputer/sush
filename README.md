# Oxide Support Shell

Proper user docs coming soon, for now see
[RFD 620](https://rfd.shared.oxide.computer/rfd/620)
for motivation and examples.

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
✅ Job ID:      install-there-mutual-warfare-sound-live-order-man
   Target:	a part:0001
   Job status:	Stopped
   Started at:	2026-08-05 16:27:58.824606210 UTC
   Stopped at:	2026-08-05 16:27:58.892796324 UTC (68ms 190us 114ns)
   Exit status:	0
   Stdout len:	50 B
   Stderr len:	0 B
   Stdout hash:	ae5a3df9c5c629590af52baceb12021525c0be16994738977b2ed049f4f374bb
   Stderr hash:	af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
✅ Job stdout:
install-there-mutual-warfare-sound-live-order-man
```

The `--wait` (`-w`) flag tells `sush` to wait for the job to stop before
returning; the default behavior is to start the job and immediately return.
You can check the status of a (running) job with `job status`.

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

See `help` for a list of other commands.
