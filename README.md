# Oxide Support Shell

Proper user docs coming soon, for now see
[RFD 620](https://rfd.shared.oxide.computer/rfd/620)
for motivation and examples.

## Quickstart

In one terminal, start the server:

```
$ cargo run --bin=sush-server
   Compiling sush-server v0.1.0 (/home/alex/oxide/sush/server)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.99s
     Running `target/debug/sush-server`
Jan 29 14:08:17.672 INFO imported root certificate, key_id: much-hedgehog-cup-bleak-energy-village-lawn-pumpkin, component: job-manager
Jan 29 14:08:17.672 INFO listening, local_addr: 0.0.0.0:44444
```

In another terminal, set up the client, point it at the server,
and start an interactive session:

```
$ export PERMSLIP_URL="https://permslip.inickles.0xeng.dev"
$ export SUSH_PERMSLIP_KEY="UNTRUSTED Support Shell Prototype"
$ export SUSH_URL="http://localhost:44444"
$ sush shell
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.08s
     Running `target/debug/sush shell`
✅ No reserved jobs
```

To reserve some jobs, tell it how many you'd like:

```
sush# reserve 3
✅ Reserved 3 jobs at 2026-01-29 21:15:39.123535261 UTC:
below-mimic-bunker-trust-coconut-parade-plunge-cereal
all-echo-thrive-rebuild-dust-pudding-match-together
cherry-butter-wing-little-office-door-renew-scissors
```

Then you can run jobs. The server automatically sets the
environment variable `SUSH_JOB_ID` on job processes, so as
a simple test we can run the command `echo $SUSH_JOB_ID`:

```
sush# start --wait "echo $SUSH_JOB_ID"
✅ Job ID:      below-mimic-bunker-trust-coconut-parade-plunge-cereal
   Job status:  Ended
   Reserved at: 2026-01-29 21:15:39.123535261 UTC
   Started at:  2026-01-29 22:33:50.987964913 UTC
   Ended at:    2026-01-29 22:33:50.992263159 UTC (4ms 298us 246ns)
   Status:      0
   Stdout len:  54 B
   Stderr len:  0 B
   Stdout hash: 832b8ddea39bf94bee42b3a4eb797aa826e6a1de44f29d6076dd9839b7fd7404
   Stderr hash: af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
✅ Job stdout:
below-mimic-bunker-trust-coconut-parade-plunge-cereal
```

See `help` for a list of other commands.
