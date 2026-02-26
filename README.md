# Oxide Support Shell

Proper user docs coming soon, for now see
[RFD 620](https://rfd.shared.oxide.computer/rfd/620)
for motivation and examples.

## Local Testing Quickstart

In the following, the local shell (`bash`) prompt is `lamia:...$ `
and the Support Shell prompt is `sush# `.

In one terminal, start the server:

```
lamia:~/oxide/sush$ cargo run --bin=sush-server
   Compiling sush-server v0.1.0 (/home/alex/oxide/sush/server)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.99s
     Running `target/debug/sush-server`
Jan 29 14:08:17.672 INFO imported root certificate, key_id: much-hedgehog-cup-bleak-energy-village-lawn-pumpkin, component: job-manager
Jan 29 14:08:17.672 INFO listening, local_addr: 0.0.0.0:44444
```

In another terminal, point the client at the server and start it up:

```
lamia:~/oxide/sush$ export PERMSLIP_URL="https://permslip.inickles.0xeng.dev"
lamia:~/oxide/sush$ export SUSH_PERMSLIP_KEY="UNTRUSTED Support Shell Prototype"
lamia:~/oxide/sush$ export SUSH_URL="http://localhost:44444"
lamia:~/oxide/sush$ cargo run --bin=sush -- shell
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

Now you can start jobs. The server automatically sets some environment
variables for job processes, so as a simple test try running the command
`echo $SUSH_JOB_ID`:

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

To run an interactive job (with a pseudoterminal), you'll have to also
set up authentication with your SSH agent:

```
sush# iam
👋 Please confirm user presence to sign with key `identify-joke-veteran-hair-pony-enact-vacuum-trumpet`
✅ Key ID:      identify-joke-veteran-hair-pony-enact-vacuum-trumpet
   Fingerprint: SHA256:zjUpuh2LgTROUXgslEzjJnwYJWlGcI8LzLQqfpL8J0w
   Algorithm:   sk-ecdsa-sha2-nistp256@openssh.com
   Comment:     alex@lamia
   Nonce:       physical-shoulder-announce-jacket-crawl-size-arena-nothing
   Authn at:    2026-02-26 17:11:09.693439341 UTC
sush# start --interactive bash
✅ Signed request for job `pair-pumpkin-knock-puzzle-dawn-lady-token-device`
👋 Please confirm user presence to sign with key `identify-joke-veteran-hair-pony-enact-vacuum-trumpet`
✅ Connected to interactive job `pair-pumpkin-knock-puzzle-dawn-lady-token-device`
lamia:~$ 
```

See `help` for a list of other commands.
