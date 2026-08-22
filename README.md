# Glasshouse

See what your computer says about you, and which parts of it you can
actually do something about.

```
[CHANGE] Recall is not explicitly disabled
[COSTLY] Closed firmware
         American Megatrends Inc. 3601, 10/12/2024
[SEALED] Intel Management Engine
         12th Gen Intel(R) Core(TM) i5-12400F
```

It reads your machine and reports what it finds, sorted by whether the
finding is a setting you can flip, a change that costs you something real,
or something burned into silicon that you will never change.

## Why the third category matters

Most privacy tools hand you a list of two hundred tweaks and apply them.
They never tell you which problems are unsolvable, so people spend
weekends trying to remove things that cannot be removed, and come away
believing they succeeded.

Glasshouse would rather say the unwelcome thing. If your CPU has Intel Boot
Guard fused, coreboot is not an option for you, and no amount of effort
changes that. Knowing it is worth more than another registry tweak.

## The trap this tool tries not to fall into

**Hardening makes you unique, and unique is trackable.** A machine with two
hundred unusual settings has a fingerprint that no other machine in the
world shares. Tor Browser refuses to let you resize its window for exactly
this reason: its privacy comes from every user looking identical, not from
clever configuration.

So Glasshouse reports. It does not apply a pile of tweaks, and when it
suggests one, it tries to be honest about what the change costs.

## What it will not do

- **It never writes.** No registry key is opened for writing anywhere in
  the source. Read it and check.
- **It never opens a socket.** A tool asking you to trust it with your
  privacy has no business phoning home, and the cheapest way to prove that
  is to contain no code that could.
- **It masks identifiers by default.** A report you can paste into a bug
  thread should not carry your machine's fingerprints. Use `--reveal` when
  you want the real values.

## Reading the report

Each finding says where it was read from, so you can go and check the claim
yourself instead of trusting this program:

```
[SEALED] Intel Boot Guard is probably fused
    Found:    12th Gen Intel(R) Core(TM) i5-12400F
    Read at:  HARDWARE\DESCRIPTION\System\CentralProcessor\0
    Inferred: based on the CPU generation; reading the fuses needs ring 0
```

A finding is `measured` when the value was read, `inferred` when it was
deduced from something else and says so, and `UNSEEN` when the check could
not look at all.

That last one matters more than it sounds. A check that quietly returns
nothing looks exactly like a machine with nothing to report, so gaps are
counted separately and called out: **a shorter report is not a safer
machine.**

## Running it

```bash
glasshouse
```

```bash
glasshouse --lang es
```

```bash
glasshouse --reveal
```

```bash
glasshouse --json
```

No installer, no runtime, no configuration. One binary.

## Building

Needs [Go](https://go.dev) and nothing else:

```bash
go build -o glasshouse .
```

The only dependency is `golang.org/x/sys`, from the Go team, used to read
the Windows registry.

## Translating

Every word a human reads lives in `messages/<code>.json`. Nothing readable
is written in Go anywhere else, so a new language is one new file and no
code at all.

Copy `messages/en.json`, translate what you can, and leave out what you
cannot: missing entries fall back to English rather than showing blanks, so
a half-finished translation is useful on the day you start it.

English and Spanish ship complete. A test prints how much of each language
is covered, so a translation falling behind the checks is visible rather
than quietly stale.

## What it looks at

| Group | Examples |
|---|---|
| Firmware and silicon | Management Engine, PSP, Boot Guard, firmware vendor, Secure Boot, SIP, TPM |
| Identifiers | System UUID, hardware serials, MachineGuid, machine-id, advertising ID, computer name |
| Telemetry | Telemetry level, upload service, error reporting, activity history, Recall, package survey |
| Browser | Font set size, and whether Firefox resists fingerprinting |
| Network | Configured DNS resolvers, and whether a local stub answers them |

Windows, Linux and macOS. Each reads the same ideas from a different place:
the registry and SMBIOS on Windows, /sys and /proc on Linux, the IORegistry
on macOS.

The checks differ where the systems genuinely differ, and the report says so
rather than pretending they are the same. The system UUID is a good example:
Windows hands it to any program that asks, while Linux keeps it root-only,
so running unprivileged there reports a gap instead of a value.

## Tests

The promises above have tests behind them, because promises in a README
rot and promises with a test behind them do not:

```bash
go test ./...
```

It checks that no source file can write to the registry or reach the
network, that every finding the code can emit has an explanation in the
catalogue and no orphan text is left for translators, that identifiers never
reach the screen or the JSON unmasked, and that no check is able to return
silence.

## Licence

MIT. Do what you like with it.
