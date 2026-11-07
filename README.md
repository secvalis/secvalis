# Secvalis agent

`secvalis.sh` is the audit agent of [Secvalis](https://secvalis.eu). It runs on your Linux host,
lists installed packages, scans them with Trivy and sends the result to the Secvalis panel.
`--dry-run` prints what would be sent without uploading anything.

This repository is the public, signed source of every agent release. Each release is a tag
`v<version>` holding `secvalis.sh` and its detached signature `secvalis.sh.sig`. Tags never move.

## Verify before you run

You need OpenSSH with `ssh-keygen -Y` support and the keys from `allowed_signers`.
Pin the key fingerprints from a source other than this repository (secvalis.eu/en/trust).

```sh
V=1.4.3   # latest tag in this repository
curl -fsSLO https://raw.githubusercontent.com/secvalis/secvalis/v$V/secvalis.sh
curl -fsSLO https://raw.githubusercontent.com/secvalis/secvalis/v$V/secvalis.sh.sig
ssh-keygen -Y verify -f allowed_signers -I release@secvalis.eu -n secvalis-agent \
  -s secvalis.sh.sig < secvalis.sh
```

Then check that the version is not listed in [`REVOKED`](REVOKED) on `main`, and do not accept a
version older than the one you already approved.

Full step-by-step guide: https://secvalis.eu/en/docs/verify-script

## License

The agent script is licensed under the [Apache License 2.0](LICENSE). The license does not cover
the Secvalis platform or grant rights to the Secvalis name or trademarks.

Security reports: see [SECURITY.md](SECURITY.md).
