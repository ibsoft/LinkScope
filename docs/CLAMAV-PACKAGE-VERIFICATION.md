# ClamAV installer authenticity verification

## Deploy the pair

Download the desired official Windows x64 MSI and its matching `.sig` file from https://www.clamav.net/downloads. Rename the files to `deploy\clamav-latest.msi` and `deploy\clamav-latest.msi.sig`. They must be from the same release and architecture. Visual Studio and Build.cmd retain automatic setup compilation; the Visual Studio output deploy folder receives both files when present. Remove obsolete output packages manually. The MSI and signature are not included in this source archive.

Install a trusted, supported Gpg4win/GnuPG release system-wide from https://www.gpg4win.org/ using your normal software approval process. Setup discovers `GnuPG\bin\gpg.exe` or `Gpg4win\bin\gpg.exe` beneath Program Files / Program Files (x86). Other locations require an administrator to install GnuPG in a supported location. Setup checks filesystem ownership, write ACLs and reparse points of the installation tree; a custom installation may be rejected. It does not download or execute a verifier from the deploy folder, PATH, user profile or an arbitrary registry path. The independently installed verifier and Windows administrators are part of the trust boundary.

## Verification sequence

1. Stage the MSI and detached signature in the existing administrator/SYSTEM-only setup directory. Calculate and log SHA-256 for the staged MSI.
2. Import the embedded official release public key into a private, isolated GnuPG home. Disable automatic key retrieval/import and ignore the user's GnuPG configuration. This step requires no Internet access.
3. Verify the exact staged MSI using GnuPG detached signature verification. Require a successful exit, exactly one GOODSIG and VALIDSIG status, pinned primary fingerprint, a binary document signature, and SHA-256/384/512. Reject bad, missing, expired, revoked or ambiguous signature status. The signer name or key ID alone is not trusted. No external public key from deploy is accepted.
4. Only after successful authentication inspect MSI product metadata. Display the fingerprint and SHA-256 and ask the administrator to confirm the intended x64 release/version. If approved, install the same staged file with Windows Installer. No signature-failure override exists.
5. Continue the existing ClamD/FreshClam provisioning workflow. Existing installed ClamAV can be checked and repaired without the MSI, signature or GnuPG. LinkScope itself remains installable without optional ClamAV.

Failure is logged in `%ProgramFiles%\LinkScope Setup Logs`; signature gate failures return exit code 10 and display a blocking message. Missing input files prevent the wizard from offering MSI installation. No Windows Installer process is started on those paths. The setup does not verify all previously installed ClamAV binaries or definitions using this detached signature; those are separate concerns.

## Trust anchor

Official procedure: https://docs.clamav.net/manual/Installing.html#verifying-clamavnet-downloads-with-gpg

Embedded public key source (linked by official documentation): https://raw.githubusercontent.com/Cisco-Talos/clamav-documentation/main/src/manual/cisco-talos.gpg

Primary fingerprint of the published key: `5BADCA2665EF59DCF8A23D8B707F0DB480836771` (key packet inspected with GnuPG). It is a public key, not a signing secret. The key is embedded at build time. If Talos rotates or revokes the key, independently verify vendor key publication and update both the resource and pinned fingerprint via a reviewed release; do not accept an arbitrary key or bypass verification. Offline verification only knows revocation information present in the embedded key. It does not establish release freshness or prevent installation of an older validly signed release. Confirm the intended version independently. This installer remains unsigned; distribute it through a trusted software deployment channel.

## Windows acceptance tests (required, not run here)

- Genuine current x64 MSI and corresponding signature: signature verified and confirmation shown, then proceed only after approval.
- MSI with one byte modified, unrelated signature, invalid/empty signature, signature from a different release, or signature by an unrelated key: blocked before `msiexec.exe`.
- Missing signature or GnuPG: no MSI installation. A fake `gpg.exe` in deploy or PATH must not run.
- Expired signing key/signature, revoked key in the trusted key material: blocked. Test correct clock and approved current key; do not disable expiry checks.
- Existing ClamAV: configure/repair and read-only readiness checks work without the deployment pair.
- Debug/Release rebuild copies both files and embeds the key; setup does not open console windows.
- Offline: package verification works with installed GnuPG; initial definitions may still require pre-provisioned databases or approved Internet access.

Portable validation: `python tests/validate_clam_signature.py` checks the actual embedded key fingerprint, exercises detached signatures with temporary test keys, and checks source gate ordering and build resource wiring. It does not run the Windows C# implementation or authenticate a real ClamAV MSI, since no MSI/signature pair was supplied. Windows compile and runtime tests remain necessary.
