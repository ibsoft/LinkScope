# V62 — Independent signature comparison and existing-file audit probe

## Evidence from V61

The host report shows a readable Security channel and one post-watermark record, but no Event 4663 during the probe. It does not establish that Windows emitted an exact marker event. The DNS status was copied from an initial pending lookup; the ClamD observation was 33 seconds old when the readiness snapshot was captured. No current official version verdict is justified by that snapshot.

## Changes

The scanner now checks the nonblocking official DNS comparison independently of the 60-second engine VERSION poll, at most once every five seconds when the scanner is online (subject to scanner tick completion). The last engine observation timestamp remains the time of the real ClamD check. The native DNS worker, cache-age and advertisement-age checks, disk-newer-than-loaded check, conservative unknown verdict and download cooldowns are unchanged. No newer official version or successful resolution is assumed.

The live audit probe creates a unique empty marker with CREATE_NEW and DELETE_ON_CLOSE, retaining the original handle without delete sharing. It then opens the same object with OPEN_EXISTING and compatible sharing (including share-delete for the existing delete handle). Both handles must pass the final-path and file-identity checks, and the reopened object must have the same volume/file index and zero initial length. The second handle writes only fixed benign content, is flushed and closed, then the original handle is closed. No existing file is truncated or overwritten, no explicit path-based deletion or new privilege is introduced. If reopening is refused, report the actual failure and independently verify cleanup; do not report a writer verdict. The two-handle pattern tests access to an existing file after creation, more closely resembling the separate PowerShell create/modify operations that previously generated audit evidence. It is not a confirmed explanation of the host's missing service audit event.

The original pre-probe watermark, exact path, Event ID 4663, PID, executable, write mask, timestamp, and cleanup requirements remain. The no-match report additionally counts observed event IDs and parent-directory candidates, neither of which qualifies as a pass. The general historical audit check is unchanged. No production correlation, quarantine, containment, audit policy, ACL or setup provisioning changes.

Run the suite in an explicitly selected disposable application test folder. If the exact event remains absent, inspect the host Security log independently for the reported marker and compare the selected directory's SACL and per-user audit policy. Do not treat absence of a match as proof auditing is disabled.

## Validation performed

Five targeted scripts passed: validate_signature_versions_v57.py, validate_audit_diagnostics_v55.py, validate_live_audit_v56.py, validate_automated_suite_v59.py and validate_guided_test_center_v58.py. Static source checks and Chromium mocked API tests only. Node syntax check passed. Native Windows compilation, dual-handle file access, actual audit generation/retrieval, DNS resolution and containment are not verified. No production certification.
