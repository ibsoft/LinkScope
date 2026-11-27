# Navigation and setup update — validation

Based on LinkScope_Endpoint_Protection_Release_Candidate.zip. This update does not certify the underlying Endpoint Protection release for production.

## Changes
- Shared compact header across nine authenticated pages, 12 px desktop navigation, 1440 px maximum width, current-page indicator. Collapse at 1239 px or below or whenever navigation overflows. Keyboard-accessible menu, Escape dismissal and 44 px compact touch targets; preserve notification bell, theme preference and account controls.
- Font Awesome Free 5.15.4 solid artwork converted to inline SVGs (see FONT-AWESOME-NOTICE.md). No font assets or external network dependencies.
- Report is a regular navigation link wired to the existing full PDF export handler; all report content remains unchanged.
- Setup builds as a Windows GUI executable. PowerShell wizard and console child processes use hidden/no-window launch flags. UAC and the wizard remain visible. Operation output is written to %ProgramFiles%\LinkScope Setup Logs.
- Optional ClamAV installation: check machine uninstall registries and conventional installation locations, prompt if missing, use deploy\clamav-latest.msi only, require administrator verification of the displayed SHA-256, and check MSI product metadata. Quiet installation without automatic reboot. ClamAV is optional; missing or declined packages do not prevent installation if the administrator chooses to proceed. Existing ClamAV installations are not upgraded automatically. ClamAV runtime configuration and signature updates remain separate steps.

## Tests executed
- `python tests/validate_navigation_static.py`: PASS — static HTML/SVG consistency, all navigation routes and active states, Report wiring, responsive selectors, utility icon markup, installer source flags and optional MSI workflow.
- `python tests/validate_endpoint.py`: PASS — JS syntax, configuration, project resources, SQLite schema and outbox SQL, source delimiter checks.
- Setup.cs delimiter check: PASS (not compilation).
- `python tests/validate_navigation.py`: attempted; Chromium refused navigation with ERR_BLOCKED_BY_ADMINISTRATOR. Actual layout, browser interactions and report download are not verified.
- Windows build and installer runtime: not run; no Windows compiler or Windows environment available.

## Windows acceptance checks (pending)
1. Run Build.cmd and verify the application and setup compile. Repeat with Visual Studio's normal build.
2. Verify one-row navigation on 1440/1536/1920 px screens and responsive fallback on smaller laptop widths. At 1024, 768, 390 and 320 px check hamburger, scrolling, 44 px targets, keyboard Escape, all links, utility icons and account menu. Check long configured brand names and browser zoom.
3. Switch theme and navigate between all pages. Verify theme retention and notification counter. Verify that Report exports a complete PDF without navigating away.
4. On a clean Windows VM, launch LinkScopeSetup.exe and install. Only the wizard, UAC and explicit confirmation dialogs should be visible; verify no console flashes and inspect setup logs.
5. Repeat with no ClamAV MSI, declining installation; then add a trusted official x64 MSI in deploy\clamav-latest.msi. Verify the prompt, package hash, successful installation, cancellation/error paths and reboot-required messaging. Check detection when ClamAV is already installed. Verify Visual Studio copies the optional MSI to the output deploy folder. Do not test with untrusted packages.
6. Configure ClamD and FreshClam following ENDPOINT-PROTECTION.md; installation alone does not enable a functional antivirus service. Complete the endpoint acceptance tests before enabling automatic response.

No MSI is bundled. The administrator must supply and independently verify the official package. MSI product metadata and a displayed hash are not proof of publisher authenticity. Setup is unsigned. Back up LinkScope settings and history before upgrading.

## Strict single-row header revision
- Replaced the shared header's flex layout with a three-track grid; removed legacy `.top` and `.bar` header classes from all nine authenticated pages. Desktop links never wrap. The bell/theme/account tools occupy their own non-wrapping track. On narrow viewports or measured link overflow, the navigation switches to a vertically scrollable, out-of-flow hamburger dropdown; header stays on one row. Starts in compact mode until the available space is measured.
- New versioned theme CSS and JS URLs avoid stale styles/scripts; previous asset aliases are preserved for compatibility. No installer, monitoring, report or API functionality changed.
- Portable navigation and endpoint regression checks: PASS. Browser test updated to verify grid layout, header height, shared centerline and nonwrapping utility controls. Attempted browser test again: blocked by ERR_BLOCKED_BY_ADMINISTRATOR. Actual rendering and Windows compilation remain unverified.

## Later setup update

The earlier manual hash-approval workflow described above is superseded by mandatory detached signature verification. See [CLAMAV-PACKAGE-VERIFICATION.md](CLAMAV-PACKAGE-VERIFICATION.md).
