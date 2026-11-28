# LinkScope V42 — Settings guidance and source build identity

Based on V41. Adds plain-language, always-visible help for 127 static Settings fields, with accessible `aria-describedby` links, descriptions for the four dynamic category groups and explanations for the per-target network rule columns. The existing controls and security confirmations remain in place. Help is available in both themes and wraps at narrow widths.

## Version

`source-build-version.txt` contains `V42`. The existing version generator now checks this archive identifier after an explicit `LINKSCOPE_RELEASE_VERSION` override, but before Git discovery. This is intentionally a source archive version, not a claim about a merged Git release branch. Both Visual Studio and Build.cmd already embed the generated `obj\LinkScopeVersion.txt` in the main executable. All 12 HTML templates use that embedded value, including login and the dashboard footer. When releasing future source archives, update the marker. In a Git-only workflow, remove the archive marker if Git-derived versioning is preferred, or use the existing explicit override.

Rebuild from a clean extracted directory with `Rebuild-VisualStudio.cmd Release`. Install the newly generated setup; refresh the browser. The installed binary must be replaced for the version to change. Check the build output for `LinkScope build version: V42 (packaged source release metadata)`.

The five V41 entropy settings are now also explicitly listed in default.json, using the existing C# defaults. A small V41 settings hash lookup fix prevents invalid CSS selector exceptions from arbitrary URL fragments. No scan policy defaults or detection algorithms have been intentionally changed from V41.

## Validation

- New portable regression script `tests/validate_settings_help_v42.py`: passed all checks (help associations, unique IDs, four dynamic group descriptions, version source/build/template wiring, JavaScript syntax, entropy defaults).
- Offline Chromium: descriptions visible and paired action controls aligned at 1366, 768 and 390 CSS pixels in light and dark themes. No live Windows server used.
- V39 C# 5 static compatibility check: passed.
- Existing `validate_endpoint_activity_version.py`: fails in its Node DOM fixture (`panel.querySelectorAll is not a function`); SQLite acknowledgement portion passes. Existing `validate_endpoint_protection_v40.py`: fails on obsolete hardcoded constant assertion after V41 introduced configurable entropy settings. These are not treated as passing tests.
- PowerShell execution, Windows native compilation and installed-service verification are not available in this environment. No claim of production certification.
