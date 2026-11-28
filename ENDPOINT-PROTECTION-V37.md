# V37 — Installer build boundary correction

## Root cause
V36 added `CacheGeneration` to `src/ClamUpdateWorker.cs`, which is compiled into both the main service and the standalone installer. Its four references to `EndpointResponse` / `EndpointProtection` caused CS0103 when compiling the installer because those classes are intentionally not included in the setup project.

## Correction
Move the existing cache-generation method and its four native process declarations unchanged into `src/ClamScanCacheGeneration.cs`. Both files declare the same internal static partial class. The main project explicitly includes the new file and the required-source manifest lists it. The standalone command-line main build already includes all `src/*.cs`. Both setup build paths continue compiling only the shared worker, without the cache partial or endpoint engine. No change to scan policy, cache logic, settings or response handling.

## Validation
Seven targeted portable scripts passed; see `ENDPOINT-TEST-RESULTS-V37.txt`. The new regression checks the actual project input lists and the command-line build paths, rejecting references to service-only endpoint APIs from installer inputs. The V36 SQLite cache and checkpoint test still passes. Native Windows compilation and service/installer execution were not available in the Linux test environment. The two previously reported V36 regression failures were not addressed by this narrowly scoped hotfix.

## Build
Extract the full archive into a clean directory, open the solution or run `Rebuild-VisualStudio.cmd Release`. Verify both `bin/Release/LinkScope.exe` and `bin/Release/LinkScopeSetup.exe` are generated. Do not copy only the shared worker into an existing source tree: the new cache partial and project manifest are required.
