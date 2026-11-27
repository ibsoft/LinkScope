# Visual Studio — automatic LinkScope setup build

## Requirements

Visual Studio with .NET desktop development and the .NET Framework 4.8 targeting pack, on 64-bit Windows. No Python or native C/C++ toolchain is needed for this build.

## Build

1. Extract the complete project into a clean directory and open `LinkScope.sln`.
2. Select Debug or Release and x64.
3. Choose **Build Solution** (Ctrl+Shift+B), **Rebuild Solution**, or right-click the LinkScope project and choose Build.
4. Inspect the Build output. It should print `Building LinkScopeSetup.exe from ...` and `Setup generated: ...`.
5. Both `LinkScope.exe` and `LinkScopeSetup.exe` are in `bin\Debug` or `bin\Release` for the default output paths. Custom output directories are supported through the main project's `TargetDir`.

The setup project is invoked automatically after the application compiles; there is no separate solution project to select and no need to run BuildSetup.cmd. The main project disables the Visual Studio fast up-to-date check, and its setup target rebuilds the nested project each normal MSBuild invocation even when the application compiler finds its inputs up to date. Design-time builds do not generate setup. A failed application build does not run the setup target. During setup generation the old published installer is removed, and any installer compilation or copy error fails the build. Clean removes generated setup executables and staging directories for the selected configuration. The optional MSI is an external package, not a generated output; Clean does not remove it.

## Deployment

The setup remains an x64 Windows GUI application and embeds the current compiled service and wizard. Hidden child consoles, UAC and local MSI verification are preserved. ClamAV readiness and configuration/repair are now included; see [CLAMAV-SETUP.md](CLAMAV-SETUP.md). Place the official x64 ClamAV MSI and matching OpenPGP signature at `deploy\clamav-latest.msi` and `deploy\clamav-latest.msi.sig` before building if desired. The build copies both beside the setup under the output `deploy` folder; it is not downloaded or installed at build time. When distributing the installer, include the output deploy directory if it contains the approved MSI/signature pair. If you remove the source MSI/signature, remove any previously copied pair from the output folder yourself before distributing it.

## Acceptance tests (Windows)

- Build Debug/x64 and Release/x64; verify both EXEs and the two setup messages.
- Build again without edits; verify setup is regenerated.
- Delete only the output LinkScopeSetup.exe, then Build; verify it is recreated.
- Clean, then Build; verify both executables are recreated.
- Change a harmless application resource, rebuild, and verify the installer embeds the new application rather than an old EXE.
- Run `powershell.exe -NoProfile -File tests\Verify-VisualStudioSetup.ps1 -OutputDirectory bin\Release` to compare the embedded payload with the built application and check the x64 GUI PE header. This script does not execute or install the EXEs.
- Repeat with a trusted optional MSI and matching signature in deploy; confirm both copied files have the same SHA-256 hashes as the sources. Launch the setup only on a test Windows VM to validate its GUI and optional ClamAV behavior.

Portable source and project XML checks were run in the delivery environment. Actual MSBuild compilation, Visual Studio incremental builds and installer execution require Windows validation. A full application compile error must be resolved before any fresh installer can be built.
