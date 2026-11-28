# Endpoint Protection V39 — C# 5 compilation hotfix

Based on V38. The reported CS8026 in src/EndpointDiskBudget.cs line 35 was caused by a C# 6 auto-property initializer. The property is now assigned the same initial value in the explicit parameterless EndpointDiskPressure constructor. Both project files and the direct build retain C# 5. No scan policy, cache, pacing or protection settings have changed.

Six targeted portable regression scripts passed; see ENDPOINT-TEST-RESULTS-V39.txt. A new static test scans the C# sources for the reported unsupported property-initializer pattern and checks build language settings. This is not a general language compatibility checker or a compiler. No native Windows compiler is available in the validation environment; full compilation and runtime validation remain outstanding.

Extract into a clean directory and run Rebuild-VisualStudio.cmd Release on Windows, then install the generated setup if the build succeeds.
