# LinkScope V43 — Settings layout

Based on V42. Replaces inline field explanations with accessible question-mark buttons and a shared dialog. The descriptions remain associated with inputs for assistive technology. Quick category shortcuts include names and icons, wrap responsively, and open and scroll to the selected category. All categories, including Dashboard appearance, start collapsed on ordinary visits; deep links and invalid fields still reveal relevant categories. The Brand label example no longer contains Unixfor; new defaults are blank and existing saved values are not changed. Clear the saved Brand label and save if a previously configured brand should be removed.

V43 build metadata is included; rebuild the service and installer using Rebuild-VisualStudio.cmd Release.

Validation: see ENDPOINT-TEST-RESULTS-V43.txt. Offline Chromium tests use actual markup, CSS and selected event handlers, not a live Windows backend. Windows compilation and integration remain unverified. Previously reported unrelated regression failures have not been retested or corrected in this UI update.
