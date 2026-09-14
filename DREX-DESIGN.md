# DREX-V2 DESIGN SYSTEM SPECIFICATION (`DREX-DESIGN.md`)

## 1. Design Principles

DREX-V2 is a **Government-Grade Digital Forensic Workstation and Secure Storage Sanitization Console**.
The interface must convey absolute technical precision, forensic accountability, high informational density, and uncompromised truthfulness.

1. **Evidence-First Architecture**: Every operation, result, digest, and certificate must display its provenance, execution reality state, and independent verification readiness.
2. **Truth-State Integrity**: Never fabricate capability or operational success. The UI displays authentic states: `LIVE`, `SYNTHETIC`, `SIMULATED`, `VERIFIED`, `PARTIAL`, `UNSUPPORTED`, `BACKEND UNAVAILABLE`, and `USB_BRIDGE_LIMITED`.
3. **Safety by Default**: Destructive drive operations require multi-step authorization, boot/system drive lockout tripwires, and exact device-specific safety phrase confirmation.
4. **Air-Gapped Operational Independence**: All design assets, fonts, icons, styles, and scripts are 100% self-contained without external CDN or telemetry dependencies.

---

## 2. Color System & Design Tokens

```css
:root {
  /* Surfaces & Backgrounds */
  --drex-bg-app: #F5F8FC;
  --drex-bg-surface: #FFFFFF;
  --drex-bg-surface-subtle: #F0F4F9;
  --drex-bg-surface-muted: #E8EEF5;
  --drex-bg-deep: #0B1F3A;
  --drex-bg-sidebar: #0B1F3A;
  --drex-bg-topbar: #FFFFFF;

  /* Primary Brand & Workstation Tones */
  --drex-primary: #1769E0;
  --drex-primary-hover: #0E56BE;
  --drex-primary-soft: #EAF3FF;
  --drex-primary-border: #BCD7FF;
  --drex-primary-glow: rgba(23, 105, 224, 0.15);

  /* Truth-State & Forensic Verdict Colors */
  --drex-status-pass: #168A4A;
  --drex-status-pass-soft: #EAF8EE;
  --drex-status-pass-border: #B7E8C7;

  --drex-status-warn: #C77B00;
  --drex-status-warn-soft: #FFF7E6;
  --drex-status-warn-border: #FFE0A3;

  --drex-status-fail: #C62828;
  --drex-status-fail-soft: #FDE8E8;
  --drex-status-fail-border: #F8B4B4;

  --drex-status-unsupported: #65748B;
  --drex-status-unsupported-soft: #F1F5F9;
  --drex-status-unsupported-border: #CBD5E1;

  --drex-status-simulated: #8E44AD;
  --drex-status-simulated-soft: #F5EEF8;
  --drex-status-simulated-border: #D7BDE2;

  /* Typography & Ink */
  --drex-text-main: #17243A;
  --drex-text-muted: #65748B;
  --drex-text-subtle: #94A3B8;
  --drex-text-on-dark: #F8FAFC;
  --drex-text-on-dark-muted: #94A3B8;

  /* Borders & Dividers */
  --drex-border-base: #D7E0EA;
  --drex-border-subtle: #E2E8F0;
  --drex-border-strong: #94A3B8;
  --drex-border-focus: #1769E0;

  /* Radius & Geometry */
  --drex-radius-xs: 2px;
  --drex-radius-sm: 4px;
  --drex-radius-md: 6px;
  --drex-radius-lg: 8px;
  --drex-radius-pill: 9999px;

  /* Elevations */
  --drex-shadow-card: 0 1px 3px rgba(11, 31, 58, 0.06), 0 1px 2px rgba(11, 31, 58, 0.04);
  --drex-shadow-elevated: 0 4px 12px rgba(11, 31, 58, 0.08), 0 1px 3px rgba(11, 31, 58, 0.05);
  --drex-shadow-modal: 0 12px 32px rgba(11, 31, 58, 0.20), 0 2px 6px rgba(11, 31, 58, 0.10);

  /* Typography */
  --drex-font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --drex-font-mono: "Consolas", "SF Mono", "Menlo", "Courier New", monospace;

  /* Layout Dimensions */
  --drex-sidebar-width: 260px;
  --drex-topbar-height: 56px;
}
```

---

## 3. Truth-State Badge Vocabulary

| Badge Class | Semantic Label | Meaning in DREX-V2 |
|---|---|---|
| `.badge-live` | `LIVE` | Real hardware device handle opened with direct Win32 IOCTL access. |
| `.badge-pass` | `PASS — REAL EXECUTION` | Executed directly on target disk/file and cryptographically verified. |
| `.badge-decision` | `PASS — DECISION ENGINE` | Decision engine verified target parameters and selected compliant policy. |
| `.badge-synthetic` | `PASS — SYNTHETIC` | Verified against synthetic image or pure-Python sandbox target. |
| `.badge-warn` | `PARTIAL` | Backend present, but access or elevation constraints prevent full execution. |
| `.badge-unsupported`| `UNSUPPORTED` | Device controller, bus, or topology does not support this operation. |
| `.badge-unavailable`| `BACKEND UNAVAILABLE` | Native binary or dependency is absent on host workstation. |
| `.badge-fail` | `FAIL` | Operation execution or verification readback failed. |

---

## 4. Workstation Components

1. **Top Workstation Bar**:
   - Breadcrumbs: `Workspace / Active View / Active Case`
   - Real-time Workstation Health dot (Green: Operational, Amber: Degraded, Red: Offline)
   - Elevation status badge (`🔒 Administrator` / `⚠ Standard User`)
   - Active Persona Switcher dropdown (Admin, Analyst, Investigator, Operator, Auditor, Judge Demo)
   - Demo Quick-Action button: `✦ Judge Proof Loop`

2. **Persistent 25-View Categorized Navigation**:
   - Organized into 6 technical clusters:
     - **Overview & Story**: Showcase & Overview, Judge Demo Flow, Method Matrix (25)
     - **Case & Evidence Core**: Cases & Timeline, Evidence Vault, Audit Chain, Certificates
     - **Forensic Recovery**: Quick/Forensic Recovery, Raw File Carving, Fragment Recovery, Damaged Media, Hex Inspector
     - **Sanitization & Erasure**: Sanitization Planner, Drive Eraser, File/Folder Eraser, Residue Analyzer
     - **Assurance & Trust**: Independent Verifier, Verification & Entropy, Validation Lab, Performance Lab
     - **Workstation & Infrastructure**: Device Intelligence, Device Manager, Backend Manager, Diagnostics, Settings

3. **64-Sector Storage Block Visualizer**:
   - Visual grid of 64 disk blocks with real-time state coloring:
     - Verified Zeroed: Green border + light green background
     - CSPRNG Overwritten: Blue border + light blue background
     - Slack Neutralized: Purple border + light purple background
     - Unallocated / Intact: Slate grey border
     - Bad / Damaged Sector: Red border + crosshatch

4. **Destructive Safety Gate & Confirmation Phrase**:
   - Requires exact matching of `ERASE-[DEVICE_ID]-[CONFIRM]` before the confirmation button is unlocked.
   - Boot/System disk volumes (`PhysicalDrive0` or active Windows volumes) dynamically disabled and labeled with `SYSTEM DISK PROTECTED`.

---

## 5. Responsive Multi-Surface Strategy

- **Workstation Desktop** ($\ge 1024\text{px}$):
  - Full persistent sidebar, multi-pane tables, split-screen hex inspection, 64-block visualizers.
- **Laptop & Tablet** ($768\text{px} - 1023\text{px}$):
  - Collapsible sidebar with drawer toggle, stacked card grids, horizontal scrolling data tables.
- **Mobile Companion** ($< 768\text{px}$):
  - Mobile bottom navigation / drawer, touch-friendly operation cards, glanceable job meters, remote authorization sign-offs, QR code certificate inspection.
