# DREX Forensic Workstation UX 2.0 &middot; UI Design System

**Document Reference:** `PHASE19_UI_DESIGN_SYSTEM.md`  
**Phase:** Phase 19 &mdash; Forensic Workstation UX 2.0 (100&times; UI/UX Optimization)  
**Classification:** Defense & Enterprise Workstation Design Tokens  

---

## 1. Design Philosophy

The DREX UI Design System is engineered specifically for high-stress forensic environments. It balances high-density information architecture with unmistakable visual hierarchies, clear action safety levels, and zero cognitive ambiguity.

### Key Principles:
1. **Investigator-First Priority:** Primary operational workflows (Cases, Vault, Recovery, Shredder) take top visual hierarchy; demo and evaluation loops are isolated.
2. **Defensive Status Semantics:** Color codes strictly convey operational truth states (Blue = Analysis, Green = Verified/Pass, Amber = Caution/Precondition, Red = Destructive/Blocked, Gray = Disabled/Unknown).
3. **Responsive High-Density Grid:** Optimized for multi-monitor workstation resolutions (1366&times;768, 1440&times;900, 1920&times;1080).

---

## 2. Design Tokens (`webui/styles.css`)

### 2.1 Color Palette
```css
:root {
  /* Brand & Shell Palette */
  --drex-primary: #1769e0;             /* Primary Interactive Blue */
  --drex-primary-hover: #1255b8;
  --drex-deep: #0b1f3a;                /* Forensic Navy Shell */
  --drex-deep-surface: #15325b;
  
  /* Background & Surfaces */
  --drex-bg-main: #f8fafc;             /* Neutral Workstation Slate */
  --drex-bg-surface: #ffffff;          /* Card Background */
  --drex-bg-surface-subtle: #f1f5f9;   /* Inset Container */
  
  /* Typography Colors */
  --drex-text-main: #0f172a;           /* Slate 900 */
  --drex-text-muted: #64748b;          /* Slate 500 */
  --drex-text-inverse: #ffffff;
  
  /* Borders */
  --drex-border-base: #e2e8f0;         /* Slate 200 */
  --drex-border-strong: #cbd5e1;       /* Slate 300 */
  
  /* Status Semantics */
  --drex-status-pass: #168a4a;         /* Verified / Pass Green */
  --drex-status-pass-soft: #ecfdf5;
  --drex-status-pass-border: #10b981;
  
  --drex-status-warn: #d97706;         /* Caution / Pending Amber */
  --drex-status-warn-soft: #fffbeb;
  
  --drex-status-fail: #dc2626;         /* Critical / Blocked Red */
  --drex-status-fail-soft: #fef2f2;
}
```

### 2.2 Typography
- **UI & Content Font:** Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif.
- **Monospace & Hex Data Font:** "JetBrains Mono", "Cascadia Code", "SF Mono", Consolas, "Courier New", monospace.

### 2.3 Spacing & Layout Tokens
- **Padding / Margins:** 4px, 8px, 12px, 16px, 24px, 32px.
- **Border Radii:** `--drex-radius-sm: 4px`, `--drex-radius-md: 6px`, `--drex-radius-lg: 8px`.
- **Elevation Shadows:** `--drex-shadow-card: 0 1px 3px rgba(0,0,0,0.05)`, `--drex-shadow-elevated: 0 8px 24px rgba(11,31,58,0.12)`.

---

## 3. Component Design Patterns

### 3.1 Operation Context Bar (`.operation-context-bar`)
```html
<div class="operation-context-bar">
  <div class="context-item"><span class="context-label">CASE:</span> <span class="context-val">DREX-2026-001</span></div>
  <div class="context-item"><span class="context-label">SOURCE:</span> <span class="context-val">\\.\PhysicalDrive1</span></div>
  <div class="context-item"><span class="context-label">WORKFLOW:</span> <span class="context-val">FORENSIC RECOVERY</span></div>
  <div class="context-item"><span class="context-label">METHOD:</span> <span class="context-val">[M17] Quick Recovery</span></div>
  <div class="context-item"><span class="context-label">STATUS:</span> <span class="badge badge-pass">READY</span></div>
</div>
```

### 3.2 6-Step Workflow Stepper (`.drex-stepper`)
- Renders an unambiguous sequential pipeline (`Select Source -> Inspect Details -> Select Method -> Preflight Review -> Scan Telemetry -> Vault Ingest`).
- Active steps highlighted with primary blue circles and bold labels; upcoming steps shown in neutral slate.

### 3.3 Segmented Filter Control (`.segmented-control`)
- Replaces traditional loose tabs with a cohesive rounded segmented switch (`[ 🔍 Operational ] [ 🎯 Evaluation ] [ 🧪 Test ] [ All ]`).

### 3.4 Slide-Out Details Drawer (`.drawer-box`)
- Slides from the right edge with a dark semi-transparent backdrop (`rgba(11,31,58,0.4)`).
- Contains structured key-value metadata, SHA-256 digests in monospace badges, and actionable CTAs.

---

## 4. Responsive Breakpoints & Viewport Adaptation

| Breakpoint | Target Surface | Layout Optimizations Applied |
|:---|:---|:---|
| `> 1440px` | 1080p Desktop Workstation | Full 4-column metric grids, 540px details drawer, 26-item sidebar |
| `1024px – 1439px` | Laptop Displays (1366&times;768, 1440&times;900) | 2-column grids, compact table typography (11px), 480px details drawer |
| `< 1024px` | Tablet / Companion | Sidebar collapses to flyout drawer, topbar switches to compact header |
| `< 768px` | Mobile PWA Companion | Fixed bottom navigation bar (`#mobileNav`), full-screen modal overlays |
