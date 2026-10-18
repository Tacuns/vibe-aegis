---
name: ui-ux-bug-finder
description: Comprehensive UI/UX design, interaction flow, responsive layout, and WCAG 2.2 AA accessibility bug finder for vibe-coded apps. Detects dead buttons, missing loading/empty/error states, mobile overflow traps, z-index collisions, and live DOM layout defects.
---

# UI/UX Design & Browser QA Bug Finder

Audit frontend code and live rendered pages to catch the visual, interaction, state-management, and accessibility bugs frequently introduced during vibe coding.

## 5-Point UI/UX Inspection Protocol

### 1. Interactive Wiring & Dead Control Detection (`HIGH`)

- Scan all `<button>`, `<a>`, `<form>`, dropdowns, and action cards across every page/route.
- Flag any control with `href="#"`, missing `onClick` / `type="submit"`, or stubbed handlers (`() => {}` or `console.log`).
- Verify every modal, drawer, and dialog has a working close button, `Escape` key dismissal, and cleans up body scroll locks on unmount.

### 2. Async State Matrix Completeness (`HIGH` / `MEDIUM`)

Verify that every component performing an async fetch or mutation explicitly implements all 4 states:
- **Loading State**: Skeleton loader or spinner shown; submit/action buttons set `disabled={isLoading}` to prevent duplicate submissions.
- **Empty State**: When a list or query returns `0` items, render a helpful empty state with a clear call-to-action instead of a blank void.
- **Error State**: When a fetch or mutation fails, catch the error and display a user-friendly alert, toast, or inline field error with a retry option (never swallow errors in an empty `catch {}`).
- **Success Feedback**: Confirm mutations give clear visual confirmation (toast, redirect, or optimistic UI update).

### 3. Responsive Layout & Mobile Viewport Audit (`MEDIUM`)

- Check layout behavior at **Mobile (`375x812`)**, **Tablet (`768x1024`)**, and **Desktop (`1440x900`)**.
- Flag hardcoded pixel widths (`w-[600px]`, `min-w-[500px]`, `width: 800px`), un-wrapped wide tables (`overflow-x-auto` missing), or `100vw` containers that cause horizontal scrolling on mobile.
- Ensure touch targets (buttons, nav links, close icons) are at least `44x44px` on mobile screens and do not overlap with fixed bottom bars or floating action buttons.

### 4. Accessibility & Keyboard Ergonomics — WCAG 2.2 AA (`MEDIUM` / `LOW`)

- Verify every `<input>`, `<select>`, and `<textarea>` is linked to a visible `<label>` or `aria-label`.
- Verify every icon-only `<button>` has an `aria-label` and every `<img />` has an `alt` attribute.
- Check color contrast pairings (avoid low-contrast muted text like `text-gray-300` on `bg-white` or `text-gray-600` on `bg-gray-900`).
- Ensure keyboard `Tab` order is logical and focus indicators (`focus-visible:ring-2`) are never stripped without replacement.

### 5. Live Browser DOM Inspection (When Dev Server + Browser Tool Available)

If the app is running locally and `agent-browser` or Playwright is installed:
```bash
agent-browser open http://localhost:3000
agent-browser set viewport 375 812
agent-browser snapshot
agent-browser screenshot --annotate .aegis/mobile-audit.png
agent-browser set viewport 1440 900
agent-browser screenshot --annotate .aegis/desktop-audit.png
agent-browser close
```
Inspect the accessibility tree and screenshots to verify zero overlapping elements, zero console errors, and clean visual alignment.
