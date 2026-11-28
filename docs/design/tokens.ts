/**
 * Drawbridge design tokens — upgrade v0.2.
 * Drop-in replacement for docs/design/tokens.ts.
 *
 * DELTA vs main@5b0ff23:
 *   Color tokens unchanged.
 *   type/space values are CSS clamp() / unitless line-heights (see tokens.css).
 *   Added type["3xl"], space[16], breakpoint.xs/sm/lg, container, containerPad.
 *   breakpoint.md stays 768; xl stays 1200 (dashboard split).
 *   Inline styles that used scale.topbarH may keep "56px" or switch to
 *   "var(--db-topbar-h)". Do not hard-code old px type sizes in new CSS.
 */

export const color = {
  bg: "var(--db-bg)",
  bgElevated: "var(--db-bg-elevated)",
  bgSunken: "var(--db-bg-sunken)",
  surface: "var(--db-surface)",
  surfaceHover: "var(--db-surface-hover)",
  border: "var(--db-border)",
  borderStrong: "var(--db-border-strong)",
  text: "var(--db-text)",
  textMuted: "var(--db-text-muted)",
  textFaint: "var(--db-text-faint)",
  accent: "var(--db-accent)",
  accentHover: "var(--db-accent-hover)",
  accentMuted: "var(--db-accent-muted)",
  accentOn: "var(--db-accent-on)",
  warn: "var(--db-warn)",
  warnMuted: "var(--db-warn-muted)",
  warnOn: "var(--db-warn-on)",
  danger: "var(--db-danger)",
  dangerMuted: "var(--db-danger-muted)",
  dangerOn: "var(--db-danger-on)",
  taint: "var(--db-taint)",
  taintMuted: "var(--db-taint-muted)",
  held: "var(--db-held)",
  heldMuted: "var(--db-held-muted)",
  denied: "var(--db-denied)",
  deniedMuted: "var(--db-denied-muted)",
  approved: "var(--db-approved)",
  approvedMuted: "var(--db-approved-muted)",
  trusted: "var(--db-trusted)",
} as const;

export const type = {
  font: "var(--db-font)",
  mono: "var(--db-font-mono)",
  xs: "var(--db-text-xs)",
  sm: "var(--db-text-sm)",
  md: "var(--db-text-md)",
  lg: "var(--db-text-lg)",
  xl: "var(--db-text-xl)",
  "2xl": "var(--db-text-2xl)",
  "3xl": "var(--db-text-3xl)",
  lhXs: "var(--db-lh-xs)",
  lhSm: "var(--db-lh-sm)",
  lhMd: "var(--db-lh-md)",
  lhLg: "var(--db-lh-lg)",
  lhXl: "var(--db-lh-xl)",
  lh2xl: "var(--db-lh-2xl)",
  lh3xl: "var(--db-lh-3xl)",
  trackingTight: "var(--db-tracking-tight)",
  trackingMono: "var(--db-tracking-mono)",
} as const;

export const space = {
  1: "var(--db-space-1)",
  2: "var(--db-space-2)",
  3: "var(--db-space-3)",
  4: "var(--db-space-4)",
  5: "var(--db-space-5)",
  6: "var(--db-space-6)",
  8: "var(--db-space-8)",
  10: "var(--db-space-10)",
  12: "var(--db-space-12)",
  16: "var(--db-space-16)",
} as const;

export const radius = {
  sm: "var(--db-radius-sm)",
  md: "var(--db-radius-md)",
  lg: "var(--db-radius-lg)",
  pill: "var(--db-radius-pill)",
} as const;

export const breakpoint = {
  xs: 360,
  sm: 480,
  md: 768,
  lg: 1024,
  xl: 1200,
} as const;

export const container = {
  max: "var(--db-container)",
  pad: "var(--db-container-pad)",
} as const;

/** Layout constants used by the dashboard (packages/dashboard/src/app.tsx). */
export const scale = {
  topbarH: "var(--db-topbar-h)",
  rowH: 48,
  btnH: 36,
  btnHTouch: 44,
  queueW: 340,
  historyW: 360,
  radius: 10,
} as const;
