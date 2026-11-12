# ADR-002: Hand-written SVG card instead of satori

Status: accepted (deviates from TASKS.md T3.2, which suggested satori + resvg)

## Decision
`src/render/card.ts` writes the 1200x630 card as a hand-built SVG string. No satori, no React/JSX
layout engine, zero runtime dependencies. All dynamic text goes through `xmlEscape`.

## Why
- The brief requires zero runtime dependencies; satori pulls in yoga, fonts and a large tree.
- The layout is fixed (banner, 5 findings, host bar, mini-graph, footer), so absolute positioning
  is simpler and deterministic: the same receipt always renders byte-identical SVG.
- SVG is itself shareable and diffable; `tattle show --card` regenerates it from receipt.json.

## PNG
`@resvg/resvg-js` is an `optionalDependency`, loaded with a dynamic import (marked external in
tsup). If it is importable, `card.png` is written next to `card.svg`; otherwise PNG is skipped
silently. System font stacks are used (`ui-sans-serif`, `ui-monospace`, ...), so glyph metrics vary
by renderer; text is clipped by character count with an ellipsis rather than measured.

## Trade-offs
No exact text measurement, so long findings are truncated conservatively. No embedded fonts, so
the look differs slightly per platform.
