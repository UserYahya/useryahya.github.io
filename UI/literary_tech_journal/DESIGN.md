---
name: Literary Tech Journal
colors:
  surface: '#fbf9f4'
  surface-dim: '#dbdad5'
  surface-bright: '#fbf9f4'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f5f3ee'
  surface-container: '#f0eee9'
  surface-container-high: '#eae8e3'
  surface-container-highest: '#e4e2dd'
  on-surface: '#1b1c19'
  on-surface-variant: '#4f4536'
  inverse-surface: '#30312e'
  inverse-on-surface: '#f2f1ec'
  outline: '#817564'
  outline-variant: '#d3c4b1'
  surface-tint: '#7d5700'
  primary: '#7d5700'
  on-primary: '#ffffff'
  primary-container: '#d9a441'
  on-primary-container: '#573c00'
  inverse-primary: '#f5bd58'
  secondary: '#984350'
  on-secondary: '#ffffff'
  secondary-container: '#fe95a2'
  on-secondary-container: '#782a38'
  tertiary: '#4f5e81'
  on-tertiary: '#ffffff'
  tertiary-container: '#9eacd3'
  on-tertiary-container: '#314061'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#ffdeaa'
  primary-fixed-dim: '#f5bd58'
  on-primary-fixed: '#271900'
  on-primary-fixed-variant: '#5f4100'
  secondary-fixed: '#ffd9dc'
  secondary-fixed-dim: '#ffb2ba'
  on-secondary-fixed: '#400011'
  on-secondary-fixed-variant: '#7a2c3a'
  tertiary-fixed: '#d9e2ff'
  tertiary-fixed-dim: '#b7c6ee'
  on-tertiary-fixed: '#0a1a3a'
  on-tertiary-fixed-variant: '#384668'
  background: '#fbf9f4'
  on-background: '#1b1c19'
  surface-variant: '#e4e2dd'
typography:
  display-lg:
    fontFamily: Tiro Bangla
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 64px
    letterSpacing: -0.01em
  headline-lg:
    fontFamily: Tiro Bangla
    fontSize: 36px
    fontWeight: '600'
    lineHeight: 48px
  headline-md:
    fontFamily: Tiro Bangla
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 40px
  headline-sm:
    fontFamily: Tiro Bangla
    fontSize: 22px
    fontWeight: '500'
    lineHeight: 32px
  body-lg:
    fontFamily: Hind Siliguri
    fontSize: 20px
    fontWeight: '400'
    lineHeight: 36px
  body-md:
    fontFamily: Hind Siliguri
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 32px
  label-lg:
    fontFamily: Hind Siliguri
    fontSize: 14px
    fontWeight: '600'
    lineHeight: 20px
    letterSpacing: 0.05em
  display-lg-mobile:
    fontFamily: Tiro Bangla
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 42px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  identity-rail-width: 280px
  content-max-width: 800px
  gutter: 2rem
  stack-sm: 1rem
  stack-md: 2.5rem
  stack-lg: 5rem
---

## Brand & Style
The design system reflects a convergence of ancient literary tradition and modern technological discourse. It is tailored for an intellectual audience that values deep-reading experiences, purposeful travel, and open-source knowledge. 

The aesthetic is **Editorial Minimalism** with a **Tactile Journal** influence. It prioritizes the "written word" over decorative elements. The visual signature is defined by "Ink and Paper"—using high-contrast serif typography and organic, ink-brush textures for subtle accents. The emotional response should be one of quiet authority, focus, and cultural groundedness.

## Colors
The palette is inspired by traditional manuscripts and South Asian spices. 

- **Paper White (#FAF8F3):** Acts as the primary canvas, providing a warm, low-strain reading surface that feels more like a physical book than a digital screen.
- **Ink Indigo (#1B2A4A):** Used for primary headings and the dark-mode foundation. It offers a deep, scholarly alternative to pure black.
- **Turmeric Gold (#D9A441):** The primary interactive accent. Use for call-to-actions, active navigation states, and key highlights.
- **Deep Maroon (#7C2D3B):** Reserved for semantic depth—hover states, critical markers, and secondary accents that require a "stamped" or "wax-seal" feel.
- **Slate Grey (#4A4A45):** Specifically tuned for Bengali legibility as body text, providing enough contrast without being jarring against the Paper White background.

## Typography
Typography is the cornerstone of this design system. Bengali script requires generous vertical space (leading) to accommodate complex conjuncts and vowel signs (kar/fala) without crowding.

- **Headlines:** Use **Tiro Bangla**. Its serif terminals provide a literary, authoritative rhythm. Headlines should use Ink Indigo for maximum impact.
- **Body Text:** Use **Hind Siliguri**. This sans-serif is highly legible at smaller sizes and maintains a clean, modern profile.
- **Special Treatment:** Article intros should use the `body-lg` scale. Use a subtle **ink-brush underline** (SVG mask or background-image) for `headline-md` when used as section starters.

## Layout & Spacing
The layout adopts an asymmetrical, editorial structure.

- **Desktop Identity Rail:** A sticky left-side column (280px) houses the brand identity, navigation, and social links. This remains fixed while the right-side content scrolls.
- **Content Column:** The main reading area is constrained to a maximum of 800px to maintain an ideal line length for long-form reading.
- **Mobile Navigation:** On screens smaller than 1024px, the identity rail collapses into a simplified top bar with a Turmeric Gold accent line.
- **Journal Index:** Blog listings must not use cards. Use a vertical list of entries with a date-title-summary structure, separated by thin, 1px Slate Grey lines that stop 20% short of the container edges to feel hand-drawn.

## Elevation & Depth
This system avoids heavy drop shadows and modern "floating" effects. Depth is communicated through **Tonal Layers** and **Line Work**.

- **Surfaces:** Use flat Paper White for the main background. The Identity Rail can use a very subtle 2% tint of Ink Indigo to create a soft separation.
- **Lines:** Use 1px borders in Slate Grey (at 20% opacity) to define boundaries. 
- **Interactive Depth:** Instead of rising on hover, elements should respond with a color shift (Turmeric Gold to Deep Maroon) or the appearance of a brush-stroke underline.

## Shapes
The shape language is primarily **Rectilinear and Organic**. 

- **Structural Elements:** Use sharp corners or very minimal (4px) rounding for containers and buttons to maintain a "cut paper" aesthetic.
- **Organic Accents:** Use SVG-based brush strokes for button backgrounds or tag containers to break the rigidity of the digital grid.
- **Images:** Photography should use sharp corners with a subtle 1px inner border to simulate a printed photograph in a journal.

## Components

- **Primary Buttons:** Solid Turmeric Gold background with Ink Indigo text. No rounded corners. On hover, background shifts to Deep Maroon and text to Paper White.
- **Journal Index Items:** Each entry consists of a vertical stack: Label (Category in Maroon), Headline (Indigo), and Summary (Slate Grey). Use a brush-stroke underline for the headline on hover.
- **Tags/Chips:** Small, uppercase labels with a 1px Slate Grey border. No background fill unless active (then use Turmeric Gold).
- **Sticky Identity Rail:** Must contain a high-contrast logo/monogram in Ink Indigo, followed by a vertical navigation list.
- **Input Fields:** Single bottom-border only (1px Slate Grey). Focus state changes border to Turmeric Gold with a slight thickness increase (2px).
- **Blockquotes:** Indented with a thick (4px) Deep Maroon left border. Typography switches to `headline-sm` in italic (if available) or slightly reduced opacity Ink Indigo.