# Tempra RMM — product presentation

A 27-slide overview of Tempra RMM: features, security design, vulnerability management, reporting and operations.

| File | Content |
| --- | --- |
| `index.html` | Standalone view of the whole deck; open it in a browser |
| `deck.json` | Slide order, sections and fonts |
| `deck.css` | Shared styles |
| `slides/*.html` | One file per slide; speaker notes in each slide's `<aside>` |
| `logo-dark.svg` | The console's logo for dark backgrounds, used on the cover and closing slides (copy of `internal/console/web/static/logo-dark.svg`) |
| `screenshots/` | Console screenshots used by the screenshot slides (`-en` and `-it`), taken from a console with demo data |
| `Tempra-RMM-presentazione-IT.pptx` | Italian PowerPoint version of the same deck, with speaker notes |

The source files follow the format of the Claude Slides artifact, where the deck is also published and can be presented or exported to PowerPoint and PDF. `index.html` is generated from them: icons are left out, and the layout may differ slightly from the artifact.

The operator manual is [USER-MANUAL.md](../USER-MANUAL.md); its training deck is [Tempra-RMM-operator-manual-EN.pptx](../Tempra-RMM-operator-manual-EN.pptx).
