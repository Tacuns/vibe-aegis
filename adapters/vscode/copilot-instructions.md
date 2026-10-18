# Vibe Aegis — VS Code GitHub Copilot Instructions

Always enforce the security and UI/UX quality rules defined in `AGENTS.md`:
- Never expose secrets in `NEXT_PUBLIC_*`, `VITE_*`, or client code.
- Always enforce server-side authentication, ownership checks (no IDOR), and Database Row-Level Security (RLS).
- Always validate inputs, parameterize database queries, and verify webhook signatures.
- Never generate dead UI buttons (`href="#"`, empty `onClick`), and always implement loading (`disabled={isLoading}`), empty, and error states for every async UI action.
- Maintain mobile-first responsive layouts (`320px+`) and WCAG 2.2 AA accessibility (`alt`, `aria-label`, `<label>`, `focus-visible:ring`).
