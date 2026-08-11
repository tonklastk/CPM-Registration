# Plant Access Management System — PostgreSQL / Dark Liquid Glass

This version is based on the complete PostgreSQL application and implements:
- Dark theme only; appearance selector removed.
- Stable left sidebar dashboard navigation.
- Native Streamlit sidebar collapse/expand controls are not overridden.
- Dashboard state uses language-independent IDs (`visitor`, `approval`, `admin`).
- English/Thai language selector remains in the sidebar.
- Navigation tiles have fixed dimensions and centered labels.
- Existing PostgreSQL database functions, approval workflow, approved visitor list, admin routing, audit log, email and PDF functionality are retained.

Keep your existing `.streamlit/secrets.toml`; do not replace it with the example file.
