# Repository Guidelines

## Project Structure & Module Organization
`kids_mode_mgr.py` contains the full application: Tkinter management UI, Windows service entry point, registry access, and session-lock logic. `kids_mode_mgr.spec` defines the PyInstaller package. `app_icon.ico` is the bundled app icon. Build artifacts land in `build/` and `dist/`; do not edit them manually. Dependencies are pinned in `requirements.txt`. There is no `tests/` directory yet; add one at the repo root if you introduce automated tests.

## Build, Test, and Development Commands
Use the project virtual environment on Windows:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe .\kids_mode_mgr.py
.\venv\Scripts\python.exe .\kids_mode_mgr.py debug
pyinstaller .\kids_mode_mgr.spec
```

The first command installs `pywin32`. Running `kids_mode_mgr.py` launches the GUI and may trigger UAC elevation. `debug` runs the service logic in the foreground for troubleshooting. `pyinstaller` produces `dist\kids_mode_mgr.exe`.

## Coding Style & Naming Conventions
Follow the existing Python style: 4-space indentation, `snake_case` for functions and variables, `PascalCase` for classes, and concise inline comments only where the control flow is non-obvious. Keep imports grouped by standard library, third-party, then local modules. Preserve the current mixed Chinese/English user-facing text unless you are intentionally standardizing a full screen or workflow.

## Testing Guidelines
Automated tests are not checked in today, so every change needs a manual Windows verification pass. At minimum, verify config save/load, service status refresh, and the install/restart/stop/remove flow from an elevated session or disposable VM. If you add tests, use `tests/test_*.py` naming and keep logic-level tests separate from admin-only service checks.

## Commit & Pull Request Guidelines
History is minimal and uses short subjects (`Initial commit`, `PC儿童模式控制工具`). Keep commit titles brief, imperative, and focused on one change. Pull requests should describe the user-visible behavior change, list manual verification steps, and include screenshots for GUI changes. Call out registry, service, or packaging changes explicitly because they affect privileged Windows behavior.

## Security & Configuration Notes
This app writes to `HKLM\SOFTWARE\KidsModeMgr` and manages a Windows service, so development usually requires administrator rights. Avoid testing install/remove flows on a shared machine; use a VM when possible.
