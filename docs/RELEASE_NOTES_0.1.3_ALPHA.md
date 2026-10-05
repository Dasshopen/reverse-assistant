# Reverse Assistant 0.1.3 Alpha

Windows x64 test build. Clean-Windows upgrade validation is pending.

## Added

- Automatic startup checks for application updates, with an opt-out setting.
- A settings panel for checking, downloading and installing signed updates.
- Signature verification before installation and explicit confirmation before
  the application closes. Installation waits for ongoing operations to finish.
- Readable MSVC and GCC/Clang C++ proposals, with full signatures and original
  symbols retained in expandable details. Decoding is local and cached.

## Fixed

- Background analysis helpers no longer request a Windows console window.
- Includes the automatic Java setup checksum fix from 0.1.1.

## Important

Install this build manually once if your current version has no updater.
Subsequent updates require a valid public update feed and a higher-version
signed release. No update is silently installed at startup.

Update signatures do not remove Windows warnings for an unsigned installer.
AI is optional. Confidence thresholds and evidence-based naming safeguards
are unchanged. Back up important projects before testing an Alpha upgrade.
