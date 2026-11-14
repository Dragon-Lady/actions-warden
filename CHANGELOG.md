# Changelog

## 0.1.6

- Inspect npm scripts and shell files for wfx-loot delivery and payload markers,
  including marker combinations without callback addresses.
- Flag bulk secret-context exports and cover those exports in the existing
  secret/network co-occurrence rule.
- Preserve incomplete coverage for malformed manifests and skipped symlinks;
  reject unsupported single-file targets explicitly.
- Add inert positive and negative regression fixtures and historical-response
  guidance. Static findings do not prove execution or credential theft.
- Disable persisted checkout credentials in the test job and use Push Guard
  0.4.4 for distribution checks.
