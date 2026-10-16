# v0.1.5

- Reject nonexistent and unsupported scan targets.
- Report unreadable files and directories as incomplete scans.
- Create report files exclusively, with private permissions on POSIX; refuse existing files, symlinks, and hardlinks.
- Preserve blocking findings (exit 2); incomplete scans without blocking findings exit 1.
- Add regression coverage and require full distribution scans before Trusted Publishing.
