# Week 4 mitigation QA evidence

I ran 101 tests from the enforcement, mitigation runner, firewall, Linux transport adapter, recovery and polling suites on the draft integration revision `89cb7f4534e35f2e5a9d4d1011297f1e4f95e899`. All passed on macOS with Python 3.12.15 using fixtures and test transports. [Draft integration PR](https://github.com/aydsman/ML-DDoS-Detector/pull/47).

| Acceptance area | Regression coverage |
| --- | --- |
| Legitimate sources and benign decisions | Protected source tests, incomplete policy settings, missing aggregate evidence, monitor-only mode without firewall construction |
| Temporary block and expiry | Fixture capture through inference and policy into a test firewall, expiry on idle ticks, duplicate and cap handling |
| Failure, disable and cleanup | Cleanup after installation failures and signal interruption, audit failure blocks installation, monitor-only transition preserves existing expiry, journal recovery after failed cleanup |
| Client recovery | Requires matching request records and observed confirmed block/removal events in the integrated Linux run |

The [Week 4 card](https://trello.com/c/FbWs7nY6) still requires the approved settings from [issue #50](https://github.com/aydsman/ML-DDoS-Detector/issues/50), policy-driven Linux acceptance from [issue #51](https://github.com/aydsman/ML-DDoS-Detector/issues/51) and a matched service trace. The source-count evidence tracked in [issue #49](https://github.com/aydsman/ML-DDoS-Detector/issues/49) is the first dependency. Vince reported that the original raw S1–S3 captures were lost. The surviving window exports contain aggregate features. The capture owner needs a decision about the scope of replacement sessions before providing the missing source counts. [Handoff and owner decision](https://github.com/aydsman/ML-DDoS-Detector/issues/49#issuecomment-7206990025). The saved benign monitor checks and the earlier standalone firewall reports cover their respective components.
