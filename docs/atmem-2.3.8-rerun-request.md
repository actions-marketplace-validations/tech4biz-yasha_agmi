# AtMem 2.3.8 independent rerun request

This draft records a vendor-submitted request to remeasure AtMem 2.3.8. It is
not an AGMI result and must not be used to update the public scorecard until the
AGMI maintainer independently reproduces it.

## Submitted reproduction

The AtMem maintainer ran the unchanged AGMI 0.6.3 harness at commit
`115493a41a7b41952f92ec07e1ea0932926e194f` against an installed AtMem 2.3.8
wheel built from commit `fdc63de4b5ced0029f2717ee542b9600730ce3fd`.

| Profile | Vendor result |
|---|---:|
| `atmem-chain` | 8/9 reported; T9 snapshot rollback accepted |
| `atmem-chain+checkpoint` | 9/9 reported |

The chain-only limit is intentional: a store cannot distinguish a legitimate
old copy from a whole-store rollback without trusted state outside the
attacker-controlled directory. The checkpoint result applies only while the
checkpoint file remains outside that directory and represents the newest
genuine state.

## Reproduction identities

- Candidate wheel SHA-256:
  `61cf17963177bd7e9c6a5e9fe18a3be30356cc0b2d4d6d373b215a9fe12266dd`
- Raw AGMI scorecard SHA-256:
  `5498bedba335d6c7f40846e17e13413e22d25c298675aa34536c80315f60cceb`
- AGMI adapter SHA-256:
  `3b1880a86e94abc7e1254224be1f92ac3914e120d9dcec219f3ff09df1ff2255`
- AGMI attacks SHA-256:
  `2d860c2b29c180595512dfe3db15dc414b584abd02c8041fd2c3893626133dab`
- Previous pinned AtMem tests SHA-256:
  `bd6978fff34276abd9f19c156a8aca519c7e5e7d9378400f2427a4e2245311ed`

## Requested independent action

1. Wait until AtMem 2.3.8 is published on PyPI.
2. Install the exact `atmem==2.3.8` pin from this draft.
3. Run `PYTHONPATH=. python3 -m pytest tests/test_atmem.py -q`.
4. Run `PYTHONPATH=. python3 agmi/full_runner.py` and inspect both AtMem rows.
5. If independently reproduced, update the scorecard, README, changelog and
   generated site together using AGMI's normal workflow and wording.

Any difference from the submitted result should remain visible in the PR and
be treated as the independent result.

## Independent reproduction (10 October 2026)

Reproduced by the AGMI maintainer from the published PyPI wheel on Linux
(x86_64, Python 3.12.3) and macOS (arm64, Python 3.12): `tests/test_atmem.py`
7 passed on both, and the full runner gives the submitted result for both
rows. The PyPI wheel's SHA-256 is
`05ca2c579be1af55de1da056ae257062417831b2e8eb4f2fda2a6413ba3ee923`, not the
candidate above; its `atmem` package is identical to the v2.3.8 tag, and
against `fdc63de` the only difference is a comment and one version string
in `atmem/control/compat.py`. The public rows, README, changelog and site
were updated from this reproduction.
