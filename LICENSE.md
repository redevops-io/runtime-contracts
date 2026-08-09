# License

`runtime-contracts` is **source-available**, not open source. It is licensed
under the **GNU Affero General Public License v3.0 or later**, as modified by
the **Commons Clause License Condition v1.0**.

- Full AGPL text: [LICENSE](LICENSE)
- The added condition: [LICENSE-COMMONS-CLAUSE](LICENSE-COMMONS-CLAUSE)

Copyright (c) 2025-2026 RedevOps.

    SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause

There is no registered SPDX identifier for this combination — Commons Clause is
a licence *condition*, not an SPDX exception — so a `LicenseRef-` name is used.
Tooling expecting a standard identifier will report this project as
unrecognised, and GitHub will stop labelling it AGPL. That is accurate: it is
not AGPL any more.

Relicensed from Apache-2.0 on 2026-08-08, to match the rest of the runtime.

## What this permits, and what it does not

You may read, run, modify, self-host and redistribute this package, including
inside a company for its own purposes. Every AGPL obligation applies, most
importantly §13: if you modify it and let users interact with the result over a
network, those users are entitled to the source of your modified version.

You may **not sell it**, in the Commons Clause's sense — you may not charge for
the software itself, for hosting it, or for consulting whose value derives
entirely from it.

## What this means for a *contract* package specifically

This is not an ordinary library, and the choice has a consequence worth stating
plainly rather than discovering later.

**A conforming implementation inherits these terms.** This package exists to be
depended on — its own README describes it as "the canonical,
application-neutral contract package for ReDevOps runtime interoperability".
Anything that imports these types to speak the contracts is a work based on
this package, so it takes on both the AGPL's network obligation and the Commons
Clause's restriction on selling.

That is a deliberate boundary and not an oversight, but it narrows the word
"interoperability": these contracts are canonical *within this runtime family*,
not an open standard anyone may implement commercially. A third party who wants
the semantics without the terms has to write their own types, and the golden
fixtures in `golden/` are what would let them prove equivalence.

**One in-family consequence, and it is a design question before it is a legal
one.** `mission-sdk` is Apache-2.0 deliberately, and its `program.py` already
anticipates that "the serialization becomes a thin adapter once
`runtime-contracts` freezes the canonical `MissionProgram`". When that adapter
exists, `mission-sdk` becomes a work based on an AGPL + Commons-Clause package
and its own Apache-2.0 grant stops describing what a downstream user receives.

The licence follows from what the package *is*, which is not yet settled:

    MissionProgram -> adapter -> runtime-contracts
        mission-sdk owns runtime semantics. It is another runtime component,
        and AGPL + Commons-Clause is the honest label.

    MissionProgram DTO <-> serialization helpers
        mission-sdk only translates. It owns no semantics, needs no dependency
        on this package, and Apache-2.0 still describes it correctly.

So the question is whether `mission-sdk` eventually *owns* runtime semantics or
merely *translates* them. That is worth deciding on its own terms rather than
having a licence decide it by accident — which is what happens if the adapter
is written before anyone asks.

Nothing in this repository can settle it. It is recorded here because the first
person to hit it should not have to rediscover it.
