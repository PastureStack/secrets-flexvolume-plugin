# Origin and attribution

This file records origin and legal facts. Historical names appear here only where required for attribution and provenance.

## Upstream

The repository is a GitHub fork of `rancher/secrets-flexvol`. The preserved upstream boundary is commit `63806ab01d586747009565416cffb53a368c0748`. PastureStack changes are consolidated into one later commit while the upstream commits, authorship, dates, and license notices remain intact.

Copyright (c) 2014-2016 Rancher Labs, Inc.

The upstream source was distributed under the Apache License, Version 2.0. The root `LICENSE` is preserved byte for byte.

## Historical snapshot and tag note

The imported migration snapshot was commit `ae07485af7e8e49ad9def220a7a097fb26415b36` with tree `ff0962b098dd44193ac628ec9f775fdc03cd9a5a`. No historical tag points to that commit. Annotated tag `v0.0.6` resolves to its parent commit rather than that snapshot, so the current release uses a new PastureStack version and does not reuse the historical tag.

## Dependency evidence

Four byte-preserved dependency license artifacts found in the historical vendor tree remain under `LICENSES/historical` and are cataloged in `LICENSES/HISTORICAL-MANIFEST.json`. They are provenance evidence only. The current implementation imports only the Go standard library and does not compile, link, copy, or execute the historical vendored packages.

The Go toolchain license and patent notice are preserved under `LICENSES`. Release validation verifies the recorded byte lengths and SHA-256 values for the root license, historical artifacts, and Go notices.

## Release gates

A release must preserve the root license and attribution, pass the legal-artifact verifier, contain no historical vendored implementation in the current tree, retain exactly one PastureStack commit after the upstream boundary, pass source and binary privacy scans, pass repeated tests and race detection, and publish an image whose semantic version is used directly by the catalog.
