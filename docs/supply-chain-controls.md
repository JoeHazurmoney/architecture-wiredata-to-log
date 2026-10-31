# Supply-chain controls: NIST SP 800-53 Rev 5 mapping

For a security assessor working under the Risk Management Framework (NIST SP 800-37 Rev 2), or
any framework that uses the NIST SP 800-53 Rev 5 catalog. For each supply-chain control or
enhancement, this page gives:

* the control's text;
* how wd2l meets it, and the evidence;
* any gap, linked to [supply-chain-security.md](supply-chain-security.md#gaps-and-how-to-close-them).

The SLSA walkthrough, the supply chain end to end and the full list of gaps are in
[supply-chain-security.md](supply-chain-security.md). The audit controls (AU-2 to AU-12) are
mapped in [audit-and-health.md, section 11](audit-and-health.md#11-control-mapping-examples) and
aren't repeated here.

**As of:** 1.4.0, 2026-10-30.

**Which text:**
* **Source:** NIST SP 800-53 Rev 5.2.0, from NIST's OSCAL catalog
  ([`usnistgov/oscal-content` v1.6.0](https://github.com/usnistgov/oscal-content/tree/v1.6.0/nist.gov/SP800-53/rev5/json),
  `NIST_SP-800-53_rev5_catalog.json`).
* **Baselines:** from the same release's SP 800-53B LOW, MODERATE and HIGH profiles.
* **How it was copied:** each statement was rendered from the catalog by script, not retyped.
* **Parameters:** shown as the publication shows them, `[Assignment: organization-defined …]` or
  `[Selection: …]`. Supplemental guidance and related controls are left out; see the catalog.

**What this is not:** a claim of compliance, or a choice of baseline. The security owner decides
which controls apply and sets the organization-defined values. Where wd2l's part is only evidence
for a control the customer owns, the status says **Customer** or **Shared**.

**Status values:**

| Status | Meaning |
|---|---|
| Met | wd2l's part of the control is done, with evidence |
| Partly met | Some parts are done; the rest is a named gap or the customer's |
| Gap | wd2l's part isn't done; see the linked gap |
| Customer | The control is the customer's; wd2l supplies evidence or tools |
| Not applicable | Doesn't apply to software delivered this way |

## Summary

Baseline: the SP 800-53B baselines that include the control (L, M, H), or – for none. Provided by: **wd2l** (this repository and its release process), **Customer** (the site or organization that runs wd2l), or **Shared**.

| Control | Title | Baseline | Status | Provided by |
|---|---|---|---|---|
| [AC-5](#ac-5-separation-of-duties) | Separation of Duties | M, H | Gap | Shared |
| [AC-6](#ac-6-least-privilege) | Least Privilege | M, H | Met | wd2l |
| [AC-6(1)](#ac-61-authorize-access-to-security-functions) | Authorize Access to Security Functions | M, H | Partly met | Shared |
| [AU-10](#au-10-non-repudiation) | Non-repudiation | H | Met | wd2l |
| [CM-2](#cm-2-baseline-configuration) | Baseline Configuration | L, M, H | Met | Shared |
| [CM-3](#cm-3-configuration-change-control) | Configuration Change Control | M, H | Partly met | wd2l |
| [CM-3(2)](#cm-32-testing-validation-and-documentation-of-changes) | Testing, Validation, and Documentation of Changes | M, H | Met | wd2l |
| [CM-5](#cm-5-access-restrictions-for-change) | Access Restrictions for Change | L, M, H | Met | Shared |
| [CM-5(4)](#cm-54-dual-authorization) | Dual Authorization | – | Gap | wd2l |
| [CM-6](#cm-6-configuration-settings) | Configuration Settings | L, M, H | Met | Shared |
| [CM-8](#cm-8-system-component-inventory) | System Component Inventory | L, M, H | Met | wd2l |
| [CM-14](#cm-14-signed-components) | Signed Components | – | Partly met | Shared |
| [PM-30](#pm-30-supply-chain-risk-management-strategy) | Supply Chain Risk Management Strategy | – | Customer | Customer |
| [RA-5](#ra-5-vulnerability-monitoring-and-scanning) | Vulnerability Monitoring and Scanning | L, M, H | Met | Shared |
| [RA-5(2)](#ra-52-update-vulnerabilities-to-be-scanned) | Update Vulnerabilities to Be Scanned | L, M, H | Met | wd2l |
| [RA-5(3)](#ra-53-breadth-and-depth-of-coverage) | Breadth and Depth of Coverage | – | Partly met | wd2l |
| [RA-5(11)](#ra-511-public-disclosure-program) | Public Disclosure Program | L, M, H | Gap | wd2l |
| [RA-9](#ra-9-criticality-analysis) | Criticality Analysis | M, H | Partly met | Shared |
| [SA-3](#sa-3-system-development-life-cycle) | System Development Life Cycle | L, M, H | Partly met | Shared |
| [SA-8](#sa-8-security-and-privacy-engineering-principles) | Security and Privacy Engineering Principles | L, M, H | Met | wd2l |
| [SA-10](#sa-10-developer-configuration-management) | Developer Configuration Management | M, H | Met | wd2l |
| [SA-10(1)](#sa-101-software-and-firmware-integrity-verification) | Software and Firmware Integrity Verification | – | Met | wd2l |
| [SA-10(4)](#sa-104-trusted-generation) | Trusted Generation | – | Met | wd2l |
| [SA-10(5)](#sa-105-mapping-integrity-for-version-control) | Mapping Integrity for Version Control | – | Partly met | wd2l |
| [SA-10(6)](#sa-106-trusted-distribution) | Trusted Distribution | – | Met | wd2l |
| [SA-11](#sa-11-developer-testing-and-evaluation) | Developer Testing and Evaluation | M, H | Met | wd2l |
| [SA-11(1)](#sa-111-static-code-analysis) | Static Code Analysis | – | Gap | wd2l |
| [SA-11(2)](#sa-112-threat-modeling-and-vulnerability-analyses) | Threat Modeling and Vulnerability Analyses | – | Partly met | wd2l |
| [SA-11(4)](#sa-114-manual-code-reviews) | Manual Code Reviews | – | Gap | wd2l |
| [SA-11(8)](#sa-118-dynamic-code-analysis) | Dynamic Code Analysis | – | Partly met | wd2l |
| [SA-15](#sa-15-development-process-standards-and-tools) | Development Process, Standards, and Tools | M, H | Met | wd2l |
| [SA-15(3)](#sa-153-criticality-analysis) | Criticality Analysis | M, H | Partly met | Shared |
| [SA-15(5)](#sa-155-attack-surface-reduction) | Attack Surface Reduction | – | Met | wd2l |
| [SA-15(7)](#sa-157-automated-vulnerability-analysis) | Automated Vulnerability Analysis | – | Met | wd2l |
| [SA-15(11)](#sa-1511-archive-system-or-component) | Archive System or Component | – | Met | wd2l |
| [SA-22](#sa-22-unsupported-system-components) | Unsupported System Components | L, M, H | Partly met | Shared |
| [SC-12](#sc-12-cryptographic-key-establishment-and-management) | Cryptographic Key Establishment and Management | L, M, H | Partly met | Shared |
| [SC-13](#sc-13-cryptographic-protection) | Cryptographic Protection | L, M, H | Met | Shared |
| [SI-2](#si-2-flaw-remediation) | Flaw Remediation | L, M, H | Met | Shared |
| [SI-2(2)](#si-22-automated-flaw-remediation-status) | Automated Flaw Remediation Status | M, H | Met | Shared |
| [SI-7](#si-7-software-firmware-and-information-integrity) | Software, Firmware, and Information Integrity | M, H | Met | Shared |
| [SI-7(1)](#si-71-integrity-checks) | Integrity Checks | M, H | Partly met | Shared |
| [SI-7(6)](#si-76-cryptographic-protection) | Cryptographic Protection | – | Met | wd2l |
| [SI-7(12)](#si-712-integrity-verification) | Integrity Verification | – | Customer | Customer |
| [SI-7(15)](#si-715-code-authentication) | Code Authentication | H | Partly met | Shared |
| [SR-1](#sr-1-policy-and-procedures) | Policy and Procedures | L, M, H | Customer | Customer |
| [SR-2](#sr-2-supply-chain-risk-management-plan) | Supply Chain Risk Management Plan | L, M, H | Customer | Customer |
| [SR-2(1)](#sr-21-establish-scrm-team) | Establish SCRM Team | L, M, H | Customer | Customer |
| [SR-3](#sr-3-supply-chain-controls-and-processes) | Supply Chain Controls and Processes | L, M, H | Met | Shared |
| [SR-4](#sr-4-provenance) | Provenance | – | Met | wd2l |
| [SR-4(1)](#sr-41-identity) | Identity | – | Partly met | wd2l |
| [SR-4(2)](#sr-42-track-and-trace) | Track and Trace | – | Met | wd2l |
| [SR-4(3)](#sr-43-validate-as-genuine-and-not-altered) | Validate as Genuine and Not Altered | – | Met | Shared |
| [SR-4(4)](#sr-44-supply-chain-integrity--pedigree) | Supply Chain Integrity — Pedigree | – | Met | wd2l |
| [SR-5](#sr-5-acquisition-strategies-tools-and-methods) | Acquisition Strategies, Tools, and Methods | L, M, H | Partly met | Shared |
| [SR-5(2)](#sr-52-assessments-prior-to-selection-acceptance-modification-or-update) | Assessments Prior to Selection, Acceptance, Modification, or Update | – | Met | wd2l |
| [SR-6](#sr-6-supplier-assessments-and-reviews) | Supplier Assessments and Reviews | M, H | Partly met | Shared |
| [SR-6(1)](#sr-61-testing-and-analysis) | Testing and Analysis | – | Met | wd2l |
| [SR-8](#sr-8-notification-agreements) | Notification Agreements | L, M, H | Gap | Shared |
| [SR-9](#sr-9-tamper-resistance-and-detection) | Tamper Resistance and Detection | H | Met | Shared |
| [SR-9(1)](#sr-91-multiple-stages-of-system-development-life-cycle) | Multiple Stages of System Development Life Cycle | H | Met | wd2l |
| [SR-10](#sr-10-inspection-of-systems-or-components) | Inspection of Systems or Components | L, M, H | Partly met | Customer |
| [SR-11](#sr-11-component-authenticity) | Component Authenticity | L, M, H | Partly met | Shared |
| [SR-11(1)](#sr-111-anti-counterfeit-training) | Anti-counterfeit Training | L, M, H | Customer | Customer |
| [SR-11(2)](#sr-112-configuration-control-for-component-service-and-repair) | Configuration Control for Component Service and Repair | L, M, H | Not applicable | Customer |
| [SR-12](#sr-12-component-disposal) | Component Disposal | L, M, H | Partly met | Shared |

Totals: Met 33, Partly met 20, Gap 6, Customer 6, Not applicable 1 (66 controls and enhancements).

## AC: Access Control

### AC-5 Separation of Duties

*Baseline: Moderate, High. Status: **Gap**. Provided by: Shared.*

> a. Identify and document [Assignment: organization-defined duties of individuals requiring separation]; and  
> b. Define system access authorizations to support separation of duties.

**How wd2l meets it:** In part. Duties are written down: the security owner holds the key and approves the `release` and `security-review` gates; only the admin role may create `v*` tags; Actions can't approve pull requests. Today one person holds all of these roles.

**Evidence:** [releasing.md, one-time setup](releasing.md#one-time-setup); the `v*` tag ruleset; the `release` environment's required reviewer.

**Gap:** [G2](supply-chain-security.md#gaps-and-how-to-close-them): the tagger, the approver and the publisher are one person, and `prevent_self_review` is off.

### AC-6 Least Privilege

*Baseline: Moderate, High. Status: **Met**. Provided by: wd2l.*

> Employ the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) that are necessary to accomplish assigned organizational tasks.

**How wd2l meets it:** For the build and release pipeline. The default token is read-only. Each workflow and job asks only for the permissions it uses. Only `attest.yml` may hold an OIDC token. The signing key reaches only the two gated jobs. The `assets` job, which builds the manifest, has no secrets and only reads. The scanners don't get registry credentials. In the product, the receiver runs unprivileged with only `CAP_NET_RAW` ([accreditation-notes.md](accreditation-notes.md#what-enclave-2-trusts)).

**Evidence:** `test_only_attest_yml_can_get_an_oidc_token`, `test_assets_are_made_once_without_secrets_or_a_token`, `test_no_workflow_hands_its_secrets_on`; [`packaging/ci/tool`](../packaging/ci/tool) (`PUSHERS`).

### AC-6(1) Authorize Access to Security Functions

*Baseline: Moderate, High. Status: **Partly met**. Provided by: Shared.*

> Authorize access for [Assignment: organization-defined individuals or roles] to:  
> (a) [Assignment: organization-defined security functions (deployed in hardware, software, and firmware)]; and  
> (b) [Assignment: organization-defined security-relevant information].

**How wd2l meets it:** The security functions of the supply chain are signing, attesting, approving a release and approving a security review. Access to each is limited: the key is an environment secret of `release`; the OIDC token exists only in `attest.yml`; the gates name a required reviewer; `v*` tags are admin-only.

**Evidence:** as for AC-6; [ADR-0006, key management](decisions/0006-release-artifacts-and-signing.md#key-management).

**Gap:** [G3](supply-chain-security.md#gaps-and-how-to-close-them): admins can bypass `security-review`.

## AU: Audit and Accountability

### AU-10 Non-repudiation

*Baseline: High. Status: **Met**. Provided by: wd2l.*

> Provide irrefutable evidence that an individual (or process acting on behalf of an individual) has performed [Assignment: organization-defined actions to be covered by non-repudiation].

**How wd2l meets it:** For the actions "built this file" and "released this version":
* every release file is covered by a signature with the release key, and by GitHub's L3 provenance;
* the keyless signatures and attestations are entries in Sigstore's public transparency log (Rekor), tied to `attest.yml` at the tag;
* the release manifest records who approved each gate;
* GitHub's release attestation records the published release.

**Evidence:** [ADR-0006](decisions/0006-release-artifacts-and-signing.md), [ADR-0007](decisions/0007-slsa-build-l3.md), [ADR-0008](decisions/0008-release-manifest.md); `gh release verify v<version>`.

**Limit:** the key signatures carry no timestamp ([G12](supply-chain-security.md#gaps-and-how-to-close-them)).

## CM: Configuration Management

### CM-2 Baseline Configuration

*Baseline: Low, Moderate, High. Status: **Met**. Provided by: Shared.*

> a. Develop, document, and maintain under configuration control, a current baseline configuration of the system; and  
> b. Review and update the baseline configuration of the system:  
> &emsp;&emsp;1. [Assignment: organization-defined frequency];  
> &emsp;&emsp;2. When required due to [Assignment: organization-defined circumstances]; and  
> &emsp;&emsp;3. When system components are installed or upgraded.

**How wd2l meets it:** For what wd2l ships. Every input is pinned and under version control: base images and tool images by digest, actions by commit SHA, Python tools by hash, runner labels by version. Each release records the baseline in its manifest: the commit, every file's SHA-256, the image and base digests, and the pinned actions and tools. Dependabot reviews the pins each week, and each release starts by bringing them up to date. The site's own baseline of its hosts is the customer's.

**Evidence:** [releasing.md, keeping the pins current](releasing.md#keeping-the-pins-current); [ADR-0008](decisions/0008-release-manifest.md); `test_no_job_runs_on_a_moving_runner_label`.

### CM-3 Configuration Change Control

*Baseline: Moderate, High. Status: **Partly met**. Provided by: wd2l.*

> a. Determine and document the types of changes to the system that are configuration-controlled;  
> b. Review proposed configuration-controlled changes to the system and approve or disapprove such changes with explicit consideration for security and privacy impact analyses;  
> c. Document configuration change decisions associated with the system;  
> d. Implement approved configuration-controlled changes to the system;  
> e. Retain records of configuration-controlled changes to the system for [Assignment: organization-defined time period];  
> f. Monitor and review activities associated with configuration-controlled changes to the system; and  
> g. Coordinate and provide oversight for configuration change control activities through [Assignment: organization-defined configuration change control element] that convenes [Selection (one or more): [Assignment: organization-defined frequency]; when [Assignment: organization-defined configuration change conditions]].

**How wd2l meets it:**
* **What's controlled:** every change to `main`, which takes squash PRs only, with `ci-ok` and `pr-title` green and no bypass.
* **Records:** each change closes an issue, and the PR title is a Conventional Commit. The issue, the PR and the squash commit are kept, and each release's manifest and changelog list them.
* **Security impact:** a change that brings in a fixable High or Critical stops at the `security-review` gate.

**Evidence:** the `main` ruleset; [releasing.md, conventions](releasing.md#conventions); [ADR-0008](decisions/0008-release-manifest.md).

**Gap:** [G1](supply-chain-security.md#gaps-and-how-to-close-them): no one but the author reviews or approves a change. There is no change control board (part g); the customer may name one.

### CM-3(2) Testing, Validation, and Documentation of Changes

*Baseline: Moderate, High. Status: **Met**. Provided by: wd2l.*

> Test, validate, and document changes to the system before finalizing the implementation of the changes.

**How wd2l meets it:** Every PR, and every release again from its tag, runs:
* the unit tests on Python 3.9 and 3.12, with no test allowed to skip;
* the namespace lab;
* the image checks, on both platforms;
* the FIPS test run;
* the RPM install tests on EL9 and EL10.

The results stay with the run, and the release manifest lists the PRs.

**Evidence:** [releasing.md, how a release is built](releasing.md#how-a-release-is-built); [`tests.yml`](../.github/workflows/tests.yml), [`image.yml`](../.github/workflows/image.yml), [`rpm.yml`](../.github/workflows/rpm.yml).

### CM-5 Access Restrictions for Change

*Baseline: Low, Moderate, High. Status: **Met**. Provided by: Shared.*

> Define, document, approve, and enforce physical and logical access restrictions associated with changes to the system.

**How wd2l meets it:**
* **Logical restrictions** are defined and enforced by the forge: `main` changes only through a PR, `v*` tags only by the admin role, and the signing jobs only after the owner's approval in the `release` environment.
* **Actions** must be pinned by SHA.
* **Pull requests from forks** wait for approval and get no secrets.
* **Physical restrictions** on the forge are GitHub's (inherited).

**Evidence:** the rulesets and environments ([releasing.md, one-time setup](releasing.md#one-time-setup)).

### CM-5(4) Dual Authorization

*Baseline: none (not in a 800-53B baseline). Status: **Gap**. Provided by: wd2l.*

> Enforce dual authorization for implementing changes to [Assignment: organization-defined system components and system-level information].

**How wd2l meets it:** Not met. A release does need a tag and two approvals, but one person can do all three.

**Gap:** [G1, G2](supply-chain-security.md#gaps-and-how-to-close-them).

### CM-6 Configuration Settings

*Baseline: Low, Moderate, High. Status: **Met**. Provided by: Shared.*

> a. Establish and document configuration settings for components employed within the system that reflect the most restrictive mode consistent with operational requirements using [Assignment: organization-defined common secure configurations];  
> b. Implement the configuration settings;  
> c. Identify, document, and approve any deviations from established configuration settings for [Assignment: organization-defined system components] based on [Assignment: organization-defined operational requirements]; and  
> d. Monitor and control changes to the configuration settings in accordance with organizational policies and procedures.

**How wd2l meets it:** For the image:
* **Configuration checked on every build:** non-root (65532), no shell, no package manager, no setuid files, the FIPS crypto policy, the base's RPM database unchanged, and nothing beside wd2l's files from the wheel.
* **Containerfiles:** linted.
* **Settings the site supplies:** the deployment guides set them (systemd sandboxing, nftables, a signature policy).
* **Host baselines:** the customer's.

**Evidence:** [`check_image.py`](../packaging/container/check_image.py), [`check_containerfile.py`](../packaging/container/check_containerfile.py), [deployment/](deployment/).

### CM-8 System Component Inventory

*Baseline: Low, Moderate, High. Status: **Met**. Provided by: wd2l.*

> a. Develop and document an inventory of system components that:  
> &emsp;&emsp;1. Accurately reflects the system;  
> &emsp;&emsp;2. Includes all components within the system;  
> &emsp;&emsp;3. Does not include duplicate accounting of components or components assigned to any other system;  
> &emsp;&emsp;4. Is at the level of granularity deemed necessary for tracking and reporting; and  
> &emsp;&emsp;5. Includes the following information to achieve system component accountability: [Assignment: organization-defined information deemed necessary to achieve effective system component accountability]; and  
> b. Review and update the system component inventory [Assignment: organization-defined frequency].

**How wd2l meets it:** SBOMs in SPDX and CycloneDX for:
* each platform's image;
* the RPMs (EL9, EL10);
* the Python package.

Each component has a supplier and a SHA-256, and each file has a SHA-256. A gap fails the release. `sbom_diff` shows that each image is its base plus wd2l, less pip, and nothing else. The SBOMs are release files, so the signature and the provenance cover them. The site's inventory of its own systems is the customer's.

**Evidence:** [ADR-0009](decisions/0009-sbom-content.md), [ADR-0010](decisions/0010-sbom-generator.md), [`sbom_enrich.py`](../packaging/container/sbom_enrich.py), [`sbom_diff.py`](../packaging/container/sbom_diff.py), [`package_sbom.py`](../packaging/release/package_sbom.py).

### CM-14 Signed Components

*Baseline: none (not in a 800-53B baseline). Status: **Partly met**. Provided by: Shared.*

> Prevent the installation of [Assignment: organization-defined software and firmware components] without verification that the component has been digitally signed using a certificate that is recognized and approved by the organization.

**How wd2l meets it:**
* **Images:** signed with the release key. Podman's signature policy refuses an unsigned image or one signed with another key ([containers.md](deployment/containers.md#signature-policy-registry-pulls)), and an image tar is checked with `cosign verify --local-image` before import.
* **Release files:** covered by the signed `SHA256SUMS`, checked by `verify-release`.
* **Who approves the key:** the security owner approves `cosign.pub`, carried in from a trusted channel.

**Gap:** [G9](supply-chain-security.md#gaps-and-how-to-close-them): the RPMs aren't GPG-signed, so `dnf` doesn't check them itself; the check is a step the operator runs.

## PM: Program Management

### PM-30 Supply Chain Risk Management Strategy

*Baseline: none (not in a 800-53B baseline). Status: **Customer**. Provided by: Customer.*

> a. Develop an organization-wide strategy for managing supply chain risks associated with the development, acquisition, maintenance, and disposal of systems, system components, and system services;  
> b. Implement the supply chain risk management strategy consistently across the organization; and  
> c. Review and update the supply chain risk management strategy on [Assignment: organization-defined frequency] or as required, to address organizational changes.

**How wd2l meets it:** This is an organization-wide strategy, which the customer writes. This repository supplies evidence for it: this page, [supply-chain-security.md](supply-chain-security.md), and each release's manifest and SBOMs.

**Gap:** [G13](supply-chain-security.md#gaps-and-how-to-close-them).

## RA: Risk Assessment

### RA-5 Vulnerability Monitoring and Scanning

*Baseline: Low, Moderate, High. Status: **Met**. Provided by: Shared.*

> a. Monitor and scan for vulnerabilities in the system and hosted applications [Assignment: organization-defined frequency and/or randomly in accordance with organization-defined process] and when new vulnerabilities potentially affecting the system are identified and reported;  
> b. Employ vulnerability monitoring tools and techniques that facilitate interoperability among tools and automate parts of the vulnerability management process by using standards for:  
> &emsp;&emsp;1. Enumerating platforms, software flaws, and improper configurations;  
> &emsp;&emsp;2. Formatting checklists and test procedures; and  
> &emsp;&emsp;3. Measuring vulnerability impact;  
> c. Analyze vulnerability scan reports and results from vulnerability monitoring;  
> d. Remediate legitimate vulnerabilities [Assignment: organization-defined response times] in accordance with an organizational assessment of risk;  
> e. Share information obtained from the vulnerability monitoring process and control assessments with [Assignment: organization-defined personnel or roles] to help eliminate similar vulnerabilities in other systems; and  
> f. Employ vulnerability monitoring tools that include the capability to readily update the vulnerabilities to be scanned.

**How wd2l meets it:**
* **(a) When it scans:** Grype and Trivy scan the image on every PR, every push to `main` and every release, with fresh data. `image-rescan` scans the latest two final releases each month, and can be run by hand when a CVE makes the news.
* **(b) Standards:** CVE IDs, CVSS, package URLs, SARIF, SPDX and CycloneDX.
* **(c) Analysis:** `vuln_gate.py` merges the two scanners' results, shows what each covered, and lists what only one found.
* **(d) Remediation:** 7 days for a Critical and 30 for a High, from the issue to a patch release.
* **(e) Sharing:** results go in the run's summary, in Code scanning, and in each release's vulnerability summary and signed scan attestation.
* **(f) Fresh data:** the scanners update their data on each run.

**Evidence:** [ADR-0011](decisions/0011-vulnerability-scanners.md); [releasing.md, security review](releasing.md#security-review) and [when to move them](releasing.md#when-to-move-them); [`vuln_gate.py`](../packaging/container/vuln_gate.py), [`image-rescan.yml`](../.github/workflows/image-rescan.yml).

**Gap:** [G3](supply-chain-security.md#gaps-and-how-to-close-them): admins can bypass the review gate. Scanning the site's hosts is the customer's.

### RA-5(2) Update Vulnerabilities to Be Scanned

*Baseline: Low, Moderate, High. Status: **Met**. Provided by: wd2l.*

> Update the system vulnerabilities to be scanned [Selection (one or more): [Assignment: organization-defined frequency]; prior to a new scan; when new vulnerabilities are identified and reported].

**How wd2l meets it:** Grype's and Trivy's databases are fetched fresh before each scan, on every PR, release and monthly rescan. The scanner images themselves are pinned and moved by Dependabot each week.

**Evidence:** [`image.yml`](../.github/workflows/image.yml) `vuln-scan`; [`tools.Containerfile`](../packaging/ci/tools.Containerfile).

### RA-5(3) Breadth and Depth of Coverage

*Baseline: none (not in a 800-53B baseline). Status: **Partly met**. Provided by: wd2l.*

> Define the breadth and depth of vulnerability scanning coverage.

**How wd2l meets it:** Coverage is defined and reported: each result says which scanner covered which kind of package, and a scanner without data for the image's OS is raised as a warning on the run. Two scanners cover the image; the RPMs and the Python package are described by SBOMs.

**Evidence:** [ADR-0011](decisions/0011-vulnerability-scanners.md), [`tool_warnings.py`](../packaging/container/tool_warnings.py).

**Gap:** [G8](supply-chain-security.md#gaps-and-how-to-close-them): only Grype covers the Hardened image's OS packages.

### RA-5(11) Public Disclosure Program

*Baseline: Low, Moderate, High. Status: **Gap**. Provided by: wd2l.*

> Establish a public reporting channel for receiving reports of vulnerabilities in organizational systems and system components.

**How wd2l meets it:** Not met. Anyone can open a public issue, but there is no published security policy and no private reporting channel.

**Gap:** [G10](supply-chain-security.md#gaps-and-how-to-close-them).

### RA-9 Criticality Analysis

*Baseline: Moderate, High. Status: **Partly met**. Provided by: Shared.*

> Identify critical system components and functions by performing a criticality analysis for [Assignment: organization-defined systems, system components, or system services] at [Assignment: organization-defined decision points in the system development life cycle].

**How wd2l meets it:** The design names its critical components: the one-way link, the receiver's parsing of untrusted input, the audit trail, and in the supply chain, the signing key, `attest.yml` and the base image ([accreditation-notes.md](accreditation-notes.md), [ADR-0007](decisions/0007-slsa-build-l3.md)). There is no criticality analysis as a separate document at decision points the customer has set.

**Gap:** [G14](supply-chain-security.md#gaps-and-how-to-close-them); the decision points are the customer's to define.

## SA: System and Services Acquisition

### SA-3 System Development Life Cycle

*Baseline: Low, Moderate, High. Status: **Partly met**. Provided by: Shared.*

> a. Acquire, develop, and manage the system using [Assignment: organization-defined system development life cycle] that incorporates information security and privacy considerations;  
> b. Define and document information security and privacy roles and responsibilities throughout the system development life cycle;  
> c. Identify individuals having information security and privacy roles and responsibilities; and  
> d. Integrate the organizational information security and privacy risk management process into system development life cycle activities.

**How wd2l meets it:** The development life cycle is documented and enforced by the forge: issue, PR, CI, security review, release, rescan ([releasing.md](releasing.md)). Security is built into each step, and the ADRs record each design decision. The security owner's role is named. Fitting it into the customer's risk process (part d) is the customer's.

**Evidence:** [releasing.md](releasing.md), [docs/decisions/](decisions/).

### SA-8 Security and Privacy Engineering Principles

*Baseline: Low, Moderate, High. Status: **Met**. Provided by: wd2l.*

> Apply the following systems security and privacy engineering principles in the specification, design, development, implementation, and modification of the system and system components: [Assignment: organization-defined systems security and privacy engineering principles].

**How wd2l meets it:** The principles applied include:
* **Least privilege:** AC-6.
* **Least functionality:** a minimal base, with no shell and no package manager.
* **Minimized trust in inputs:** Enclave 2 trusts nothing from the wire ([accreditation-notes.md](accreditation-notes.md#what-enclave-2-trusts)).
* **Defense in depth:** a physical one-way link, then host controls.
* **Standard library only:** nothing third-party to review or patch.
* **Fail visibly:** every lost event is reported.
* **Verifiable releases:** offline checks of everything that ships.

**Evidence:** [architecture.md](architecture.md), [ADR-0004](decisions/0004-container-base-image.md), [accreditation-notes.md](accreditation-notes.md).

### SA-10 Developer Configuration Management

*Baseline: Moderate, High. Status: **Met**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service to:  
> a. Perform configuration management during system, component, or service [Selection (one or more): design; development; implementation; operation; disposal];  
> b. Document, manage, and control the integrity of changes to [Assignment: organization-defined configuration items under configuration management];  
> c. Implement only organization-approved changes to the system, component, or service;  
> d. Document approved changes to the system, component, or service and the potential security and privacy impacts of such changes; and  
> e. Track security flaws and flaw resolution within the system, component, or service and report findings to [Assignment: organization-defined personnel].

**How wd2l meets it:**
* **(a)** Configuration management covers design through release: git, with ADRs for design decisions.
* **(b)** Every configuration item is in the repository, changed only through `main`'s rules.
* **(c, d)** A change lands only through an approved PR that closes an issue, and each release's manifest lists every PR with its issues.
* **(e)** Security flaws are tracked as issues labelled `security`. A release lists the open ones as Known issues, and the monthly rescan opens new ones.

**Evidence:** [releasing.md, conventions](releasing.md#conventions); [ADR-0008](decisions/0008-release-manifest.md).

**Gap:** [G1](supply-chain-security.md#gaps-and-how-to-close-them): the approver of a PR is its author.

### SA-10(1) Software and Firmware Integrity Verification

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service to enable integrity verification of software and firmware components.

**How wd2l meets it:** Every delivered component can be checked for integrity, offline:
* the signed `SHA256SUMS`;
* the key-signed image, with its attestations;
* GitHub's L3 provenance;
* `verify-release`, which checks all of them in one step.

**Evidence:** [releasing.md, bringing a release into an enclave](releasing.md#bringing-a-release-into-an-enclave); [`verify_release.py`](../packaging/release/verify_release.py).

### SA-10(4) Trusted Generation

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service to employ tools for comparing newly generated versions of security-relevant hardware descriptions, source code, and object code with previous versions.

**How wd2l meets it:** The `reproducible` job builds the wheel, the sdist and the image a second time from the same inputs, compares them with the first build byte for byte, and fails the run on any difference, showing what differs. Between releases, the manifest gives line counts per file type and a link that compares the two commits. `sbom_diff` compares each image with its base.

**Evidence:** `test_a_build_that_does_not_reproduce_fails`; [`check_dist.py`](../packaging/check_dist.py); [ADR-0008](decisions/0008-release-manifest.md).

### SA-10(5) Mapping Integrity for Version Control

*Baseline: none (not in a 800-53B baseline). Status: **Partly met**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service to maintain the integrity of the mapping between the master build data describing the current version of security-relevant hardware, software, and firmware and the on-site master copy of the data for the current version.

**How wd2l meets it:**
* **Image:** `wd2l/BUILD` names the commit inside every package, and the image records it too.
* **Provenance:** both provenance documents name the commit and the tag.
* **Source bundle:** each release ships a full-history `git bundle`, and `verify-release` checks that the bundle's tag is the manifest's commit.
* **Tags:** only the admin role can move or delete a `v*` tag.

**Evidence:** `verify-release`; the tag ruleset.

**Gap:** [G7](supply-chain-security.md#gaps-and-how-to-close-them): commits aren't signed, and the forge issues no source provenance.

### SA-10(6) Trusted Distribution

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service to execute procedures for ensuring that security-relevant hardware, software, and firmware updates distributed to the organization are exactly as specified by the master copies.

**How wd2l meets it:** A consumer can check that what arrived is exactly what was built and released:
* `SHA256SUMS`, signed with the release key, covers every file;
* the image is signed by digest;
* releases are immutable once published;
* `gh release verify` checks GitHub's release attestation.

**Evidence:** [ADR-0006](decisions/0006-release-artifacts-and-signing.md); [releasing.md](releasing.md#bringing-a-release-into-an-enclave).

### SA-11 Developer Testing and Evaluation

*Baseline: Moderate, High. Status: **Met**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service, at all post-design stages of the system development life cycle, to:  
> a. Develop and implement a plan for ongoing security and privacy control assessments;  
> b. Perform [Selection (one or more): unit; integration; system; regression] testing/evaluation [Assignment: organization-defined frequency] at [Assignment: organization-defined depth and coverage];  
> c. Produce evidence of the execution of the assessment plan and the results of the testing and evaluation;  
> d. Implement a verifiable flaw remediation process; and  
> e. Correct flaws identified during testing and evaluation.

**How wd2l meets it:**
* **(a) A plan for ongoing assessment:** the pipeline itself, documented in [releasing.md](releasing.md#how-a-release-is-built).
* **(b) Testing:**
  * unit and regression tests, on two Python versions and under FIPS, with none allowed to skip;
  * integration and system tests: the namespace lab, the functional tests from the image, and the RPM install tests;
  * when: on every PR and again for every release.
* **(c) Evidence:** the run logs, the artifacts and each release's files.
* **(d, e) Flaws:** tracked as issues and fixed through PRs that close them.

**Evidence:** [`tests/`](../tests/), [running-the-lab.md](running-the-lab.md), [`tests.yml`](../.github/workflows/tests.yml).

### SA-11(1) Static Code Analysis

*Baseline: none (not in a 800-53B baseline). Status: **Gap**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service to employ static code analysis tools to identify common flaws and document the results of the analysis.

**How wd2l meets it:** Not met for wd2l's own code. Hadolint and Trivy check the Containerfiles, and the workflows are checked by `tests/test_workflow_policy.py`, but no static analysis tool reads the Python source.

**Gap:** [G6](supply-chain-security.md#gaps-and-how-to-close-them).

### SA-11(2) Threat Modeling and Vulnerability Analyses

*Baseline: none (not in a 800-53B baseline). Status: **Partly met**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service to perform threat modeling and vulnerability analyses during development and the subsequent testing and evaluation of the system, component, or service that:  
> (a) Uses the following contextual information: [Assignment: organization-defined information concerning impact, environment of operations, known or assumed threats, and acceptable risk levels];  
> (b) Employs the following tools and methods: [Assignment: organization-defined tools and methods];  
> (c) Conducts the modeling and analyses at the following level of rigor: [Assignment: organization-defined breadth and depth of modeling and analyses]; and  
> (d) Produces evidence that meets the following acceptance criteria: [Assignment: organization-defined acceptance criteria].

**How wd2l meets it:**
* **The transfer:** the threats are analyzed in [accreditation-notes.md](accreditation-notes.md) (residual risks) and [ADR-0002](decisions/0002-opaque-content.md).
* **The supply chain:** SLSA's threat model is applied in [supply-chain-security.md](supply-chain-security.md#threats-and-where-theyre-addressed).
* **Vulnerability analysis:** RA-5.

The parameters (tools, rigor, acceptance criteria) haven't been set by the customer.

**Gap:** [G14](supply-chain-security.md#gaps-and-how-to-close-them).

### SA-11(4) Manual Code Reviews

*Baseline: none (not in a 800-53B baseline). Status: **Gap**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service to perform a manual code review of [Assignment: organization-defined specific code] using the following processes, procedures, and/or techniques: [Assignment: organization-defined processes, procedures, and/or techniques].

**How wd2l meets it:** Not met as a control. Every change is shown as a diff in its PR, but no second person is required to review it.

**Gap:** [G1](supply-chain-security.md#gaps-and-how-to-close-them).

### SA-11(8) Dynamic Code Analysis

*Baseline: none (not in a 800-53B baseline). Status: **Partly met**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service to employ dynamic code analysis tools to identify common flaws and document the results of the analysis.

**How wd2l meets it:**
* **Fuzz tests:** the frame and packet parsers are fuzzed with random and mutated input, and must only ever raise their own error (`test_fuzz_decode_only_raises_frame_error`, `test_fuzz_parse_only_raises_notudp`).
* **The lab:** it runs the sender and receiver end to end with injected loss.
* **Not used:** dynamic analysis tools beyond these, such as sanitizers or a coverage-guided fuzzer.

**Evidence:** [`tests/test_wire.py`](../tests/test_wire.py), [`tests/test_packets.py`](../tests/test_packets.py), [running-the-lab.md](running-the-lab.md).

### SA-15 Development Process, Standards, and Tools

*Baseline: Moderate, High. Status: **Met**. Provided by: wd2l.*

> a. Require the developer of the system, system component, or system service to follow a documented development process that:  
> &emsp;&emsp;1. Explicitly addresses security and privacy requirements;  
> &emsp;&emsp;2. Identifies the standards and tools used in the development process;  
> &emsp;&emsp;3. Documents the specific tool options and tool configurations used in the development process; and  
> &emsp;&emsp;4. Documents, manages, and ensures the integrity of changes to the process and/or tools used in development; and  
> b. Review the development process, standards, tools, tool options, and tool configurations [Assignment: organization-defined frequency] to determine if the process, standards, tools, tool options and tool configurations selected and employed can satisfy the following security and privacy requirements: [Assignment: organization-defined security and privacy requirements].

**How wd2l meets it:**
* **(a) A documented process:**
  * security requirements in the ADRs and the accreditation notes;
  * the tools and their exact versions pinned in the repository and listed in each release manifest;
  * tool options in the workflows and scripts themselves;
  * changes to the process or tools made only through `main`'s rules.
* **(b) Review:** Dependabot and the pins review the tools each week. The security owner sets the requirements.

**Evidence:** [releasing.md](releasing.md), [`tools.Containerfile`](../packaging/ci/tools.Containerfile), [ADR-0008](decisions/0008-release-manifest.md).

### SA-15(3) Criticality Analysis

*Baseline: Moderate, High. Status: **Partly met**. Provided by: Shared.*

> Require the developer of the system, system component, or system service to perform a criticality analysis:  
> (a) At the following decision points in the system development life cycle: [Assignment: organization-defined decision points in the system development life cycle]; and  
> (b) At the following level of rigor: [Assignment: organization-defined breadth and depth of criticality analysis].

**How wd2l meets it:** See RA-9. The decision points and the rigor are the customer's to set.

**Gap:** [G14](supply-chain-security.md#gaps-and-how-to-close-them).

### SA-15(5) Attack Surface Reduction

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service to reduce attack surfaces to [Assignment: organization-defined thresholds].

**How wd2l meets it:** The image is a minimal Hardened base with no shell, no package manager and no setuid file, running as non-root, with nothing beside wd2l's own files. On 1.1.0's wheel it had 65 components and 7 known vulnerabilities, against 207 and 535 for the same wd2l on UBI 9. wd2l itself uses only the Python standard library. The receiver reads one raw socket and accepts one flow.

**Evidence:** [ADR-0004](decisions/0004-container-base-image.md); [`check_image.py`](../packaging/container/check_image.py); the README's comparison.

### SA-15(7) Automated Vulnerability Analysis

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Require the developer of the system, system component, or system service [Assignment: organization-defined frequency] to:  
> (a) Perform an automated vulnerability analysis using [Assignment: organization-defined tools];  
> (b) Determine the exploitation potential for discovered vulnerabilities;  
> (c) Determine potential risk mitigations for delivered vulnerabilities; and  
> (d) Deliver the outputs of the tools and results of the analysis to [Assignment: organization-defined personnel or roles].

**How wd2l meets it:**
* **(a) Automated analysis:** two scanners on every PR, every release and each month.
* **(b, c) Exploitability and mitigation:** decided by the security owner at the review gate, and recorded as exceptions that expire within 90 days.
* **(d) Delivery:** each release carries its vulnerability summaries and a signed scan attestation on each image.

**Evidence:** [ADR-0011](decisions/0011-vulnerability-scanners.md), [`vuln-exceptions.json`](../packaging/container/vuln-exceptions.json).

**Gap:** [G6](supply-chain-security.md#gaps-and-how-to-close-them) (no analysis of wd2l's own source); [G10](supply-chain-security.md#gaps-and-how-to-close-them) (no VEX).

### SA-15(11) Archive System or Component

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Require the developer of the system or system component to archive the system or component to be released or delivered together with the corresponding evidence supporting the final security and privacy review.

**How wd2l meets it:** Each release is archived with its evidence, and can't be changed once published. It holds:
* **What shipped:** every package and the image tars.
* **Where it came from:** the full-history source bundle, both kinds of provenance and the attestations.
* **What it's made of and what's known against it:** the SBOMs and the vulnerability summaries.
* **What was approved:** the manifest, with its approvals and the issues it resolves, and the changelog.

**Evidence:** [ADR-0008](decisions/0008-release-manifest.md); [releasing.md, one-time setup](releasing.md#one-time-setup) (immutable releases).

### SA-22 Unsupported System Components

*Baseline: Low, Moderate, High. Status: **Partly met**. Provided by: Shared.*

> a. Replace system components when support for the components is no longer available from the developer, vendor, or manufacturer; or  
> b. Provide the following options for alternative sources for continued support for unsupported components [Selection (one or more): in-house support; [Assignment: organization-defined support from external providers]].

**How wd2l meets it:**
* **Supported components only:** the Python runtime and OS come from Red Hat's Hardened Images, which Red Hat supports. The base's Python version is a recorded decision ([ADR-0004](decisions/0004-container-base-image.md)), and the base moves by digest each week.
* **Unsupported pins:** a pin to a retired digest is caught each week by `pin-check`.
* **Python 3.9:** wd2l still supports it on EL9 hosts for native installs. Whether that's acceptable depends on the host OS's support, which is the customer's.

**Gap:** [G15](supply-chain-security.md#gaps-and-how-to-close-them): wd2l itself depends on one maintainer.

## SC: System and Communications Protection

### SC-12 Cryptographic Key Establishment and Management

*Baseline: Low, Moderate, High. Status: **Partly met**. Provided by: Shared.*

> Establish and manage cryptographic keys when cryptography is employed within the system in accordance with the following key management requirements: [Assignment: organization-defined requirements for key generation, distribution, storage, access, and destruction].

**How wd2l meets it:**
* **The release key:** generation, storage, access, rotation and compromise response are written down: made on a trusted machine, kept only in the `release` environment's secrets, the local copy kept offline or destroyed. Retired public keys are kept so old releases still verify.
* **Keyless signing:** no long-lived key; Fulcio issues a certificate per run.
* **Inherited:** the keys of GitHub, Fulcio and Rekor.

**Evidence:** [ADR-0006, key management](decisions/0006-release-artifacts-and-signing.md#key-management); [releasing.md, one-time setup](releasing.md#one-time-setup).

**Gap:** [G4](supply-chain-security.md#gaps-and-how-to-close-them) (a software key, no set cryptoperiod) and [G12](supply-chain-security.md#gaps-and-how-to-close-them) (trust root refresh).

### SC-13 Cryptographic Protection

*Baseline: Low, Moderate, High. Status: **Met**. Provided by: Shared.*

> a. Determine the [Assignment: organization-defined cryptographic uses]; and  
> b. Implement the following types of cryptography required for each specified cryptographic use: [Assignment: organization-defined types of cryptography for each specified cryptographic use].

**How wd2l meets it:**
* **Uses:** signing and checking release files, images and attestations, and integrity checks with SHA-256.
* **Types:** cosign's ECDSA P-256 signatures with SHA-256, and Sigstore's keyless certificates.
* **Inside the image:** wd2l runs under the FIPS crypto policy.

Which algorithms and modules the customer requires is theirs to set.

**Evidence:** [ADR-0006](decisions/0006-release-artifacts-and-signing.md); [`fips_check.py`](../packaging/container/fips_check.py).

## SI: System and Information Integrity

### SI-2 Flaw Remediation

*Baseline: Low, Moderate, High. Status: **Met**. Provided by: Shared.*

> a. Identify, report, and correct system flaws;  
> b. Test software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation;  
> c. Install security-relevant software and firmware updates within [Assignment: organization-defined time period] of the release of the updates; and  
> d. Incorporate flaw remediation into the organizational configuration management process.

**How wd2l meets it:**
* **(a) Finding flaws:** by tests, scans, the monthly rescan and issues.
* **(b) Testing fixes:** each fix, a base move included, runs the whole pipeline before it merges.
* **(c) Timelines:** 7 days for a Critical and 30 for a High, from the issue to a patch release.
* **(d) Configuration management:** fixes go through the same PR process as any change.

Installing updates on the site's hosts is the customer's ([planned-downtime.md](planned-downtime.md)).

**Evidence:** [releasing.md, when to move them](releasing.md#when-to-move-them).

**Gap:** [G3](supply-chain-security.md#gaps-and-how-to-close-them).

### SI-2(2) Automated Flaw Remediation Status

*Baseline: Moderate, High. Status: **Met**. Provided by: Shared.*

> Determine if system components have applicable security-relevant software and firmware updates installed using [Assignment: organization-defined automated mechanisms] [Assignment: organization-defined frequency].

**How wd2l meets it:**
* **Shipped images:** `image-rescan` checks the latest two final releases each month against fresh vulnerability data, and opens an issue for each one that needs a fix.
* **Pins:** Dependabot checks every pin each week.

Whether the site's hosts run the latest release is the customer's to check.

**Evidence:** [`image-rescan.yml`](../.github/workflows/image-rescan.yml), [`dependabot.yml`](../.github/dependabot.yml).

### SI-7 Software, Firmware, and Information Integrity

*Baseline: Moderate, High. Status: **Met**. Provided by: Shared.*

> a. Employ integrity verification tools to detect unauthorized changes to the following software, firmware, and information: [Assignment: organization-defined software, firmware, and information]; and  
> b. Take the following actions when unauthorized changes to the software, firmware, and information are detected: [Assignment: organization-defined actions].

**How wd2l meets it:**
* **Before installation:** `verify-release` checks every release file and image against the signed `SHA256SUMS` and the image signatures.
* **At pull time:** Podman's signature policy refuses an image without our signature.
* **On the hosts:** the audit trail's hash chain detects changes to the audit records ([audit-and-health.md](audit-and-health.md#8-protecting-the-audit-trail)).
* **On failure:** a failed check stops the install.

What else to do when a check fails is the customer's to define.

**Evidence:** [releasing.md](releasing.md#bringing-a-release-into-an-enclave); [containers.md](deployment/containers.md#signature-policy-registry-pulls).

### SI-7(1) Integrity Checks

*Baseline: Moderate, High. Status: **Partly met**. Provided by: Shared.*

> Perform an integrity check of [Assignment: organization-defined software, firmware, and information] [Selection (one or more): at startup; at [Assignment: organization-defined transitional states or security-relevant events]; [Assignment: organization-defined frequency]].

**How wd2l meets it:**
* **At a transitional state:** release files and images are checked when they're installed, and Podman checks the signature at every pull.
* **On a schedule:** the audit trail's self-check runs daily.
* **Not done:** a periodic check of installed files against the RPM database (`rpm -V`), or of the image digest, is not scripted. The customer's host integrity tools can do it.

**Evidence:** as for SI-7.

### SI-7(6) Cryptographic Protection

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Implement cryptographic mechanisms to detect unauthorized changes to software, firmware, and information.

**How wd2l meets it:** Changes are detected cryptographically:
* SHA-256 over every file;
* signatures on `SHA256SUMS`, on each image digest and on each attestation;
* SHA-256 per event and a hash chain over the audit records, in the product.

**Evidence:** [ADR-0006](decisions/0006-release-artifacts-and-signing.md), [audit-and-health.md](audit-and-health.md#8-protecting-the-audit-trail).

**Gap:** [G12](supply-chain-security.md#gaps-and-how-to-close-them): no timestamp on key signatures.

### SI-7(12) Integrity Verification

*Baseline: none (not in a 800-53B baseline). Status: **Customer**. Provided by: Customer.*

> Require that the integrity of the following user-installed software be verified prior to execution: [Assignment: organization-defined user-installed software].

**How wd2l meets it:** Applies where an operator installs wd2l. The documented install verifies the release before anything runs: `verify-release`, then `dnf install` or `skopeo copy`. Whether the site makes that mandatory is the customer's decision.

**Evidence:** [releasing.md, bringing a release into an enclave](releasing.md#bringing-a-release-into-an-enclave).

### SI-7(15) Code Authentication

*Baseline: High. Status: **Partly met**. Provided by: Shared.*

> Implement cryptographic mechanisms to authenticate the following software or firmware components prior to installation: [Assignment: organization-defined software or firmware components].

**How wd2l meets it:** Images are authenticated by signature before import or pull. Release files are authenticated through the signed `SHA256SUMS`.

**Gap:** [G9](supply-chain-security.md#gaps-and-how-to-close-them): `dnf` can't authenticate the RPMs itself, so the check depends on the operator running `verify-release` first.

## SR: Supply Chain Risk Management

### SR-1 Policy and Procedures

*Baseline: Low, Moderate, High. Status: **Customer**. Provided by: Customer.*

> a. Develop, document, and disseminate to [Assignment: organization-defined personnel or roles]:  
> &emsp;&emsp;1. [Selection (one or more): organization-level; mission/business process-level; system-level] supply chain risk management policy that:  
> &emsp;&emsp;&emsp;&emsp;(a) Addresses purpose, scope, roles, responsibilities, management commitment, coordination among organizational entities, and compliance; and  
> &emsp;&emsp;&emsp;&emsp;(b) Is consistent with applicable laws, executive orders, directives, regulations, policies, standards, and guidelines; and  
> &emsp;&emsp;2. Procedures to facilitate the implementation of the supply chain risk management policy and the associated supply chain risk management controls;  
> b. Designate an [Assignment: organization-defined official] to manage the development, documentation, and dissemination of the supply chain risk management policy and procedures; and  
> c. Review and update the current supply chain risk management:  
> &emsp;&emsp;1. Policy [Assignment: organization-defined frequency] and following [Assignment: organization-defined events]; and  
> &emsp;&emsp;2. Procedures [Assignment: organization-defined frequency] and following [Assignment: organization-defined events].

**How wd2l meets it:** The supply-chain risk management policy and procedures are the customer's. This repository's procedures for its own part are [releasing.md](releasing.md) and this page.

**Gap:** [G13](supply-chain-security.md#gaps-and-how-to-close-them).

### SR-2 Supply Chain Risk Management Plan

*Baseline: Low, Moderate, High. Status: **Customer**. Provided by: Customer.*

> a. Develop a plan for managing supply chain risks associated with the research and development, design, manufacturing, acquisition, delivery, integration, operations and maintenance, and disposal of the following systems, system components or system services: [Assignment: organization-defined systems, system components, or system services];  
> b. Review and update the supply chain risk management plan [Assignment: organization-defined frequency] or as required, to address threat, organizational or environmental changes; and  
> c. Protect the supply chain risk management plan from unauthorized disclosure and modification.

**How wd2l meets it:** The customer's plan. Inputs from this repository: the supply-chain stages and their protections, the threats, the gaps ([supply-chain-security.md](supply-chain-security.md)), and each release's manifest and SBOMs.

**Gap:** [G13](supply-chain-security.md#gaps-and-how-to-close-them).

### SR-2(1) Establish SCRM Team

*Baseline: Low, Moderate, High. Status: **Customer**. Provided by: Customer.*

> Establish a supply chain risk management team consisting of [Assignment: organization-defined personnel, roles, and responsibilities] to lead and support the following SCRM activities: [Assignment: organization-defined supply chain risk management activities].

**How wd2l meets it:** The customer's team. On wd2l's side, the security owner holds the key and approves the gates.

**Gap:** [G13](supply-chain-security.md#gaps-and-how-to-close-them).

### SR-3 Supply Chain Controls and Processes

*Baseline: Low, Moderate, High. Status: **Met**. Provided by: Shared.*

> a. Establish a process or processes to identify and address weaknesses or deficiencies in the supply chain elements and processes of [Assignment: organization-defined system or system component] in coordination with [Assignment: organization-defined supply chain personnel];  
> b. Employ the following controls to protect against supply chain risks to the system, system component, or system service and to limit the harm or consequences from supply chain-related events: [Assignment: organization-defined supply chain controls]; and  
> c. Document the selected and implemented supply chain processes and controls in [Selection (one or more): security and privacy plans; supply chain risk management plan; [Assignment: organization-defined document]].

**How wd2l meets it:**
* **(a) Weaknesses found and addressed:** this page, the rescan and pin-check, and issues.
* **(b) Controls employed:** pinning, base verification, isolated builds, reproducibility, scanning, SBOMs, signing, provenance, gated release and offline verification.
* **(c) Documentation:** this page, [supply-chain-security.md](supply-chain-security.md) and the ADRs. The customer may cite them in its plans.

**Evidence:** [supply-chain-security.md](supply-chain-security.md#the-supply-chain-end-to-end).

**Gap:** [G11](supply-chain-security.md#gaps-and-how-to-close-them).

### SR-4 Provenance

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Document, monitor, and maintain valid provenance of the following systems, system components, and associated data: [Assignment: organization-defined systems, system components, and associated data].

**How wd2l meets it:** Provenance is documented for every delivered component, and kept with the release:
* **GitHub's SLSA Build L3 provenance:** every file and image.
* **wd2l's own provenance:** commit, workflow, wheel digest, exact base digests and their mirrors.
* **The base's own provenance:** Red Hat's, checked and recorded in `base-image-record.json`, and mirrored with the base.
* **Monitoring:** the base's provenance is checked again whenever the base moves.

**Evidence:** [ADR-0006](decisions/0006-release-artifacts-and-signing.md), [ADR-0007](decisions/0007-slsa-build-l3.md), [`provenance.py`](../packaging/release/provenance.py), [`base_record.py`](../packaging/container/base_record.py).

### SR-4(1) Identity

*Baseline: none (not in a 800-53B baseline). Status: **Partly met**. Provided by: wd2l.*

> Establish and maintain unique identification of the following supply chain elements, processes, and personnel associated with the identified system and critical system components: [Assignment: organization-defined supply chain elements, processes, and personnel associated with organization-defined systems and critical system components].

**How wd2l meets it:**
* **Supply-chain elements:** identified uniquely, by digest or commit: the repository, the commit, each workflow, each runner type, each base image, each tool image and each action.
* **Processes:** identified by the signer workflow `attest.yml` at a tag.
* **People:** identified as the GitHub accounts that merged each PR and approved each gate, recorded in the manifest.

**Gap:** [G7](supply-chain-security.md#gaps-and-how-to-close-them): commits aren't signed, so authorship rests on the forge's account records.

### SR-4(2) Track and Trace

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Establish and maintain unique identification of the following systems and critical system components for tracking through the supply chain: [Assignment: organization-defined systems and critical system components].

**How wd2l meets it:** Each component carries a unique identifier from build to installation:
* the image digests (index and each platform);
* the SHA-256 of every file;
* the RPM header digests;
* the version, in every package's name and metadata, and the commit, in `wd2l/BUILD`.

The same identifiers appear in the manifest, the SBOMs, the provenance and the release notes, and the monthly rescan looks each released image up by the digest its manifest records.

**Evidence:** [ADR-0008](decisions/0008-release-manifest.md), [ADR-0009](decisions/0009-sbom-content.md).

### SR-4(3) Validate as Genuine and Not Altered

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: Shared.*

> Employ the following controls to validate that the system or system component received is genuine and has not been altered: [Assignment: organization-defined controls].

**How wd2l meets it:** A site checks that each component is genuine and unaltered, offline:
* the signature on `SHA256SUMS` and every checksum;
* the image signature and its attestations;
* that the manifest agrees with both;
* that the source bundle's tag is the manifest's commit;
* optionally, GitHub's L3 provenance against the pinned signer workflow and tag.

Running these checks is the site's step.

**Evidence:** [releasing.md](releasing.md#bringing-a-release-into-an-enclave); [`verify_release.py`](../packaging/release/verify_release.py).

### SR-4(4) Supply Chain Integrity — Pedigree

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Employ [Assignment: organization-defined controls] and conduct [Assignment: organization-defined analysis] to ensure the integrity of the system and system components by validating the internal composition and provenance of critical or mission-essential technologies, products, and services.

**How wd2l meets it:**
* **Composition:** checked by the SBOM checks: every component has a supplier and a hash, wd2l's files are checked against the wheel and each RPM's files against its header, and `sbom_diff` shows the image is its base plus wd2l and nothing else.
* **Provenance of the base:** checked against Red Hat's signature and provenance before use.

**Evidence:** [ADR-0009](decisions/0009-sbom-content.md), [`sbom_diff.py`](../packaging/container/sbom_diff.py), [`base_record.py`](../packaging/container/base_record.py).

### SR-5 Acquisition Strategies, Tools, and Methods

*Baseline: Low, Moderate, High. Status: **Partly met**. Provided by: Shared.*

> Employ the following acquisition strategies, contract tools, and procurement methods to protect against, identify, and mitigate supply chain risks: [Assignment: organization-defined acquisition strategies, contract tools, and procurement methods].

**How wd2l meets it:** The choices this repository made are recorded with their reasons:
* a supplier that signs and attests its base images ([ADR-0004](decisions/0004-container-base-image.md));
* pinning everything;
* preferring the standard library to third-party packages;
* scanners chosen for coverage ([ADR-0011](decisions/0011-vulnerability-scanners.md)).

Contract tools and procurement methods are the customer's.

### SR-5(2) Assessments Prior to Selection, Acceptance, Modification, or Update

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Assess the system, system component, or system service prior to selection, acceptance, modification, or update.

**How wd2l meets it:** No upstream component changes without an assessment. A new base image, tool or action arrives only as a PR, which runs the whole pipeline:
* `base-verify`: Red Hat's signature, provenance and SBOM;
* the scans, compared with `main`;
* reproducibility, hardening and the functional tests.

[releasing.md, how to judge a new digest](releasing.md#how-to-judge-a-new-digest) says what to read before merging.

**Evidence:** [`dependabot.yml`](../.github/dependabot.yml); [`compare-bases.yml`](../.github/workflows/compare-bases.yml) for choosing a base.

### SR-6 Supplier Assessments and Reviews

*Baseline: Moderate, High. Status: **Partly met**. Provided by: Shared.*

> Assess and review the supply chain-related risks associated with suppliers or contractors and the system, system component, or system service they provide [Assignment: organization-defined frequency].

**How wd2l meets it:**
* **Red Hat (the base image):** checked on every build against its signature, provenance and SBOM, and assessed when chosen ([ADR-0004](decisions/0004-container-base-image.md)).
* **GitHub (build platform) and Sigstore:** chosen as documented L3 builders ([ADR-0007](decisions/0007-slsa-build-l3.md)), with no further assessment.

How often suppliers are reviewed is the customer's to set.

### SR-6(1) Testing and Analysis

*Baseline: none (not in a 800-53B baseline). Status: **Met**. Provided by: wd2l.*

> Employ [Selection (one or more): organizational analysis; independent third-party analysis; organizational testing; independent third-party testing] of the following supply chain elements, processes, and actors associated with the system, system component, or system service: [Assignment: organization-defined supply chain elements, processes, and actors].

**How wd2l meets it:** Selected: organizational testing and analysis. Each build tests the base image's signature, provenance and SBOM, scans it, and checks its RPM database is unchanged in the image. The UBI 9 comparison image measures the alternative on each release.

**Evidence:** [`base_record.py`](../packaging/container/base_record.py), [`check_image.py`](../packaging/container/check_image.py), [ADR-0004's amendment](decisions/0004-container-base-image.md#amendment-2026-10-18-a-comparison-image-on-ubi-9-192).

### SR-8 Notification Agreements

*Baseline: Low, Moderate, High. Status: **Gap**. Provided by: Shared.*

> Establish agreements and procedures with entities involved in the supply chain for the system, system component, or system service for the [Selection (one or more): notification of supply chain compromises; [Assignment: organization-defined information]].

**How wd2l meets it:** Not met. Agreements with suppliers are the customer's. For wd2l itself, a consumer learns of a problem through the repository's issues and releases, but there is no published security contact or advisory process.

**Gap:** [G10](supply-chain-security.md#gaps-and-how-to-close-them).

### SR-9 Tamper Resistance and Detection

*Baseline: High. Status: **Met**. Provided by: Shared.*

> Implement a tamper protection program for the system, system component, or system service.

**How wd2l meets it:** For software, tamper protection and detection is the chain from build to install:
* builds that reproduce;
* signed checksums and images;
* L3 provenance;
* immutable releases;
* a check before install, offline.

Physical tamper protection of the hosts, the tap and the fiber is the customer's ([accreditation-notes.md](accreditation-notes.md)).

**Evidence:** [supply-chain-security.md](supply-chain-security.md#the-supply-chain-end-to-end).

### SR-9(1) Multiple Stages of System Development Life Cycle

*Baseline: High. Status: **Met**. Provided by: wd2l.*

> Employ anti-tamper technologies, tools, and techniques throughout the system development life cycle.

**How wd2l meets it:** Anti-tamper measures apply at each stage of the life cycle:
* **Source:** rulesets, no force-push, admin-only tags.
* **Build:** isolated, no caches, reproducible.
* **Release:** signatures, provenance, a manifest, gated and immutable.
* **Delivery:** offline verification.
* **Operation:** Podman's signature policy and the audit trail's hash chain.

**Evidence:** as for SR-9.

### SR-10 Inspection of Systems or Components

*Baseline: Low, Moderate, High. Status: **Partly met**. Provided by: Customer.*

> Inspect the following systems or system components [Selection (one or more): at random; at [Assignment: organization-defined frequency]; upon [Assignment: organization-defined indications of need for inspection]] to detect tampering: [Assignment: organization-defined systems or system components].

**How wd2l meets it:** The tools to inspect a component for tampering are delivered with every release (`verify-release`, the attestations, `cosign.pub`), and can be run at any time against an installed image or RPM set. When and how often to inspect is the customer's choice.

**Evidence:** [releasing.md](releasing.md#bringing-a-release-into-an-enclave).

### SR-11 Component Authenticity

*Baseline: Low, Moderate, High. Status: **Partly met**. Provided by: Shared.*

> a. Develop and implement anti-counterfeit policy and procedures that include the means to detect and prevent counterfeit components from entering the system; and  
> b. Report counterfeit system components to [Selection (one or more): source of counterfeit component; [Assignment: organization-defined external reporting organizations]; [Assignment: organization-defined personnel or roles]].

**How wd2l meets it:** For software, the anti-counterfeit means is cryptographic:
* only components signed with the release key, or attested by `attest.yml` from this repository at a release tag, are genuine;
* everything else fails the documented checks;
* the base images are checked against Red Hat's keys.

The policy and where to report a counterfeit (part b) are the customer's.

**Gap:** [G10](supply-chain-security.md#gaps-and-how-to-close-them): no published channel for reporting one to this project.

### SR-11(1) Anti-counterfeit Training

*Baseline: Low, Moderate, High. Status: **Customer**. Provided by: Customer.*

> Train [Assignment: organization-defined personnel or roles] to detect counterfeit system components (including hardware, software, and firmware).

**How wd2l meets it:** Training is the customer's. The verification steps the training would teach are in [releasing.md](releasing.md#bringing-a-release-into-an-enclave).

### SR-11(2) Configuration Control for Component Service and Repair

*Baseline: Low, Moderate, High. Status: **Not applicable**. Provided by: Customer.*

> Maintain configuration control over the following system components awaiting service or repair and serviced or repaired components awaiting return to service: [Assignment: organization-defined system components].

**How wd2l meets it:** wd2l is software and isn't sent out for service or repair. Hardware on the transfer path (the tap, the NICs) is the customer's.

### SR-12 Component Disposal

*Baseline: Low, Moderate, High. Status: **Partly met**. Provided by: Shared.*

> Dispose of [Assignment: organization-defined data, documentation, tools, or system components] using the following techniques and methods: [Assignment: organization-defined techniques and methods].

**How wd2l meets it:**
* **Retired keys:** on rotation, the public half moves to `keys/retired/` so old releases still verify (the first rotation creates the directory), and the private key is removed from the secrets ([ADR-0006, key management](decisions/0006-release-artifacts-and-signing.md#key-management)).
* **Retired images:** left untagged in the registry, and deleted only on purpose ([releasing.md](releasing.md#when-a-release-run-fails)).

Disposal of the site's hosts, media and data is the customer's.
