# Changelog

## [Unreleased](https://github.com/casbin/casbin-rs/tree/HEAD)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v2.0.5...HEAD)

**Implemented enhancements:**

- Support policy.csv comment or YAML file adapter [\#213](https://github.com/casbin/casbin-rs/issues/213)

## [v2.0.5](https://github.com/casbin/casbin-rs/tree/v2.0.5) (2020-12-24)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v2.0.3...v2.0.5)

**Implemented enhancements:**

- Add actix-casbin-auth to Actix official middleware list [\#92](https://github.com/casbin/casbin-rs/issues/92)

**Fixed bugs:**

- not currently running on the Tokio runtime on tonic [\#221](https://github.com/casbin/casbin-rs/issues/221)
- CSV loader deletes double quotes [\#214](https://github.com/casbin/casbin-rs/issues/214)

**Closed issues:**

- Broken enforce with json string in 2.0 [\#210](https://github.com/casbin/casbin-rs/issues/210)

**Merged pull requests:**

- revert tokio upgrade [\#223](https://github.com/casbin/casbin-rs/pull/223) ([GopherJ](https://github.com/GopherJ))
- fix\(csv\): shouldn't delete inner double quotes [\#216](https://github.com/casbin/casbin-rs/pull/216) ([GopherJ](https://github.com/GopherJ))
- feat: switch to lru [\#212](https://github.com/casbin/casbin-rs/pull/212) ([PsiACE](https://github.com/PsiACE))
- upgrade versions of rhai & tokio [\#211](https://github.com/casbin/casbin-rs/pull/211) ([PsiACE](https://github.com/PsiACE))

## [v2.0.3](https://github.com/casbin/casbin-rs/tree/v2.0.3) (2020-10-19)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v2.0.2...v2.0.3)

## [v2.0.2](https://github.com/casbin/casbin-rs/tree/v2.0.2) (2020-09-19)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v2.0.1...v2.0.2)

**Closed issues:**

- setup clog-cli CI [\#205](https://github.com/casbin/casbin-rs/issues/205)

**Merged pull requests:**

- fix: wasm checking in CI [\#207](https://github.com/casbin/casbin-rs/pull/207) ([GopherJ](https://github.com/GopherJ))
- Automatic change log generation. [\#206](https://github.com/casbin/casbin-rs/pull/206) ([PsiACE](https://github.com/PsiACE))

## [v2.0.1](https://github.com/casbin/casbin-rs/tree/v2.0.1) (2020-08-30)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v2.0.0...v2.0.1)

## [v2.0.0](https://github.com/casbin/casbin-rs/tree/v2.0.0) (2020-08-30)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v1.1.3...v2.0.0)

**Implemented enhancements:**

- support serializable struct to be passed as ABAC parameters [\#199](https://github.com/casbin/casbin-rs/issues/199)
- pattern support in role manager [\#192](https://github.com/casbin/casbin-rs/issues/192)

**Merged pull requests:**

- Release v2.0.0 [\#204](https://github.com/casbin/casbin-rs/pull/204) ([GopherJ](https://github.com/GopherJ))

## [v1.1.3](https://github.com/casbin/casbin-rs/tree/v1.1.3) (2020-08-26)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v1.1.2...v1.1.3)

**Implemented enhancements:**

- structured logging [\#190](https://github.com/casbin/casbin-rs/issues/190)
- add `EnforcerBuilder` type? [\#174](https://github.com/casbin/casbin-rs/issues/174)
- casbin cache [\#171](https://github.com/casbin/casbin-rs/issues/171)
- Make a Casbin middleware for Rocket.rs [\#93](https://github.com/casbin/casbin-rs/issues/93)
- GSOC: Shared Redis TTL cache [\#83](https://github.com/casbin/casbin-rs/issues/83)

## [v1.1.2](https://github.com/casbin/casbin-rs/tree/v1.1.2) (2020-07-20)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v1.1.1...v1.1.2)

**Implemented enhancements:**

- clear\_policy in adapter and enforcer [\#193](https://github.com/casbin/casbin-rs/issues/193)
- Improve casbin-rs bench [\#109](https://github.com/casbin/casbin-rs/issues/109)

**Fixed bugs:**

-  allowing the parsing of policy file to deal with commas inside columns [\#184](https://github.com/casbin/casbin-rs/issues/184)

**Closed issues:**

- re-exports rhai & add IEnforcer [\#197](https://github.com/casbin/casbin-rs/issues/197)
- Filter should work with dynamic values \(&str instead of &'static str\) [\#195](https://github.com/casbin/casbin-rs/issues/195)

**Merged pull requests:**

- feat: re-exports rhai & add IEnforcer && bump version [\#198](https://github.com/casbin/casbin-rs/pull/198) ([GopherJ](https://github.com/GopherJ))
- Change Filter definition to support dynamic filter. [\#196](https://github.com/casbin/casbin-rs/pull/196) ([bodymindarts](https://github.com/bodymindarts))

## [v1.1.1](https://github.com/casbin/casbin-rs/tree/v1.1.1) (2020-07-18)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v1.1.0...v1.1.1)

**Merged pull requests:**

- Fix unhandled dquote [\#188](https://github.com/casbin/casbin-rs/pull/188) ([GopherJ](https://github.com/GopherJ))
- fix: add casbin-cpp to supported languages. [\#185](https://github.com/casbin/casbin-rs/pull/185) ([divy9881](https://github.com/divy9881))

## [v1.1.0](https://github.com/casbin/casbin-rs/tree/v1.1.0) (2020-07-14)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v1.0.0...v1.1.0)

**Implemented enhancements:**

- add cache for g function [\#175](https://github.com/casbin/casbin-rs/issues/175)

**Closed issues:**

- test issue-label-bot [\#178](https://github.com/casbin/casbin-rs/issues/178)
- setup issue-label-bot [\#177](https://github.com/casbin/casbin-rs/issues/177)
- GSOC & Non-GSOC: gitter team link [\#80](https://github.com/casbin/casbin-rs/issues/80)

**Merged pull requests:**

- Cache g [\#183](https://github.com/casbin/casbin-rs/pull/183) ([GopherJ](https://github.com/GopherJ))
- Update rhai requirement from 0.16.1 to 0.17.0 [\#182](https://github.com/casbin/casbin-rs/pull/182) ([dependabot-preview[bot]](https://github.com/apps/dependabot-preview))
- Update rhai requirement from 0.15.1 to 0.16.1 [\#179](https://github.com/casbin/casbin-rs/pull/179) ([dependabot-preview[bot]](https://github.com/apps/dependabot-preview))

## [v1.0.0](https://github.com/casbin/casbin-rs/tree/v1.0.0) (2020-06-18)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.9.3...v1.0.0)

**Implemented enhancements:**

- Make effector a stream to optimize enforcing speed by quick return [\#125](https://github.com/casbin/casbin-rs/issues/125)
- split code into multiple features [\#97](https://github.com/casbin/casbin-rs/issues/97)
- automate package release [\#90](https://github.com/casbin/casbin-rs/issues/90)

**Closed issues:**

- casbin cache [\#170](https://github.com/casbin/casbin-rs/issues/170)
-  Explain enforcement by informing matched rules [\#141](https://github.com/casbin/casbin-rs/issues/141)
- Dont rebuild all role links [\#138](https://github.com/casbin/casbin-rs/issues/138)

**Merged pull requests:**

- Cleanup [\#173](https://github.com/casbin/casbin-rs/pull/173) ([GopherJ](https://github.com/GopherJ))
- add os matrix for CI [\#167](https://github.com/casbin/casbin-rs/pull/167) ([GopherJ](https://github.com/GopherJ))

## [v0.9.3](https://github.com/casbin/casbin-rs/tree/v0.9.3) (2020-05-25)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.9.2...v0.9.3)

**Closed issues:**

- Add AuthN & AuthZ sections for Rust in our awesome-auth list [\#160](https://github.com/casbin/casbin-rs/issues/160)

**Merged pull requests:**

- Change enforce and enforce\_mut to non-async. [\#166](https://github.com/casbin/casbin-rs/pull/166) ([schungx](https://github.com/schungx))
- remove explain relevant code when feature has been disabled [\#164](https://github.com/casbin/casbin-rs/pull/164) ([GopherJ](https://github.com/GopherJ))
- Speed improvements [\#163](https://github.com/casbin/casbin-rs/pull/163) ([schungx](https://github.com/schungx))
- Use eval\_expression to restrict to expressions only. [\#161](https://github.com/casbin/casbin-rs/pull/161) ([schungx](https://github.com/schungx))

## [v0.9.2](https://github.com/casbin/casbin-rs/tree/v0.9.2) (2020-05-13)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.9.1...v0.9.2)

## [v0.9.1](https://github.com/casbin/casbin-rs/tree/v0.9.1) (2020-05-13)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.9.0...v0.9.1)

## [v0.9.0](https://github.com/casbin/casbin-rs/tree/v0.9.0) (2020-05-13)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.8.7...v0.9.0)

## [v0.8.7](https://github.com/casbin/casbin-rs/tree/v0.8.7) (2020-05-13)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.8.6...v0.8.7)

**Merged pull requests:**

- Fix/cargo toml version [\#156](https://github.com/casbin/casbin-rs/pull/156) ([GopherJ](https://github.com/GopherJ))

## [v0.8.6](https://github.com/casbin/casbin-rs/tree/v0.8.6) (2020-05-13)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.8.5...v0.8.6)

## [v0.8.5](https://github.com/casbin/casbin-rs/tree/v0.8.5) (2020-05-13)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.8.4...v0.8.5)

**Merged pull requests:**

- fix: exec module not found [\#155](https://github.com/casbin/casbin-rs/pull/155) ([GopherJ](https://github.com/GopherJ))
- fix: semantic-release/exec-not-found [\#154](https://github.com/casbin/casbin-rs/pull/154) ([GopherJ](https://github.com/GopherJ))
- fix: semantic release [\#153](https://github.com/casbin/casbin-rs/pull/153) ([GopherJ](https://github.com/GopherJ))
- add status log [\#152](https://github.com/casbin/casbin-rs/pull/152) ([GopherJ](https://github.com/GopherJ))

## [v0.8.4](https://github.com/casbin/casbin-rs/tree/v0.8.4) (2020-05-12)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.8.3...v0.8.4)

**Merged pull requests:**

- fix cached enforcer mgmt event log [\#151](https://github.com/casbin/casbin-rs/pull/151) ([GopherJ](https://github.com/GopherJ))
- general improving [\#150](https://github.com/casbin/casbin-rs/pull/150) ([GopherJ](https://github.com/GopherJ))

## [v0.8.3](https://github.com/casbin/casbin-rs/tree/v0.8.3) (2020-05-12)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.8.2...v0.8.3)

## [v0.8.2](https://github.com/casbin/casbin-rs/tree/v0.8.2) (2020-05-12)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.8.1...v0.8.2)

**Merged pull requests:**

- Explain [\#149](https://github.com/casbin/casbin-rs/pull/149) ([GopherJ](https://github.com/GopherJ))

## [v0.8.1](https://github.com/casbin/casbin-rs/tree/v0.8.1) (2020-05-12)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.8.0...v0.8.1)

**Merged pull requests:**

- Revert "Effector stream" [\#147](https://github.com/casbin/casbin-rs/pull/147) ([GopherJ](https://github.com/GopherJ))
- Revert "Fix: CI" [\#146](https://github.com/casbin/casbin-rs/pull/146) ([GopherJ](https://github.com/GopherJ))
- finish effector stream [\#145](https://github.com/casbin/casbin-rs/pull/145) ([GopherJ](https://github.com/GopherJ))
- Fix: CI [\#143](https://github.com/casbin/casbin-rs/pull/143) ([GopherJ](https://github.com/GopherJ))

## [v0.8.0](https://github.com/casbin/casbin-rs/tree/v0.8.0) (2020-05-11)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.7.6...v0.8.0)

**Merged pull requests:**

- Effector stream [\#142](https://github.com/casbin/casbin-rs/pull/142) ([GopherJ](https://github.com/GopherJ))

## [v0.7.6](https://github.com/casbin/casbin-rs/tree/v0.7.6) (2020-05-11)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.7.5...v0.7.6)

## [v0.7.5](https://github.com/casbin/casbin-rs/tree/v0.7.5) (2020-05-11)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.7.4...v0.7.5)

**Merged pull requests:**

- Move build role links to internal [\#140](https://github.com/casbin/casbin-rs/pull/140) ([GopherJ](https://github.com/GopherJ))

## [v0.7.4](https://github.com/casbin/casbin-rs/tree/v0.7.4) (2020-05-10)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.7.2...v0.7.4)

**Merged pull requests:**

- Incremental build rolelinks [\#139](https://github.com/casbin/casbin-rs/pull/139) ([GopherJ](https://github.com/GopherJ))

## [v0.7.2](https://github.com/casbin/casbin-rs/tree/v0.7.2) (2020-05-10)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.7.1...v0.7.2)

**Merged pull requests:**

- Split code into features [\#137](https://github.com/casbin/casbin-rs/pull/137) ([GopherJ](https://github.com/GopherJ))

## [v0.7.1](https://github.com/casbin/casbin-rs/tree/v0.7.1) (2020-05-08)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.7.0...v0.7.1)

**Merged pull requests:**

- Fix: ClearCache log wasn't trigger [\#135](https://github.com/casbin/casbin-rs/pull/135) ([GopherJ](https://github.com/GopherJ))

## [v0.7.0](https://github.com/casbin/casbin-rs/tree/v0.7.0) (2020-05-08)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.6.2...v0.7.0)

**Implemented enhancements:**

- switch to smol when it's ready [\#130](https://github.com/casbin/casbin-rs/issues/130)

**Closed issues:**

- GSOC: logger system [\#84](https://github.com/casbin/casbin-rs/issues/84)
- GSOC: actix actor,actix middleware [\#82](https://github.com/casbin/casbin-rs/issues/82)

**Merged pull requests:**

- Simple logger [\#134](https://github.com/casbin/casbin-rs/pull/134) ([GopherJ](https://github.com/GopherJ))
- remove circular link caused by pattern matching func [\#133](https://github.com/casbin/casbin-rs/pull/133) ([GopherJ](https://github.com/GopherJ))
- make enforce immutable and add enforce\_mut [\#132](https://github.com/casbin/casbin-rs/pull/132) ([GopherJ](https://github.com/GopherJ))
- fix stackoverflow when circular link detected [\#131](https://github.com/casbin/casbin-rs/pull/131) ([GopherJ](https://github.com/GopherJ))

## [v0.6.2](https://github.com/casbin/casbin-rs/tree/v0.6.2) (2020-05-01)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.6.1...v0.6.2)

**Merged pull requests:**

- fix get\_implicit\_users\_for\_permission api [\#129](https://github.com/casbin/casbin-rs/pull/129) ([GopherJ](https://github.com/GopherJ))
- upgrade rhai to 0.13.0 [\#128](https://github.com/casbin/casbin-rs/pull/128) ([GopherJ](https://github.com/GopherJ))

## [v0.6.1](https://github.com/casbin/casbin-rs/tree/v0.6.1) (2020-04-25)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.6.0...v0.6.1)

**Merged pull requests:**

- add simple quick return [\#126](https://github.com/casbin/casbin-rs/pull/126) ([GopherJ](https://github.com/GopherJ))
- add get\_all\_policy, get\_all\_grouping\_policy [\#124](https://github.com/casbin/casbin-rs/pull/124) ([GopherJ](https://github.com/GopherJ))
- POC try scaling abac rules [\#121](https://github.com/casbin/casbin-rs/pull/121) ([GopherJ](https://github.com/GopherJ))

## [v0.6.0](https://github.com/casbin/casbin-rs/tree/v0.6.0) (2020-04-18)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.5.2...v0.6.0)

**Closed issues:**

- Implement FilteredAdapter [\#79](https://github.com/casbin/casbin-rs/issues/79)
- Roadmap for casbin-rs@1.0.0 [\#5](https://github.com/casbin/casbin-rs/issues/5)

**Merged pull requests:**

- Stable filtered adapter [\#120](https://github.com/casbin/casbin-rs/pull/120) ([GopherJ](https://github.com/GopherJ))
- Share engine [\#117](https://github.com/casbin/casbin-rs/pull/117) ([GopherJ](https://github.com/GopherJ))
- deactivate script functon, extra i8, i16...i128, and float math [\#116](https://github.com/casbin/casbin-rs/pull/116) ([GopherJ](https://github.com/GopherJ))

## [v0.5.2](https://github.com/casbin/casbin-rs/tree/v0.5.2) (2020-04-15)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.5.1...v0.5.2)

**Closed issues:**

- add github-action-benchmark [\#104](https://github.com/casbin/casbin-rs/issues/104)

**Merged pull requests:**

- use raw engine && bump version [\#115](https://github.com/casbin/casbin-rs/pull/115) ([GopherJ](https://github.com/GopherJ))
- add remove\_filtered\_policy details && enable\_auto\_notify\_watcher func… [\#113](https://github.com/casbin/casbin-rs/pull/113) ([GopherJ](https://github.com/GopherJ))
- Update rhai requirement from 0.11.1 to 0.12.0 [\#111](https://github.com/casbin/casbin-rs/pull/111) ([dependabot-preview[bot]](https://github.com/apps/dependabot-preview))
- Improve/benchmark [\#110](https://github.com/casbin/casbin-rs/pull/110) ([GopherJ](https://github.com/GopherJ))
- add benchmarks [\#108](https://github.com/casbin/casbin-rs/pull/108) ([GopherJ](https://github.com/GopherJ))
- Add workflow for benchmark. [\#107](https://github.com/casbin/casbin-rs/pull/107) ([PsiACE](https://github.com/PsiACE))

## [v0.5.1](https://github.com/casbin/casbin-rs/tree/v0.5.1) (2020-04-12)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.5.0...v0.5.1)

**Closed issues:**

- considering trait inheritance [\#99](https://github.com/casbin/casbin-rs/issues/99)
- Implement ABAC model [\#78](https://github.com/casbin/casbin-rs/issues/78)

**Merged pull requests:**

- Improve/watcher [\#106](https://github.com/casbin/casbin-rs/pull/106) ([GopherJ](https://github.com/GopherJ))
- Implement ABAC [\#102](https://github.com/casbin/casbin-rs/pull/102) ([xcaptain](https://github.com/xcaptain))
- use lazy static to avoid re-complilation of regex [\#96](https://github.com/casbin/casbin-rs/pull/96) ([DevinR528](https://github.com/DevinR528))

## [v0.5.0](https://github.com/casbin/casbin-rs/tree/v0.5.0) (2020-04-10)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.4.4...v0.5.0)

**Closed issues:**

- GSOC: tokio runtime, fully async adapter [\#81](https://github.com/casbin/casbin-rs/issues/81)

**Merged pull requests:**

- Improve/inheritance [\#103](https://github.com/casbin/casbin-rs/pull/103) ([GopherJ](https://github.com/GopherJ))

## [v0.4.4](https://github.com/casbin/casbin-rs/tree/v0.4.4) (2020-04-08)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.4.3...v0.4.4)

**Closed issues:**

- support pattern in role manager [\#94](https://github.com/casbin/casbin-rs/issues/94)
- improve error handling [\#85](https://github.com/casbin/casbin-rs/issues/85)
- Missing async support \(async-std + async adapter\) [\#43](https://github.com/casbin/casbin-rs/issues/43)

**Merged pull requests:**

- remove inMatch because rhai starts to support in operator since 0.11.1 [\#98](https://github.com/casbin/casbin-rs/pull/98) ([GopherJ](https://github.com/GopherJ))
- add support of pattern [\#95](https://github.com/casbin/casbin-rs/pull/95) ([GopherJ](https://github.com/GopherJ))

## [v0.4.3](https://github.com/casbin/casbin-rs/tree/v0.4.3) (2020-04-06)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.4.2...v0.4.3)

**Closed issues:**

- implementation of `TryIntoAdapter` and `TryIntoModel` trait [\#70](https://github.com/casbin/casbin-rs/issues/70)
- Missing logger support [\#51](https://github.com/casbin/casbin-rs/issues/51)

**Merged pull requests:**

- Improve/error handling [\#91](https://github.com/casbin/casbin-rs/pull/91) ([GopherJ](https://github.com/GopherJ))
- upgrade rhai to 0.11.1 to make Error Send, Sync [\#89](https://github.com/casbin/casbin-rs/pull/89) ([GopherJ](https://github.com/GopherJ))
- remove clones and string allocs, use macro for model retreval [\#87](https://github.com/casbin/casbin-rs/pull/87) ([DevinR528](https://github.com/DevinR528))

## [v0.4.2](https://github.com/casbin/casbin-rs/tree/v0.4.2) (2020-04-05)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/v0.4.1...v0.4.2)

**Closed issues:**

- Missing watcher support \(with a proper lock\) [\#46](https://github.com/casbin/casbin-rs/issues/46)

**Merged pull requests:**

- add TryIntoAdapter & TryIntoModel [\#86](https://github.com/casbin/casbin-rs/pull/86) ([GopherJ](https://github.com/GopherJ))

## [v0.4.1](https://github.com/casbin/casbin-rs/tree/v0.4.1) (2020-04-05)

[Full Changelog](https://github.com/casbin/casbin-rs/compare/9e7ebbddb5b92b6aad27412fadd82115793ea07a...v0.4.1)

**Implemented enhancements:**

- Database transactions similar api `addPolicies`, `removePolicies`  [\#55](https://github.com/casbin/casbin-rs/issues/55)
- Diesel adapter is calling for contribution! [\#35](https://github.com/casbin/casbin-rs/issues/35)
- Add a new from file api for model [\#32](https://github.com/casbin/casbin-rs/issues/32)
- Consider default implement some APIs for Enforcer [\#31](https://github.com/casbin/casbin-rs/issues/31)
- Rename the package name [\#30](https://github.com/casbin/casbin-rs/issues/30)
- Refactor API structure [\#29](https://github.com/casbin/casbin-rs/issues/29)
- Proper error handling \(eliminate unwrap calls\) [\#24](https://github.com/casbin/casbin-rs/issues/24)
- Role inheritance problem in rbac.rs [\#7](https://github.com/casbin/casbin-rs/issues/7)

**Fixed bugs:**

- Relation to Devolutions/casbin-rs? [\#23](https://github.com/casbin/casbin-rs/issues/23)

**Closed issues:**

- covert rule: Vec\<&str\> to rule: Vec\<String\> [\#73](https://github.com/casbin/casbin-rs/issues/73)
- Add Casbin-RS to our feature set table [\#71](https://github.com/casbin/casbin-rs/issues/71)
- Consider using the subslice patterns [\#67](https://github.com/casbin/casbin-rs/issues/67)
- Add unit tests for `addPolicies` and `removePolicies` [\#65](https://github.com/casbin/casbin-rs/issues/65)
- Add an example to Actix web examples repo [\#63](https://github.com/casbin/casbin-rs/issues/63)
- Automatically publish package to crate.io when a new git tag is created [\#58](https://github.com/casbin/casbin-rs/issues/58)
- Add crates badge that linked to: https://crates.io/crates/casbin [\#54](https://github.com/casbin/casbin-rs/issues/54)
- Missing cache support [\#45](https://github.com/casbin/casbin-rs/issues/45)
- Use github actions to auto generate rust doc  [\#33](https://github.com/casbin/casbin-rs/issues/33)
- Add "Installation" and "Get started" in README. [\#27](https://github.com/casbin/casbin-rs/issues/27)
- Should we stick with rust clippy [\#15](https://github.com/casbin/casbin-rs/issues/15)

**Merged pull requests:**

- add critcmp & insert into adapter before model [\#77](https://github.com/casbin/casbin-rs/pull/77) ([GopherJ](https://github.com/GopherJ))
- add glob\_match, make enforce function take only reference [\#76](https://github.com/casbin/casbin-rs/pull/76) ([GopherJ](https://github.com/GopherJ))
- Refactor: modify Vec\<&str\> to Vec\<String\> \(\#73\) [\#75](https://github.com/casbin/casbin-rs/pull/75) ([hackerchai](https://github.com/hackerchai))
- Benchmark [\#68](https://github.com/casbin/casbin-rs/pull/68) ([DevinR528](https://github.com/DevinR528))
- Added Unit Tests for `addPolicies` and `removePolicies` [\#66](https://github.com/casbin/casbin-rs/pull/66) ([drholmie](https://github.com/drholmie))
- Create release.yml [\#62](https://github.com/casbin/casbin-rs/pull/62) ([PsiACE](https://github.com/PsiACE))
- Update rustdoc workflow. [\#61](https://github.com/casbin/casbin-rs/pull/61) ([PsiACE](https://github.com/PsiACE))
- fix cache tests for runtime-tokio [\#60](https://github.com/casbin/casbin-rs/pull/60) ([GopherJ](https://github.com/GopherJ))
- Feature/model trait and add policies [\#59](https://github.com/casbin/casbin-rs/pull/59) ([GopherJ](https://github.com/GopherJ))
- Build docs [\#57](https://github.com/casbin/casbin-rs/pull/57) ([PsiACE](https://github.com/PsiACE))
- Add badges. [\#56](https://github.com/casbin/casbin-rs/pull/56) ([PsiACE](https://github.com/PsiACE))
- add async/await support [\#53](https://github.com/casbin/casbin-rs/pull/53) ([GopherJ](https://github.com/GopherJ))
- Add some keywords and readme and also optimize --release compiles [\#52](https://github.com/casbin/casbin-rs/pull/52) ([omid](https://github.com/omid))
- Feature/watcher and cache [\#50](https://github.com/casbin/casbin-rs/pull/50) ([GopherJ](https://github.com/GopherJ))
- fix more rbac apis \(add missing domain parameter\) & add prelude module [\#49](https://github.com/casbin/casbin-rs/pull/49) ([GopherJ](https://github.com/GopherJ))
- fix DefaultRoleManager::get\_users && add domain paramter to get\_roles… [\#48](https://github.com/casbin/casbin-rs/pull/48) ([GopherJ](https://github.com/GopherJ))
- using IndexSet to store policy in assertion [\#47](https://github.com/casbin/casbin-rs/pull/47) ([GopherJ](https://github.com/GopherJ))
- replace Box by Arc\<RwLock\> && add get\_model, get\_mut\_model for Model.… [\#44](https://github.com/casbin/casbin-rs/pull/44) ([GopherJ](https://github.com/GopherJ))
- Improve/add function and remove gg2 gg3 [\#42](https://github.com/casbin/casbin-rs/pull/42) ([GopherJ](https://github.com/GopherJ))
- fix typo in load\_assertion [\#41](https://github.com/casbin/casbin-rs/pull/41) ([zupzup](https://github.com/zupzup))
- add in operator [\#40](https://github.com/casbin/casbin-rs/pull/40) ([GopherJ](https://github.com/GopherJ))
- apply new error type to enforcer,model,config... [\#39](https://github.com/casbin/casbin-rs/pull/39) ([GopherJ](https://github.com/GopherJ))
- remove Send & Sync marker to make it easier to construct error types [\#37](https://github.com/casbin/casbin-rs/pull/37) ([GopherJ](https://github.com/GopherJ))
- make CasbinResult public [\#36](https://github.com/casbin/casbin-rs/pull/36) ([GopherJ](https://github.com/GopherJ))
- update some metadata [\#34](https://github.com/casbin/casbin-rs/pull/34) ([xcaptain](https://github.com/xcaptain))
- Add some get started doc [\#28](https://github.com/casbin/casbin-rs/pull/28) ([xcaptain](https://github.com/xcaptain))
- Add multi-thread support [\#26](https://github.com/casbin/casbin-rs/pull/26) ([xcaptain](https://github.com/xcaptain))
- make g function support 2 or 3 parameters [\#22](https://github.com/casbin/casbin-rs/pull/22) ([xcaptain](https://github.com/xcaptain))
- Optimize role manager and add more rbac apis [\#20](https://github.com/casbin/casbin-rs/pull/20) ([xcaptain](https://github.com/xcaptain))
- add error handling [\#19](https://github.com/casbin/casbin-rs/pull/19) ([xcaptain](https://github.com/xcaptain))
- add auto\_save and auto\_build\_role\_links option in enforcer [\#17](https://github.com/casbin/casbin-rs/pull/17) ([xcaptain](https://github.com/xcaptain))
- resolve clippy warnings and add clippy to travis [\#16](https://github.com/casbin/casbin-rs/pull/16) ([GopherJ](https://github.com/GopherJ))
- Feature/enforcer rbac api [\#14](https://github.com/casbin/casbin-rs/pull/14) ([xcaptain](https://github.com/xcaptain))
- add unit tests for model and implement ip match [\#13](https://github.com/casbin/casbin-rs/pull/13) ([GopherJ](https://github.com/GopherJ))
- use Rc\<RefCell\<Role\>\> to store roles [\#9](https://github.com/casbin/casbin-rs/pull/9) ([xcaptain](https://github.com/xcaptain))
- add travis-ci and codecov badges [\#6](https://github.com/casbin/casbin-rs/pull/6) ([xcaptain](https://github.com/xcaptain))
- \[add\]: load\_model && load\_model\_from\_text [\#4](https://github.com/casbin/casbin-rs/pull/4) ([GopherJ](https://github.com/GopherJ))
- \[add\]: support for parsing config files with multiple lines [\#3](https://github.com/casbin/casbin-rs/pull/3) ([GopherJ](https://github.com/GopherJ))
- add a basic parsing functions for ini config file [\#2](https://github.com/casbin/casbin-rs/pull/2) ([xcaptain](https://github.com/xcaptain))
- add basic matching function for casbin [\#1](https://github.com/casbin/casbin-rs/pull/1) ([xcaptain](https://github.com/xcaptain))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
