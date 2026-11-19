# iSafe Keylogger PRO / WPK - Fake GTA 6 Installer Analysis

An evidence-driven analysis of a Windows installer named **`GTA 6.msi`** containing the **iSafe Keylogger PRO / AllInOne Keylogger** surveillance suite, including its **WPK.exe** collector and **WPK64.exe** helper.

**[Read the full forensic report - 95 pages](iSafe_Keylogger_PRO_GTA6_Forensic_Report.pdf)**

**Analysis date:** 19 November 2026  
**Classification:** spyware / keylogging and surveillance software distributed through deceptive packaging  
**Family attribution:** iSafe Keylogger PRO / AllInOne Keylogger, WPK lineage - high confidence

## Overview

The installer uses a game filename while declaring a Microsoft-like product identity and installing a surveillance application under `C:\ProgramData\windows-systempro`.

The attribution is supported by internal product names, PDB paths, the paired WPK/IMME architecture, a populated logging database, and exact component-hash matches in an independent public sandbox report. It is an analytical identification: the supplied CAPE reports did not return a successful antivirus family verdict because their VirusTotal requests failed with HTTP 429.

The strongest findings are:

- **The installed execution chain is confirmed.** Sysmon and Windows Security events record the MSI launching WPK, followed by WPK launching WPK64 with `#3763`.
- **The MSI already contains captured historical material.** Its embedded SQLite database has **2,057 `wLog` records** predating the laboratory runs.
- **A delivery configuration is embedded.** `subcfg` contains an SMTP server, account and stored credential. The credential is redacted from the published analysis.
- **Multiple collection capabilities are supported.** Static evidence covers keyboard/raw input, clipboard access, mouse/window context and microphone recording, with additional screen-capture support.
- **CAPE's API view is incomplete for the payloads.** The confirmed WPK/WPK64 PIDs are missing from the API-process lists, despite their presence in independent Windows events.
- **Successful exfiltration is not demonstrated by the supplied PCAPs.** A configured SMTP account is not evidence that a message was sent or received.

## Scope and evidence

The analysis correlates MSI tables, independently extracted cabinet files, PE metadata, decompiler exports, raw BSON/API records, Windows event logs, PCAPs, Zeek logs, screenshots and process-memory artifacts.

| Evidence / measurement | Count |
| --- | ---: |
| CAPE sessions | 3 - tasks 8, 9 and 13 |
| Inventoried input files | 400 |
| Independently extracted MSI cabinet members | 24 |
| CAPE API call rows reviewed | 30,044 |
| BSON records decoded | 31,538 |
| Periodic EVTX export files parsed | 638 |
| Deduplicated Windows events, summed per task | 10,156 |
| Screenshots decoded and inventoried | 209 |
| Historical `wLog` records in the bundled database | 2,057 |

The Windows executions described here were captured in the supplied CAPE evidence. The subsequent offline analysis did not execute the original malware samples. Compiled checks apply to the inert C models included with the analysis.

## Primary sample hashes

These hashes identify the **original installer and extracted executable bytes**, not the reconstructed C files. MD5 is included for compatibility with sample databases; SHA-256 is the primary identity value.

| Original file | Size (bytes) | MD5 | SHA-256 |
| --- | ---: | --- | --- |
| `GTA 6.msi` | 7,127,040 | `37ceac4b41884711ec3f40a920f1cf32` | `368427c356b85f99e0d58d06eeac2bca210c3aa6383c19eb4722d9d4fdb4b82a` |
| `WPK.exe` | 6,162,944 | `8d786798081117e78b6c201c42ecf06b` | `35e6be911a65cae4fab14f5354c66a8ef5fb19301043d2456804fcb3a59e0ec4` |
| `WPK64.exe` | 58,368 | `bd5bdbf05557bd0ad5a9949c8bed35d0` | `980d667a7abdf54d598cbbdbb51f3ed2f70614c6b1e3950721834e9ae90f5f56` |

<details>
<summary>Additional primary-sample SHA-1 hashes</summary>

| Original file | SHA-1 |
| --- | --- |
| `GTA 6.msi` | `66cee3714147fd50926ceea95703928cc31d7293` |
| `WPK.exe` | `28e22b9fdc1219390d53cb2b0b65a84b875da196` |
| `WPK64.exe` | `cebfd24449845b4c825571466cedc68f594490df` |

</details>

## Installer identity and behavior

| Property / artifact | Observed value |
| --- | --- |
| Submitted filename | `GTA 6.msi` |
| MSI product name | `system windows ........` |
| Claimed manufacturer | `Microsoft2026` |
| MSI product version | `11.0.0` |
| Product code | `{8CC301C3-0636-45A8-BEA3-FC4AE700B157}` |
| Upgrade code | `{CA90359B-7024-42CE-837E-CE3B07533C83}` |
| Main installation directory | `C:\ProgramData\windows-systempro` |
| Data/configuration directory | `C:\Users\Public\L001` |
| Execution custom action | `Action1_WPK.exe` |
| Custom-action type | `1234` / `0x04d2` |
| Custom-action source | Installed file `WPK.exe` |
| Custom-action condition | `(NOT Installed)` |

The custom-action type specifies an installed EXE with deferred, asynchronous execution and ignored return status. Its `NoImpersonate` flag is absent; the type alone does not establish SYSTEM-context execution. The observed task 8 WPK event records Medium integrity.

The Microsoft-like product strings are installer metadata and do not establish Microsoft authorship or signing.

## Confirmed execution chain

The installed run provides the clearest behavioral evidence:

| Step | Process / PID | Evidence |
| --- | --- | --- |
| MSI client launch | `msiexec.exe`, PID `6024` | Sysmon Event 1 and Security Event 4688 |
| Collector launch | `WPK.exe`, PID `6788` | Installed path; parent is service-side `msiexec.exe`, PID `3480` |
| Helper launch | `WPK64.exe`, PID `5276` | Parent WPK PID `6788`; command-line marker `#3763` |
| Visual corroboration | WPK x86 and WPK64 x64 | Task 8 screenshot `0035.jpg` shows the same names and PIDs |

WPK64 creates a hidden window named `WPK64_W` and delegates hook installation to `IMME64.dll` when the activation path is reached. Its marker check is a substring test, not an authentication mechanism.

The isolated runs are materially different:

| CAPE task | Target | Observed lifetime | Interpretation |
| --- | --- | ---: | --- |
| 8 | `GTA 6.msi` | Collector/helper chain observed | Installed execution confirmed |
| 9 | Standalone `WPK.exe` | Approximately 2.167 seconds | Early exit; exact cause unresolved |
| 13 | Standalone `WPK64.exe` | Approximately 2.092 seconds | `#3763` absent; activation path not reproduced |

The standalone launches use a temporary-file context rather than the complete installed tree. Missing dependencies and initialization conditions remain possible explanations; the available logs do not establish a single failure cause.

## Component roles

| Component | Supported role |
| --- | --- |
| `WPK.exe` | Primary 32-bit collector and application orchestrator |
| `WPK64.exe` | 64-bit hidden-window hook helper |
| `IMME.dll` / `IMME64.dll` | Architecture-specific hook implementations |
| `wpkr.exe` | Associated interface/log-console component; historical records reference its dialogs |
| `SecPro.exe` / `SvcControl.exe` | Service-support components; presence alone does not prove service installation |
| `FltEng.dll` | Auxiliary engine with hook and network-related imports |
| `df.exe` | Auxiliary executable; its full role remains unresolved |
| `wpkun.bin` | PE-format uninstall/support component |
| `subcfg` | Binary monitoring and delivery configuration |
| `W0000` | Pre-existing SQLite log database |
| `W0002` / `W0003` | Binary state files, 52 and 128 bytes respectively |

The cabinet also includes Microsoft VC90 runtime components and curl/OpenSSL/LDAP/SASL libraries. Their inclusion does not make every dependency an independently malicious file.

## Host indicators

### Installation and data paths

| Path / filename | Context |
| --- | --- |
| `C:\ProgramData\windows-systempro\WPK.exe` | Installed collector |
| `C:\ProgramData\windows-systempro\WPK64.exe` | Installed x64 helper |
| `C:\ProgramData\windows-systempro\IMME.dll` | 32-bit hook module |
| `C:\ProgramData\windows-systempro\IMME64.dll` | 64-bit hook module |
| `C:\Users\Public\L001\subcfg` | Configuration |
| `C:\Users\Public\L001\W0000` | SQLite monitoring database |
| `C:\Users\Public\L001\W0002` | Binary state |
| `C:\Users\Public\L001\W0003` | Binary state |
| `ixsaflog.dat` | Diagnostic-log basename referenced by WPK |
| `ftpokay.txt` | Local status/test artifact; not independent proof of a successful FTP transfer |
| `sdYYYY-MM-DD_HH-MM-SS.wav` | Recovered microphone-recording filename pattern |

### Declared persistence

The MSI Registry table declares these values:

| Registry value | Data |
| --- | --- |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\iSafe` | `C:\ProgramData\windows-systempro\WPK.exe` |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\LoginDat` | `C:\ProgramData\windows-systempro\Microsoft2021.bat` |

`Microsoft2021.bat` is referenced by the installer but is absent from the recovered cabinet. Its contents and post-install existence are unresolved. The authored registry paths are preserved as evidence; effective registry-view placement and persistence replay after logon were not confirmed.

### Named objects, windows and coordination strings

| Indicator | Context |
| --- | --- |
| `_MPKON_TX_2` | Collector single-instance mutex |
| `WWWPXX64_ON_` | Helper single-instance mutex |
| `_CON_QUIT_` | Named quit event |
| `_MUTEXT-LOG-FIE_` | Diagnostic-log serialization mutex |
| `WPK_WIND` | Collector window title |
| `WPK64_W` | Helper window title |
| `MMXIME32_` | 32-bit coordination channel |
| `MMXIME64_` | 64-bit coordination channel |
| `MMXEUSAUL_` | Additional application coordination channel |
| `#3763` | Helper activation marker |
| `UWM_LLLBDN_MSG-44E531B1_14D3_11d5_A025_006067718D04` | Registered application message |

The IPC helper derives object names using `Global\EVENT_%s`, `Global\MUTEX_%s`, and `Local\FILEMAPPING_%s` or `Global\FILEMAPPING_%s`. These are naming templates, not complete observed object names by themselves.

### Static identifiers

| Artifact | Value |
| --- | --- |
| WPK PDB path | `d:\iSafeDev\SVNDev\WPK\WPK.pdb` |
| WPK64 PDB path | `e:\SVNSrc\trunk\WPK64\WPK64.pdb` |
| WPK imphash | `9d29b98c539b9fc9837db84bd4758f65` |
| WPK64 imphash | `6275d4a37c0ea616ee6330b6762d2231` |
| 32-bit hook exports | `setLBDownHook`, `clearLBDownHook` |
| 64-bit hook exports | `setLBDownHook64`, `clearLBDownHook64` |
| Product string | `iSafe Keylogger PRO` |
| Embedded welcome-version claim | `iSafe Keylogger v6.2` |

PDB paths, version claims and PE timestamps are mutable metadata. They support correlation and do not independently establish authorship or development dates.

## Network and delivery indicators

| Indicator | Source | Interpretation |
| --- | --- | --- |
| `taratararosoroso@yandex.com` | `subcfg`, file offset `0x1bc` | Configured SMTP account; ownership and successful delivery are not established |
| `smtp.yandex.com` | `subcfg`, file offset `0xec` | Shared SMTP provider endpoint; correlate with process/account evidence |
| `hxxp://isafesoft[.]com/keylogger-pro/buy.htm` | WPK application strings | Product branding/purchase reference; not established C2 |
| `hxxp://isafesoft[.]com/faq/index.htm#welcome` | WPK application strings | Product help reference; not established C2 |

The stored SMTP credential is omitted from the published material. No authentication attempt was performed.

Independent packet parsing found **572**, **404** and **431** packets in tasks 8, 9 and 13. The few TCP packets target the local gateway on DNS port 53; they do not demonstrate a remote SMTP session. Background Windows/update domains, laboratory IP addresses and `searchapp.bundleassets.example` are not attributed to attacker infrastructure.

**No successful log exfiltration is demonstrated by these captures.** This limits the observed outcome, not the software's delivery capability.

## Historical database and configuration

The MSI includes a valid **384,000-byte SQLite database**, `W0000`, with:

- **2,057 `wLog` rows** and **50 `rLog` rows**.
- Host/user context, numeric event categories, application-specific timestamps, captured data, window titles and file paths.
- Screenshot-basename records and mouse/activity descriptions.
- Historical interactions with the keylogger console and SMTP configuration dialogs.

The dominant empirical timestamp conversion spans **9 September 2022 through 4 November 2026**. A subset of records differs by one second or one hour; raw timestamps are retained, and the conversion is not presented as a universal UTC timeline.

These records were **already packaged inside the installer**. They are not new victim data collected during the 19 November CAPE sessions. Captured historical content and incidental private identifiers are redacted in the supporting exports.

`subcfg` is **4,572 bytes**: a four-byte update counter followed by a **4,568-byte body**. The supplied configuration contains a nondefault hotkey, a configured SMTP account and additional customized settings. Unknown flags remain explicitly unresolved.

## Capabilities and evidence boundaries

| Capability | Local evidence | Status |
| --- | --- | --- |
| Keylogging / input observation | Raw-input registration/retrieval, hook modules, historical input records | Static capability and historical-use evidence |
| Clipboard observation | Clipboard-viewer registration and retrieval xrefs | Static capability; historical content corroboration |
| Mouse/window observation | Hook registration, window metadata and formatted click records | Static capability and historical-use evidence |
| Screen capture | Screen/PNG/attachment references and historical screenshot basenames | Supported capability; no attributable new screenshot spool acquired |
| Microphone recording | Recovered wave-input and RIFF/WAVE recorder lifecycle | Static capability; no attributable new recording acquired |
| Log delivery | SMTP settings and email/FTP/IMAP/Drive application references | Configured/static capability; successful transfer unproven |
| Logon persistence | MSI Registry table | Declared; replay after logon unobserved |

Relevant ATT&CK mappings include [T1056.001](https://attack.mitre.org/techniques/T1056/001/), [T1115](https://attack.mitre.org/techniques/T1115/), [T1113](https://attack.mitre.org/techniques/T1113/), [T1123](https://attack.mitre.org/techniques/T1123/) and [T1547.001](https://attack.mitre.org/techniques/T1547/001/). These mappings describe supported capabilities and declared behavior, not proof that every feature ran successfully in each session.

The evidence does not establish ransomware, a destructive wiper, a named threat actor, browser-database decryption or malware-driven LSASS dumping.

## Sandbox artifacts and false-positive control

Several apparent high-severity findings require attribution before being treated as malware behavior:

- The confirmed WPK/WPK64 processes are absent from the CAPE API-process lists. Independent Sysmon/Security events establish their execution.
- **Twenty-four 312-byte CAPE captures** contain analyzer-selected monitor-DLL paths and are attributed to instrumentation context, not twenty-four additional malware stages.
- Large monitor images and Windows resource images in context-process memory are not automatically WPK payloads.
- Token/ACL and suspended-process marks belong to Windows context processes in the cited traces. They do not establish WPK ransomware or a WPK injection chain.
- The `invalid_authenticode_signature` alert's detail is a **file-not-found** condition, not a demonstrated cryptographic signature failure.

The PDF retains the owning PIDs, API marks, acquisition limitations and competing interpretations.

## Repository contents

| Path | Purpose |
| --- | --- |
| [iSafe_Keylogger_PRO_GTA6_Forensic_Report.pdf](iSafe_Keylogger_PRO_GTA6_Forensic_Report.pdf) | Full 95-page forensic report |
| [source/WPK_readable.c](source/WPK_readable.c) | Readable, inert WPK semantic reconstruction and passive configuration parser |
| [source/WPK64_readable.c](source/WPK64_readable.c) | Readable, inert helper reconstruction |
| [source/source_map.csv](source/source_map.csv) | 137 recovered application-region address/line locators |
| [source/README.md](source/README.md) | Reconstruction scope and build instructions |
| [detections/isafe_wpk.yar](detections/isafe_wpk.yar) | Four YARA rules for core, helper, hook modules and case-specific MSI |
| [detections/wpk64_process.yml](detections/wpk64_process.yml) | Experimental Sigma helper-activation rule |
| [detections/wpk_registry.yml](detections/wpk_registry.yml) | Experimental Sigma policy Run persistence rule |
| [evidence_tables/indicators.csv](evidence_tables/indicators.csv) | Indicators with source, confidence and interpretation |
| [evidence_tables/msi_payload_hashes.csv](evidence_tables/msi_payload_hashes.csv) | Full cabinet hash/PE metadata inventory |
| [evidence_tables/relevant_windows_events.json](evidence_tables/relevant_windows_events.json) | Corroborating Windows events |
| `evidence_tables/` | Redacted database index, MSI tables, packet/Zeek audits, signature audit and acquisition inventories |
| [verification.json](verification.json) | Recorded validation results |
| [SHA256SUMS.txt](SHA256SUMS.txt) | Checksums from the original analysis package |

The C files are **semantic reconstructions, not recovered original source or byte-equivalent rebuilds**. Native capture, hooks, process creation, persistence and delivery are represented by inert model state. Missing worker bodies remain identified by their original addresses.

Both C models compiled with strict warnings and passed their embedded checks. All four YARA rules compiled and produced the expected matches on five positive-control files, with no matches on the other 20 objects in the limited test corpus. The two Sigma files were parsed as YAML; production backend deployment was not tested.

## Additional cabinet hashes

The following inventory complements the WPK/WPK64 hashes above. Dependency hashes are provided for provenance and should not be treated as blanket malware indicators.

<details>
<summary>Show MD5 and SHA-256 for the other 22 cabinet members</summary>

| Cabinet member | Size (bytes) | MD5 | SHA-256 |
| --- | ---: | --- | --- |
| `IMME.dll` | 78,336 | `1b97917c70383fac9bf52461edc8e5da` | `4319b9a511b7edae8f22903a1748e3e6d34925896459b585d426258a59d180ed` |
| `IMME64.dll` | 66,048 | `eb252b262603c6835c450e89b3a8bc86` | `69222394c50e162942053be9852d2200b4d65dfc9a6152cfa05280b5368a7d21` |
| `wpkr.exe` | 1,432,064 | `9bdd0454452116e45fde61e96894219d` | `f6ffaf12545d708ed2689088778836329993647ac2915e4472495b4cdac808ae` |
| `SecPro.exe` | 61,440 | `6cb12df92e2148c699644fd6fd365cc9` | `27f36031c76e6e99ca440b998b38c1f76503ecdb9abe32cc63b935b349ae38c5` |
| `SvcControl.exe` | 13,312 | `8d018d57d934c5fc7cf6233b91f3f662` | `580f5c942c5529743baf4e97e3e2525fb111474953fb94da32cb6edac841f50b` |
| `FltEng.dll` | 235,008 | `ad63e34f0838735a1880d829e721eef5` | `42e97a35e1e3fbd97664e705ab073773f04da18140fe1f925c1217d82f7c8970` |
| `df.exe` | 252,416 | `81cfd43ebbaaf78edb97cef7a81aa6ef` | `63d1c563992fbb7c44ec087637ecb1995eb6888f5b2e15704c5e15acc51d6dcc` |
| `wpkun.bin` | 228,864 | `0323ae2a6d4c5a91110f1049ee893495` | `c8b2e1b66d22b31e1e8502e76d048f9438574ab2ef8ac38109b17e1e1e1f1658` |
| `subcfg` | 4,572 | `f09fa0b3145d9e6271505d729440512c` | `cde9e580b465292ef57108431ee7500c19f56bc8d6d4ad32af607e08e5b23245` |
| `W0000` | 384,000 | `1ac7034b993054cb115d30dedd77d32e` | `e509bc4e06554d74b0ac7a589e654108e772dd4afa635785824697185e47ce35` |
| `W0002` | 52 | `a09dac25d7dded2f1377a74409f6ee36` | `2e8bbef92de60ed8906e401ba182074ae9c48ce784ae0dc211539c8646d260d0` |
| `W0003` | 128 | `6afcd6c979c624112b1cd3e0721b4a8d` | `87f777897ea9b900707fd2e8eb03c7bfb4ffd8ff4ea1053eabc9fadf6b6eb647` |
| `Microsoft.VC90.CRT.manifest` | 1,857 | `ef6a2dfbd914169a3209137ab7b97e05` | `382115a60ec7e48894e1c3ba311ec31636443350e11184ce8bf88b738588ce52` |
| `Microsoft.VC90.MFC.manifest` | 2,354 | `be81faa8d3c3491618651771ab4fa514` | `c54c9d9a89dcddbaf3edf3ec10ca434b5cc5718a175438c365c5049c3bc4aa29` |
| `curllib.dll` | 194,048 | `3b61db29136b42f1e820a3602280249b` | `bea3e29ef3d16348af60d0ba57545e8f351bc277655128e7c5fddc8e6621af3b` |
| `libeay32.dll` | 1,016,832 | `6a24f76940cf7dab794d60c7b8538d5c` | `37efd3cb7553caf1b188469926182f3fc83faef71d3fa6e56795c5d0dadbef37` |
| `libsasl.dll` | 198,656 | `b14e855d8a9f5871af5be321e89d9844` | `d0a1c93c5ee2d8401d0c653ef7676b609062124c86db0be7f6c521bbad0f4f4e` |
| `mfc90u.dll` | 3,780,424 | `423069307fb726e51e2a66f1c3f738fe` | `314ef0e1c636ac553c0e09f992b34573da4a89accb759bda27335e8125c08e35` |
| `msvcp90.dll` | 572,928 | `871f979d70414c900b35e56222932daf` | `91fd46d7335c9990a20f215b9f6f53bc59551420a9c99ad8110ae2f9ff7598f0` |
| `msvcr90.dll` | 655,872 | `4d03ca609e68f4c90cf66515218017f8` | `cf420aced0d810e1d75f6811dd986f2d9fded2fbb8d61fc9a7024520c475febb` |
| `openldap.dll` | 110,592 | `9eba4562872965f59edeecd4a4efafb9` | `eea3d3d34b152ac77b582385b94b8bb41b717e2e1c08f5cfb334c1008e485396` |
| `ssleay32.dll` | 274,432 | `37b4ea6dd710deb0b33299f3a692c9d9` | `aedfcddce0d104176f9ab64bf4cd43fd9fab978b883dc48af632a8ee76cc8869` |

</details>

## References

- [Full forensic report](iSafe_Keylogger_PRO_GTA6_Forensic_Report.pdf), including evidence locators, methodology, limitations and source listings.
- [Independent Triage report: 250713-sppmmaslx5](https://tria.ge/250713-sppmmaslx5/behavioral2), containing identical WPK/WPK64 component hashes inside a differently named installer. This supports component reuse, not common-operator attribution.
- [Doctor Web: Trojan.DownLoader11.18281](https://vms.drweb.com/virus/?i=3965320), historical context for an overlapping iSafe component bundle. This vendor-specific variant name is not asserted as the exact verdict for the current MSI.

The published analysis package excludes original executable samples, stored SMTP passwords and unredacted captured content. The report distinguishes confirmed execution, static capability, declared configuration and unresolved questions throughout.
