# MCP Analysis Artifact Coverage and Flow

??臾몄꽌??forensic-workstation MCP 遺꾩꽍 ?⑥닔媛 ?대뼡 利앷굅?먯쓣 而ㅻ쾭?섎뒗吏,
洹몃━怨?遺꾩꽍媛媛 ?대뼡 ?쒖꽌濡??섎룞 寃利앷낵 ?먮룞 ?먯?瑜?議고빀?댁빞 ?섎뒗吏 ?뺣━?쒕떎.

?듭떖 ?먯튃? ??媛吏??

- MCP ?꾧뎄 寃곌낵???먯젙???꾨땲??利앷굅 紐⑸줉, coverage ?곹깭, ?ㅼ쓬 ?쇰쿁 ?뚰듃??
- 0嫄?寃곌낵???쒕룞 ?놁쓬??利앷굅媛 ?꾨땲?? coverage gap, parser failure, ?꾪꽣, ?좎쭨 踰붿쐞瑜?癒쇱? ?뺤씤?쒕떎.
- backend媛 ?쒓났??artifact family, rule id, ?뚯씪 寃쎈줈, ?댁떆, registry key, timestamp, command line? ?먮Ц 利앷굅濡??좎??쒕떎.

## Ultimate Objective: E01-Only Analyst Parity

???꾨줈?앺듃??理쒖쥌 紐⑺몴??MFDB/AXIOM/KAPE ?섏〈???④퀎?곸쑝濡??쒓굅?섍퀬,
E01/VMDK/raw image留뚯쑝濡쒕룄 KAPE ?먮뒗 MFDB 湲곕컲 遺꾩꽍??以?섎뒗 ?먯???
而ㅻ쾭由ъ? ?ㅻ챸?? ??꾨씪??援ъ꽦?? 諛섎났 寃???깅뒫???쒓났?섎뒗 寃껋씠??

??臾몄꽌???꾩옱 coverage matrix??"?꾩옱 援ы쁽 ?곹깭"? "紐⑺몴 ?곹깭"瑜?援щ텇?댁꽌
?쎌뼱???쒕떎. ?꾩옱 raw sidecar???쇰? high-value artifact瑜?吏?먰븯吏留? 理쒖쥌
紐⑺몴??Windows endpoint IR?먯꽌 ?뚮젮吏?二쇱슂 artifact family瑜?raw image?먯꽌
吏곸젒 ?뚯떛?섍굅?? ?뚯떛 遺덇? ??紐낆떆?곸씤 coverage gap?쇰줈 蹂닿퀬?섎뒗 寃껋씠??

E01-only parity???⑥닚??artifact parser ?섎? ?섎━??寃껋씠 ?꾨땲?? 媛?artifact
family???ㅼ쓬 怨꾩빟??留뚯”?댁빞 ?쒕떎.

- Source discovery: ?먮낯 寃쎈줈, VSS layer, ?ъ슜??profile, hive/control set???꾨씫 ?놁씠 李얜뒗??
- Parser contract: ?깃났, partial, not_evaluable, coverage_gap, cap reached瑜?援щ텇?쒕떎.
- Evidence semantics: ?ㅽ뻾, ?ㅼ젙 議댁옱, ?ъ슜???됱쐞, ?ㅽ듃?뚰겕 愿李? anti-forensic ?됰룞??援щ텇?쒕떎.
- Timeline semantics: UTC, device-local, file-system timestamp, registry LastWrite瑜??쇰룞?섏? ?딅뒗??
- Query parity: `search_artifacts`, `build_timeline`, `slice_timeline`, `correlate`, `coverage_explainer`?먯꽌 媛숈? 諛⑹떇?쇰줈 蹂댁씤??
- Bias resistance: ??artifact hit媛 ?꾩껜 遺꾩꽍 諛⑺뼢??怨좎젙?섏? ?딅룄濡?lane蹂??쒗쉶? 諛섏쬆 ?덉감瑜?媛뺤젣?쒕떎.
- Regression evidence: parser, zero-result handling, cap handling, and report wording???뚯뒪?몃줈 怨좎젙?쒕떎.

## E01 Parity Acceptance Criteria

| Capability area | Acceptance criterion |
| --- | --- |
| Raw artifact coverage | KAPE/MFDB ?놁씠 core Windows endpoint artifact families瑜?raw image?먯꽌 吏곸젒 ?됱씤?섍굅?? 誘몄???family瑜?`not_evaluable`濡??몄텧 |
| Search parity | raw sidecar artifact媛 parsed case? 媛숈? `search_artifacts` / `build_timeline` / `coverage_explainer` 寃쎈줈濡?議고쉶 媛??|
| Timeline parity | EVTX, NTFS, Prefetch, SRUM, registry, browser, Defender, WMI, BITS ??source蹂?timestamp semantics瑜?蹂댁〈??timeline ?앹꽦 |
| Rule parity | parsed-case ?꾩슜 rule? raw-only?먯꽌 silent-zero媛 ?꾨땲??unevaluable濡?蹂닿퀬?섍퀬, raw-index 吏??rule? raw evidence?먯꽌 吏곸젒 ?됯? |
| Performance | ???E01?먯꽌 諛섎났 荑쇰━??sidecar index瑜??ъ슜?섍퀬, direct parser??targeted verification???쒖젙 |
| Artifact freshness | ?좉퇋 Windows artifact, 理쒓렐 移⑦빐?ш퀬?먯꽌 以묒슂?댁쭊 artifact, ?꾧뎄 ?붿쟻??backlog媛 ?꾨땲??coverage registry??紐낆떆 |
| Bias control | lane-balanced traversal, refutation tasks, strong-conclusion gates瑜??듦낵?섏? ?딆쑝硫?寃곕줎 ???lead/hypothesis濡?異쒕젰 |
| Auditability | 紐⑤뱺 finding? source path, parser run, coverage status, raw field provenance瑜?異붿쟻 媛??|

## Bias-Resistant Artifact Traversal

AI 遺꾩꽍 ?붿쭊? 泥?踰덉㎏濡?蹂댁씤 ?섏떖 artifact??anchoring?섏뼱 ?ㅻⅨ artifact瑜?蹂댁? ?딅뒗 ?ㅽ뙣瑜?留됱븘???쒕떎. ?대? ?꾪빐 遺꾩꽍? "loudest signal first"媛 ?꾨땲??"coverage-first, lane-balanced, timeline-window traversal"濡?吏꾪뻾?쒕떎.

沅뚯옣 ?쒗쉶 諛⑹떇:

1. Coverage inventory瑜?癒쇱? 留뚮뱺??
   - `case_health`, `coverage_explainer`, raw parser run status, VSS ?곹깭瑜??뺤씤?쒕떎.
   - artifact family蹂?searched / not_evaluable / coverage_gap??湲곕줉?쒕떎.
2. Suspicion-independent timeline windows瑜?留뚮뱺??
   - ?뱀젙 IOC??rule hit ?댁쟾?? ?꾩껜 timeline?먯꽌 activity burst? source gap??癒쇱? 蹂몃떎.
   - cap reached ?먮뒗 thin source??蹂꾨룄 warning?쇰줈 ?좎??쒕떎.
3. Lane蹂?round-robin???섑뻾?쒕떎.
   - Ingress/access
   - Execution/impact
   - Persistence/cleanup
   - Credential/lateral movement
   - Defense evasion
   - C2/download/exfil
4. 媛?lane?먯꽌 理쒖냼 ?섎굹??primary artifact? ?섎굹??corroboration artifact瑜?李얘굅?? ??李얠쓣 ???녿뒗吏 coverage gap?쇰줈 ?④릿??
5. 泥?踰덉㎏ suspicious chain??諛쒓껄?대룄 利됱떆 寃곕줎???대━吏 ?딅뒗??
   - 媛숈? ?쒓컙????ㅻⅨ artifact family瑜??쒗쉶?쒕떎.
   - benign/admin explanation??諛섏쬆?쒕떎.
   - missing source媛 寃곕줎??留됰뒗吏 ?뺤씤?쒕떎.
6. Strong-conclusion gate瑜??듦낵?섏? 紐삵븯硫?寃곕줎 臾멸뎄瑜???텣??
   - "confirmed" ???"observed", "lead", "hypothesis", "requires corroboration"?쇰줈 ?쒗쁽?쒕떎.

理쒖냼 ?붽뎄?ы빆: coverage媛 議댁옱?섎뒗 lane??嫄대꼫?곌퀬 ?⑥씪 artifact family留뚯쑝濡?理쒖쥌 寃곕줎???묒꽦?댁꽌?????쒕떎. ?⑥씪 artifact family濡쒕뒗 triage lead瑜?留뚮뱾 ???덉?留? incident conclusion? ?ㅼ쨷 family ?먮뒗 紐낆떆??gap reasoning???꾩슂?섎떎.

## Evidence Source Model

MCP 遺꾩꽍? 媛숈? ?곗씠?곕? ??寃쎈줈濡쒕쭔 蹂댁? ?딅뒗?? 利앷굅 異쒖쿂瑜?遺꾨━?댁꽌 ?댁꽍?댁빞 ?쒕떎.

| Source | ????⑥닔 | ?⑸룄 | ?댁꽍 二쇱쓽 |
| --- | --- | --- | --- |
| Parsed case | `open_case`, `search_artifacts`, `find_suspicious`, `hunt_evtx_rules` | AXIOM/Magnet/KAPE ?곗텧臾쇱쓣 鍮좊Ⅴ寃?寃?됲븯怨?猷??곸슜 | parser媛 留뚮뱺 artifact留?蹂댁씤?? 鍮좎쭊 family??遺??利앷굅媛 ?꾨땲?? |
| Mounted raw image | `mount_image`, `list_files`, `get_file_timestamps`, `extract_file` | ?뚯씪 議댁옱, NTFS timestamp, ?뺤쟻 遺꾩꽍 ???異붿텧 | 異붿텧 ?뚯씪? ?덈? ?ㅽ뻾?섏? ?딅뒗?? |
| Raw sidecar index | `build_raw_file_index`, `build_raw_artifact_index` | raw image?먯꽌 諛섎났 寃??媛?ν븳 artifact DB ?앹꽦 | unreadable/parse cap? coverage gap?쇰줈 湲곕줉?쒕떎. |
| Raw direct parser | `query_evtx_file`, `query_registry_hive`, `query_prefetch_files`, `srum_by_process` | ?뱀젙 ?먮낯 ?뚯씪??遺꾩꽍媛媛 吏곸젒 議고쉶 | 0嫄댁씠硫??꾪꽣? parser ?곹깭瑜??뺤씤?쒕떎. |
| VSS layer | `list_vss_snapshots`, `vss_query_evtx_file`, `vss_query_registry_hive`, `vss_get_file_timestamps` | ??젣/?뺣━ ??怨쇨굅 ?곹깭 ?뺤씤 | snapshot? clean baseline???꾨땲??怨쇨굅 layer?? |
| Memory | `vol_load_memory`, `vol_pslist`, `vol_pstree`, `vol_cmdline`, `vol_netscan`, `vol_malfind` | 硫붾え由??ㅽ봽 湲곕컲 ?꾨줈?몄뒪/?ㅽ듃?뚰겕/二쇱엯 ?붿쟻 | disk evidence? timestamp瑜?蹂꾨룄 corroboration?쒕떎. |
| Static malware analysis | `inspect_pe_file`, `analyze_binary`, `ghidra_*` | ?댁떆, ?쒕챸, import, strings, decompile | capability 遺꾩꽍?댁? ?ㅽ뻾 利앷굅媛 ?꾨땲?? |

## Core Coverage Matrix

### 1. Source Readiness and Coverage

| 紐⑹쟻 | ?⑥닔 | 寃곌낵 |
| --- | --- | --- |
| 耳?댁뒪 濡쒕뱶 | `open_case` | active connector ?깅줉 |
| ?대?吏 留덉슫??| `mount_image` | raw image file operations ?쒖꽦??|
| ?꾩껜 ?곹깭 ?뺤씤 | `case_health` | loaded case, date range, high-value family, parser thinness ??|
| dependency ?뺤씤 | `dependency_health` | EVTX, registry, Ghidra, Volatility ??湲곕뒫 ?섏〈??|
| artifact family 媛?쒖꽦 ?뺤씤 | `coverage_explainer` | searched / available_not_loaded / structurally_unavailable |
| artifact family count | `get_artifact_types` | 寃??媛?ν븳 family? row count |
| 0嫄??먯씤 遺꾩꽍 | `explain_zero_results` | date/filter/source/coverage 臾몄젣? ?ъ떆???쒖븞 |

### 2. File System and NTFS

| Artifact | ?앹꽦/議고쉶 ?⑥닔 | Source | 二쇱슂 ?꾨뱶 | 利앷굅 媛뺣룄 |
| --- | --- | --- | --- | --- |
| `File System Entry` | `build_raw_file_index` | MFT ?곗꽑, fallback directory walk | path, name, size, MFT segment, MFT sequence number when exposed, deleted flag, created/modified/accessed/MFT changed | ?뚯씪 議댁옱? NTFS timestamp??媛뺥븳 filesystem evidence |
| NTFS timestamps | `get_file_timestamps`, `vss_get_file_timestamps` | current FS / VSS | `$STANDARD_INFORMATION`, `$FILE_NAME` | timestomp 寃?좎뿉 ?꾩닔 |
| Raw file listing | `list_files`, `vss_list_files` | mounted image / VSS | path, file metadata | 議댁옱 ?뺤씤. ?⑤룆 ?낆꽦 ?먮떒 湲덉? |
| Recycle Bin Deleted Items | `build_raw_artifact_index(include_recyclebin=True)` | `$Recycle.Bin\\<SID>\\$I*` + `$R*` companion paths | original path, original size, deletion time, user SID, recycled payload path | deletion/recovery context. Not proof of secure wiping, execution, or original-file absence |
| USN Journal Entries | `build_raw_artifact_index(include_usnjrnl=True)` | `$Extend\\$UsnJrnl:$J` + raw `File System Entry` MFT segment/sequence map when available | filename, parent/file reference, USN, reason flags, timestamp, MFT-backed parent/path candidates, path reconstruction confidence (`sequence_verified`, `sequence_mismatch_candidate`, or `candidate`) | strong filesystem change evidence. Sequence-verified candidates are stronger path corroboration, but still not full journal replay |
| USN Rename Transitions | `build_raw_artifact_index(include_usnjrnl=True)` | paired `$UsnJrnl:$J` RENAME_OLD_NAME / RENAME_NEW_NAME records | old/new name, old/new path candidate, FRN, USN delta, time delta, pairing method | strong rename-chain context for impact/cleanup triage. Pairing is a candidate chain, not proof of malicious rename or full rename history |
| NTFS LogFile Operation Candidates | `build_raw_artifact_index(include_logfile=True)` | `$LogFile` | RSTR/RCRD page signature, page offset, embedded path/name candidates, operation-name hints, parser scope | strong filesystem transaction-log context. Page-candidate extraction only; redo/undo replay and full path reconstruction are not claimed |
| Static file extraction | `extract_file`, `vss_extract_file` | mounted image / VSS | safe local export path | ?뺤쟻 遺꾩꽍 ?꾩슜, ?ㅽ뻾 湲덉? |

### 3. EVTX

Raw artifact index???ㅼ쓬 梨꾨꼸???곗꽑 ?섏쭛?쒕떎.

- `Security.evtx`
- `System.evtx`
- `Application.evtx`
- `Windows PowerShell.evtx`
- `Microsoft-Windows-PowerShell/Operational`
- `Microsoft-Windows-Sysmon/Operational`
- `Microsoft-Windows-WinRM/Operational`
- `Microsoft-Windows-DNS-Client/Operational`
- `Microsoft-Windows-WMI-Activity/Operational`
- `Microsoft-Windows-TaskScheduler/Operational`
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
- `Microsoft-Windows-TerminalServices-RDPClient/Operational`
- `Microsoft-Windows-Bits-Client/Operational`
- `Microsoft-Windows-Windows Defender/Operational`
- `Microsoft-Windows-SmbClient/Security`
- `Microsoft-Windows-SmbClient/Connectivity`
- `OAlerts.evtx`

Raw index artifact type:

| Artifact | ?앹꽦 ?⑥닔 | 二쇱슂 event 踰붿쐞 | ?ъ슜 紐⑹쟻 |
| --- | --- | --- | --- |
| `Windows Event Logs` | `build_raw_artifact_index(include_evtx=True)` | 4624/4625/4648/4672/4674, 4768/4769/4771/4776, 4688, 4697/7045/7036/7040, 4698/4702/106/129/140/141/200/201, 1102/104/4719/4616, 400/600/4103/4104, Sysmon 1/3/8/10/11/12/13/18/22, WinRM 91/168/6, WMI-Activity 5857-5861, 1116/1117/1119/5001/5007, 59/60, 4662/4663/5136/5140/5145/5156, 1024/31001/30803/30804, OAlerts 300 ??| logon, execution, persistence, cleanup, Defender, BITS, SMB/RDP/WinRM/WMI, Office alert 異붿쟻 |

EVTX rule pack:

The table below describes the parsed-case EVTX rule pack. It must not be read
as raw-sidecar parity. In raw-only mode, `hunt_evtx_rules` currently reports
unsupported evaluation instead of treating missing rule hits as clean results.
Raw-sidecar EVTX coverage is limited to the event/channel subset listed above;
Sysmon, WinRM, DNS-Client, WMI-Activity, classic Windows PowerShell, and
expanded Security/System EIDs are now indexed as raw EVTX rows when the
channels exist. Full raw-only rule evaluation is still separate from row
indexing: `hunt_evtx_rules` remains parsed-case oriented until a raw-rule
adapter is implemented.

| Rule group | ?⑥닔 | ???rule |
| --- | --- | --- |
| Authentication / account | `hunt_evtx_rules` | failed logon 4625, account creation 4720, group membership 4728/4732/4756, Kerberos weak encryption 4768/4769, NTLM 4776 |
| Privilege / discovery | `hunt_evtx_rules` | 4672/4674, 4798/4799, Sysmon discovery process/network/pipe |
| Persistence | `hunt_evtx_rules` | services 4697, tasks 106/140/141 and 129/200/201, Sysmon registry autostart 12/13 |
| PowerShell / execution | `hunt_evtx_rules` | 4104, engine 400/600, process creation patterns |
| Defense evasion | `hunt_evtx_rules`, `detect_anti_forensics` | Security 1102, System 104, audit policy 4719, firewall edits, VSS deletion, Defender/EventLog/Sysmon stop |
| Defender | `hunt_evtx_rules` | `fw-evtx-034` Defender 1116/1117 detection, `fw-evtx-035` Defender 5001/5007/1119 tamper |
| Network / lateral | `hunt_evtx_rules` | SMB 5140/5145, RDP 1149/21/25/4778/4779/1024, WinRM 91/168/6, BITS 59/60/3, WFP 5156 |

Direct EVTX 議고쉶??`query_evtx_file` ?먮뒗 `vss_query_evtx_file`濡??섑뻾?쒕떎.
?? Defender Operational? `/c:/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx`.

### 4. Registry-Derived Artifacts

Raw artifact index??registry parser??SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat, setupapi.dev.log瑜?議고빀?쒕떎.

| Artifact | Source | 二쇱슂 ?섎? |
| --- | --- | --- |
| `System Services` | raw sidecar??current control set 以묒떖. `service_persistence_gate`??SYSTEM `ControlSet*\\Services` 吏곸젒 寃利?| ?쒕퉬??persistence configuration. svchost service??`Parameters\\ServiceDll` ?뺤씤 ?꾩슂 |
| `BAM Execution Entries` | raw sidecar??current control set BAM/DAM 以묒떖 | user SID蹂??ㅽ뻾 愿李? Prefetch/SRUM怨?corroboration 沅뚯옣 |
| `USB Devices` | raw sidecar??current control set USBSTOR + NTUSER MountPoints2 + setupapi.dev.log 以묒떖 | USB ?μ튂 ?앸퀎, serial, user mount, first install local time |
| `AutoRun Items` | NTUSER Run/RunOnce | user-level startup persistence |
| `Scheduled Tasks` | `C:\\Windows\\System32\\Tasks` XML and SOFTWARE TaskCache via `build_raw_artifact_index(include_tasks=True)` / `include_registry=True` | task command, arguments, principal, run level, enabled/hidden state, trigger type, registration/start-boundary timestamps, GUID mapping, best-effort TaskCache action strings |
| `Office Trusted Documents` | NTUSER Office TrustRecords | macro/trusted document ?붿쟻 |
| `Office Recent Documents` | NTUSER Office MRU | Office 臾몄꽌 ?묎렐 context |
| `RDP Client Destinations` | NTUSER Terminal Server Client MRU | outbound RDP target |
| `IFEO Persistence` | SOFTWARE Image File Execution Options / SilentProcessExit | debugger, verifier DLL, monitor process persistence |
| `COM Hijack` | UsrClass.dat `Software\\Classes\\CLSID` | per-user COM server hijack ?꾨낫 |
| `ShellBags` | UsrClass.dat BagMRU via `build_raw_artifact_index(include_registry=True)` | folder navigation/view-state context. ShellItem 臾몄옄?댁? best-effort path hint濡?蹂댁〈 |

?섎룞 registry 議고쉶??`query_registry_hive`? `vss_query_registry_hive`瑜??ъ슜?쒕떎.
?쒕퉬??persistence??`service_persistence_gate`? `vss_service_persistence_gate`瑜??곗꽑 ?ъ슜?쒕떎.

### 5. Ingress and User-Action Artifacts

| Artifact | ?⑥닔 | Source | ?섎? |
| --- | --- | --- | --- |
| `Mark of the Web (Zone.Identifier)` | `build_raw_artifact_index(include_motw=True)` | user Downloads/Desktop/Documents ADS | ZoneId, ReferrerUrl, HostUrl. ?명꽣???좎엯 ?붿쟻 |
| Office trust/MRU | `build_raw_artifact_index(include_registry=True)` | NTUSER | macro enable, recent document context |
| OAlerts EVTX | raw EVTX index | `OAlerts.evtx` EID 300 | Office warning/prompt context |
| Browser/download artifacts | `build_raw_artifact_index(include_browser=True)`, parsed case search, `temporal_anchor_correlation` | Chrome/Edge/Naver Whale Chromium `History` DB visits/downloads, Firefox `places.sqlite` visits/download annotations, IE/Legacy Edge WebCacheV*.dat URL/download/cache candidates, and Chromium Cache/Code Cache file anchors | web ingress and payload-source anchor. Not execution proof; corroborate with MOTW, file timestamps, Prefetch/SRUM/BAM/EVTX |

### 6. Defender Coverage

Defender??EVTX? MPLog ??痢듭쑝濡?蹂몃떎.

| Layer | Artifact / ?⑥닔 | Source | ?댁꽍 |
| --- | --- | --- | --- |
| Defender Operational EVTX | `hunt_evtx_rules` `fw-evtx-034`, `fw-evtx-035`; `query_evtx_file` | `Microsoft-Windows-Windows Defender%4Operational.evtx` | 1116/1117? threat detection, 5001/5007/1119??protection disabled/tamper |
| Defender MPLog | `build_raw_artifact_index(include_mplog=True)` -> `Defender MPLog Activity` | `C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog-*.log` | RTP 愿李?湲곕컲 process/injection/detection telemetry |
| Defender service stop | `detect_anti_forensics` | process/EVTX text | `Stop-Service`, `net stop`, `sc stop` ??곸씠 Defender/Sysmon/EventLog?몄? ?뺤씤 |

`Defender MPLog Activity` record 醫낅쪟:

| Kind | ?섎? | 二쇱쓽 |
| --- | --- | --- |
| `threat_detection` | non-zero `Threat:` line. ?ㅼ젣 ?먯?濡?痍④툒 媛??| ?먮Ц detail怨?Defender EVTX瑜?cross-check |
| `process_execution` | `ProcessImageName`??Defender RTP媛 愿李?| command line ?놁쓬. ?ㅽ뻾 利앷굅濡?媛뺥븯吏留??⑤룆 ?ш굔 寃곕줎 湲덉? |
| `injection_source` | Defender媛 injection source濡?紐⑤땲?곕쭅???대?吏 | 愿怨??뺣낫?? ?낆꽦 ?뺤젙 ?꾨떂 |

MPLog timestamp??device-local wall-clock 臾몄옄?댁씠?? UTC timeline??洹몃?濡?諛곗튂?섏? ?딅뒗??
MPLog directory ?놁쓬, unreadable file, decode error, read cap, record cap? 紐⑤몢 coverage gap ?먮뒗 not_evaluable濡??댁꽍?쒕떎.

### 7. WMI, BITS, Network and Lateral Movement

| Artifact | ?⑥닔 | Source | ?섎? |
| --- | --- | --- | --- |
| `WMI Persistence` | `build_raw_artifact_index(include_wmi=True)` | CIM repository / `OBJECTS.DATA` | `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding`. 鍮꾪몴以 namespace? ActiveScript/CommandLine consumer??媛뺥븳 persistence lead |
| `BITS Transfer` | `build_raw_artifact_index(include_bits=True)` | `C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr.db` | URL怨?local path瑜?best-effort 異붿텧. download/C2/exfil lead |
| BITS EVTX | `hunt_evtx_rules` `fw-evtx-036` | BITS-Client Operational EID 59/60/3 | BITS job ?앹꽦/?꾨즺 context |
| RDP inbound/outbound | EVTX rule pack, registry MRU | TerminalServices channels, Security, NTUSER MRU | lateral movement ?먮뒗 pivot target |
| SMB outbound | raw EVTX index | SmbClient Security/Connectivity 31001/30803/30804 | remote share ?묒냽 ?쒕룄 |
| WFP network | `hunt_evtx_rules` `fw-evtx-032` | Security 5156 | allowed connection context. high-volume 媛??|

### 8. Execution Corroboration

| Artifact family | ?⑥닔 | 媛뺣룄 ?댁꽍 |
| --- | --- | --- |
| Prefetch | `query_prefetch_files`, parsed case search | strong execution evidence when enabled |
| SRUM | `build_raw_artifact_index(include_srum=True)` -> `SRUM Network Usage`, `SRUM Application Resource Usage`; `srum_by_process` | SRUDB.dat ESE schema-introspection with best-effort SruDbIdMapTable AppId resolution. Prefetch와 결합하면 stronger/confirmed 방향 |
| BAM | raw registry index | user SID + executable last run. moderate to strong context |
| PCA `pca.db` | `build_raw_artifact_index(include_pca=True)` -> `PCA Program Compatibility Activity` | Program Compatibility Assistant SQLite rows?먯꽌 path/timestamp ?꾨낫瑜?schema-introspection?쇰줈 異붿텧. execution-context lead?대ŉ ?⑤룆 ?뺤젙 湲덉? |
| Windows Timeline `ActivitiesCache.db` | `build_raw_artifact_index(include_activities=True)` -> `Windows Timeline Activity` | ConnectedDevicesPlatform SQLite rows?먯꽌 app/display/path/timestamp ?꾨낫瑜?schema-introspection?쇰줈 異붿텧. user-action corroboration?대ŉ ?⑤룆 ?뺤젙 湲덉? |
| LNK / JumpList | `build_raw_artifact_index(include_lnk=True)` -> `LNK Files`, `Jump Lists` | user Recent/Desktop/Downloads/Documents shortcut, Recent Automatic/CustomDestinations?먯꽌 embedded path ?꾨낫? LNK header time??best-effort 異붿텧 |
| EVTX 4688 / Sysmon 1 | raw EVTX index, `hunt_evtx_rules` | command line???덉쑝硫?strong execution context |
| UserAssist / AmCache / ShimCache | `build_raw_artifact_index(include_userassist=True, include_amcache=True, include_shimcache=True)` -> `UserAssist`, `AmCache File Entries`, `AmCache Program Entries`, `AmCache Driver Binaries`, `Shim Cache` | UserAssist/AmCache는 moderate context, ShimCache는 weak file-existence context. standalone verdict 금지 |
| WER / Crashpad | `search_wer_reports`, `temporal_anchor_correlation` | crash/process context. ?ㅽ뻾怨??멸낵??蹂꾨룄 ?뺤씤 |

Raw-only note: this execution row means raw sidecar covers Security 4688 and
Sysmon Event ID 1 when those channels exist and parse successfully. Missing
channels or disabled audit policy remain coverage gaps, not absence evidence.

## Review Sufficiency Matrix

???뱀뀡? 諛⑸쾿濡?寃?좎옄媛 "?꾩옱 artifact set???대뼡 怨듦꺽 ?④퀎源뚯? 異⑸텇?쒓?"瑜??먮떒?섍린 ?꾪븳 湲곗??쒕떎. `Primary coverage`???꾩옱 MCP/raw index媛 吏곸젒 ?ㅻ（??利앷굅?먯씠怨? `Corroboration`? 寃곕줎 ?꾩뿉 ?④퍡 ?뺤씤?댁빞 ?섎뒗 蹂닿컯 利앷굅??

| Attack lane | Primary coverage | Corroboration | Strong conclusion gate | Known gap / residual risk |
| --- | --- | --- | --- | --- |
| Ingress / Access | MOTW, Browser History/Downloads/Cache raw sidecar, Office Trusted Documents, Office MRU, OAlerts, raw RDP/SMB-client subset, raw WinRM EVTX, USB Devices | file timestamps, source URL, remote host pivots, parsed browser artifacts where available | external/source artifact plus user/action or file-placement evidence | raw browser coverage covers Chromium History/Cache anchors, Firefox places.sqlite visits/download annotations, and IE/Legacy Edge WebCache URL/download/cache candidates. Remaining raw gaps: cookies, email artifacts, and cloud app logs |
| Execution / Impact | Prefetch, SRUM, EVTX 4688/Sysmon 1, BAM, PCA `pca.db`, UserAssist, AmCache, Defender MPLog `process_execution`, WER | NTFS timestamps, process command line, parent/child process, PE metadata, ShimCache weak file-existence context | at least one strong execution artifact plus one independent corroborating family, or Prefetch+SRUM in the same window | AmCache/UserAssist/ShimCache raw parsing is best-effort and not full Eric Zimmerman parser parity; SRUM ESE parsing is schema-introspected and may not cover every Windows-build-specific table |
| Persistence | System Services, service registry gate, AutoRun Items, Scheduled Tasks XML/TaskCache, WMI Persistence, IFEO Persistence, COM Hijack, Scheduled Task EVTX | service/task payload timestamp/hash/signature, task XML, Prefetch/SRUM execution, VSS historical state | registry/config state plus payload presence or execution evidence; service persistence must inspect registry, not only EID 7045 | TaskCache binary field decoding is best-effort; task execution still needs EVTX/Prefetch/SRUM/BAM corroboration |
| Defense Evasion / Cleanup | EVTX 1102/104/4719, VSS deletion patterns, Defender tamper EVTX, Defender/EventLog/Sysmon stop, MPLog gaps, Recycle Bin Deleted Items, USN Journal Entries with MFT-backed path candidates, USN Rename Transitions, NTFS LogFile Operation Candidates | VSS historical EVTX, service state, Prefetch/process creation, `$LogFile` page candidates, coverage gaps | tamper event plus actor/process context or timing relative to incident window | absence of logs is a coverage gap; full `$LogFile` redo/undo replay, complete FRN history reconstruction, and deleted/missing journal recovery are not full raw-index coverage |
| Credential Access | LSASS/Sysmon access rules, sensitive file access, Security 4672/4674, Kerberos/NTLM rules, memory plugins | memory dump, process lineage, suspicious tool execution, file artifacts | credential-access event plus process/tool/user context | browser credential stores and DPAPI artifacts are not first-class raw-index artifacts |
| Lateral Movement / Pivot | RDP inbound/outbound EVTX, RDP Client Destinations, raw SMB client/share channels, raw WinRM EVTX, WFP 5156 | remote host correlation, account logons, explicit credential use, timeline window | remote access event plus account/host pair and supporting auth/process evidence | network PCAP/Zeek and remote endpoint evidence are optional external sources |
| C2 / Download / Exfil | BITS Transfer, BITS EVTX, WFP 5156, MOTW HostUrl, Sysmon DNS, DNS-Client EVTX, raw Browser Downloads/Cache and parsed browser artifacts | destination reputation, payload file timestamps, process owner, network logs | network or transfer record plus file/process/user context | qmgr.db blob parsing and browser cache semantics are best-effort; full proxy/DNS/PCAP coverage depends on imported logs |
| Malware / Defender | Defender EVTX, Defender MPLog Activity, PE static metadata, Ghidra strings/imports/APIs | file hash, NTFS timestamps, Prefetch/SRUM/EVTX execution, quarantine/detection detail | Defender `threat_detection` or EVTX detection plus file identity and execution/file-placement evidence | Defender quarantine store is not yet a first-class parser; MPLog time is device-local |

## Strong-Conclusion Gates

Reviewers should treat these as minimum bars for incident statements. A lower bar can still
produce a lead or hypothesis, but not a strong conclusion.

| Claim type | Minimum evidence before strong wording | Blocking condition |
| --- | --- | --- |
| "Process executed" | Prefetch, SRUM, EVTX 4688/Sysmon 1, BAM, or Defender MPLog `process_execution`; prefer two independent families | only file existence, ShimCache, PE timestamp, or temporal proximity |
| "File was dropped at time T" | NTFS `$SI` and `$FN` timestamps, file-system listing/MFT, plus ingress or process context | only Prefetch referenced path or browser cache proximity |
| "Persistence installed" | registry/task/service/WMI/IFEO/COM config state plus payload path verification; execution corroboration when claiming use | only EID 7045 or only service registry without payload review |
| "Defender detected malware" | Defender EVTX 1116/1117 or MPLog `threat_detection`, with source file/path/hash preserved | only Defender service stop/tamper or MPLog `process_execution` |
| "Defender was tampered with" | EVTX 5001/5007/1119 or explicit stop/tamper command, with actor/process/timing context | missing Defender logs alone |
| "Lateral movement occurred" | remote access/auth event plus account/host pair and supporting process or session evidence | one RDP/SMB artifact without account/session context |
| "Exfiltration occurred" | outbound transfer/network evidence plus file selection/access or destination context | BITS/WFP/network event alone |
| "Cleanup/anti-forensics occurred" | log clear/VSS deletion/logging tamper command plus timing and actor context | missing logs or empty VSS catalog alone |

If a gate is blocked, phrase the output as a lead, observation, or unrefuted hypothesis.
Record the missing source under coverage gaps.

## Known Blind Spots and Review Checklist

The current implementation intentionally records coverage gaps rather than pretending full
endpoint parity. Reviewers should check the following before approving the methodology as
"sufficient" for a given case.

| Area | Current status | Review action |
| --- | --- | --- |
| Browser history/cache/download DB | First-class raw sidecar coverage for Chrome/Edge/Naver Whale Chromium `History` visits/downloads, Firefox `places.sqlite` visits/download annotations, IE/Legacy Edge WebCacheV*.dat URL/download/cache candidates, plus Chromium Cache/Code Cache file anchors; not full browser-forensics parity | Use as web-ingress/user-activity context only. Corroborate download/execution with MOTW, file timestamps, Prefetch/SRUM/BAM/EVTX. Cookies, sessions, credential stores, and cache content reconstruction remain residual gaps |
| Email/client artifacts | Not a primary raw-index family | Do not conclude phishing ingress without external mail/client evidence |
| AmCache/UserAssist/ShimCache | First-class raw sidecar coverage via Amcache.hve, NTUSER UserAssist, and SYSTEM AppCompatCache best-effort parsing; not full Eric Zimmerman parser parity | Use as corroboration only. ShimCache remains weak and is not execution proof |
| ShellBags | First-class raw sidecar coverage via UsrClass BagMRU path hints; ShellItem binary decoding is best-effort | Use as folder navigation context only; do not infer file execution, copy, or exfiltration from ShellBags alone |
| PCA `pca.db` | First-class raw sidecar coverage via schema-introspected path/timestamp extraction | Treat as execution-context lead; corroborate with Prefetch/SRUM/BAM/EVTX before strong execution wording |
| SRUM SRUDB.dat | First-class raw sidecar coverage via ESE schema-introspection for Network Usage and Application Resource Usage | Use as execution/network corroboration; if SRUDB.dat is missing, unreadable, or the ESE parser is unavailable, treat that as coverage gap rather than no activity |
| Windows Timeline `ActivitiesCache.db` | First-class raw sidecar coverage via schema-introspected app/display/path/timestamp extraction | Treat as user-activity corroboration; verify execution/file access with Prefetch/SRUM/BAM/EVTX/LNK/JumpList/filesystem timestamps |
| LNK/JumpList | First-class raw sidecar coverage via shortcut/JumpList embedded path extraction; full LECmd/JLECmd semantic decode is not claimed | Use as user-action/path-access corroboration; verify execution/copy/exfil claims with independent artifacts |
| Scheduled Task XML / TaskCache | Task XML and TaskCache Tree/Tasks registry mapping are first-class raw sidecar coverage; TaskCache binary Actions are best-effort string extraction | Use raw `Scheduled Tasks` plus TaskScheduler EVTX; manually inspect TaskCache binary fields when exact trigger/action serialization matters |
| Defender quarantine | Defender EVTX and MPLog are covered; quarantine store is not first-class | Do not rely on quarantine absence; use Defender event/detail and file evidence |
| Sysmon Operational EVTX | Core raw sidecar channel added; requires Sysmon installation and successful EVTX parsing | Treat missing channel as coverage gap; raw row indexing is not the same as full raw `hunt_evtx_rules` parity |
| WinRM Operational EVTX | Core raw sidecar channel added for 91/168/6-style session evidence | Corroborate with auth/session/process evidence before lateral-movement conclusion |
| DNS-Client Operational EVTX | Core raw sidecar channel added; Sysmon DNS EID 22 also targeted | DNS/C2 conclusions still need process/destination/file context or imported network logs |
| WMI-Activity Operational EVTX | Core raw sidecar channel added for 5857-5861 corroboration | Pair with WMI repository persistence artifacts and process/timeline context |
| Classic `Windows PowerShell.evtx` | Core raw sidecar channel added alongside PowerShell Operational | Engine-start evidence is execution context, not full command visibility unless scriptblock/process data exists |
| USN Journal / `$LogFile` / `$UsnJrnl` | First-class raw sidecar coverage for `$UsnJrnl:$J` USN_RECORD_V2/V3 filename/reason/timestamp entries, MFT-backed USN path candidates with sequence-match confidence when available, USN rename transition candidates, and `$LogFile` RSTR/RCRD page candidates; not full NTFS journal replay | Use USN and `$LogFile` as strong filesystem-change / transaction-log context. Treat `sequence_verified` USN paths as stronger path corroboration than plain candidates, and treat `sequence_mismatch_candidate` or unpaired rename rows as unverified context. Avoid timestomp, redo/undo transaction, or anti-forensic conclusions without MFT/VSS/EVTX/timeline corroboration |
| Recycle Bin | First-class raw sidecar coverage for `$I` metadata and `$R` companion path anchors | Use as deletion/recovery context only. It does not prove secure wiping, original-file absence, execution, or malicious cleanup by itself |
| Full packet/network telemetry | Optional imported logs/PCAP only | Exfil/C2 conclusions require external network evidence when endpoint logs are thin |
| Cloud identity/SaaS logs | Outside endpoint MCP primary coverage | Require external cloud audit logs for cloud-account conclusions |
| Remote host corroboration | `pivot_across_cases` works only for loaded cases | Load peer hosts or state the limitation |
| Timestamp normalization | MPLog and setupapi use device-local strings | Do not mix into UTC chronology without offset handling |

## Validation and Regression Evidence

These tests and validation notes are useful references when the methodology is reviewed.
They do not prove every real-world case is covered; they show the parser and guardrail
contracts that are currently exercised.

| Capability | Evidence in repository |
| --- | --- |
| Raw EVTX / registry artifact indexing | `backend/tests/test_raw_artifact_indexer.py` |
| Raw index MCP search/timeline/coverage behavior | `backend/tests/test_raw_index_mcp.py`, `backend/tests/test_zero_results.py` |
| Defender MPLog parser and coverage gaps | `backend/tests/test_mplog_indexer.py` |
| WMI persistence parser and gap semantics | `backend/tests/test_wmi_indexer.py` |
| BITS qmgr.db URL/path extraction | `backend/tests/test_bits_indexer.py` |
| PCA pca.db path/timestamp extraction | `backend/tests/test_raw_artifact_indexer.py` |
| ShellBags BagMRU path-hint extraction | `backend/tests/test_raw_artifact_indexer.py` |
| Windows Timeline ActivitiesCache extraction | `backend/tests/test_raw_artifact_indexer.py` |
| LNK / JumpList embedded path extraction | `backend/tests/test_raw_artifact_indexer.py` |
| USN MFT-backed path candidate reconstruction | `backend/tests/test_raw_artifact_indexer.py` |
| USN rename transition candidate pairing | `backend/tests/test_raw_artifact_indexer.py` |
| NTFS `$LogFile` page-candidate extraction | `backend/tests/test_raw_artifact_indexer.py`, `backend/tests/test_raw_index_mcp.py` |
| Prefetch direct parser guardrails | `backend/tests/test_prefetch_semantic.py`, `backend/tests/test_raw_artifact_guardrails.py` |
| Service persistence registry gate | `backend/tests/test_service_persistence_gate.py`, `backend/tests/test_vss_tools.py` |
| Anti-forensics detection | `backend/tests/test_anti_forensics.py` |
| EVTX rule pack and Sigma integration | `backend/tests/test_sigma_loader.py`, `backend/tests/test_ingress_artifacts.py` |
| Evidence strength / rule coverage semantics | `backend/tests/test_rule_coverage.py`, `backend/tests/test_provenance.py` |
| Lane summary and report guardrails | `backend/tests/test_auto_triage_contract.py`, `backend/tests/test_report_generator_guardrails.py`, `backend/tests/test_triage_lane_state_endpoint.py` |
| Blind/fixture validation tracking | `docs/AUTONOMOUS_E01_VALIDATION_LOG.md`, `docs/DFIR_VALIDATION_PLAN.md`, `docs/ADVANCED_DFIR_BLIND_VALIDATION_PLAN.md` |

## Reviewer Decision Checklist

Use this checklist when deciding whether the artifact coverage is sufficient for a case.

- Evidence sources are named separately: parsed case, raw index, direct raw parser, VSS, memory, imported logs.
- `case_health`, `coverage_explainer`, or equivalent coverage output is attached before conclusions.
- Each major claim maps to at least one attack lane and passes the relevant strong-conclusion gate.
- Zero-result queries are paired with `explain_zero_results` or explicit coverage reasoning.
- Truncated/capped parser or rule outputs are not used as complete evidence.
- Defender MPLog timestamps are not treated as UTC.
- Registry state is not described as execution unless execution evidence is present.
- Static PE/Ghidra results are described as capability, not execution.
- Known blind spots are either out of scope, manually checked, or listed as residual risk.
- The final report separates confirmed facts, strong observations, moderate leads, weak context, and unverified hypotheses.

## Analysis Flow

### Flow A. Parsed AXIOM/KAPE Case

1. Load and validate source.
   - `open_case`
   - `case_health`
   - `get_artifact_types`
   - `coverage_explainer`
2. Run broad but non-verdict triage.
   - `initial_triage_pack`
   - `find_suspicious`
   - `hunt_evtx_rules`
   - `detect_anti_forensics`
3. Identify candidate windows and entities.
   - `build_timeline`
   - `slice_timeline`
   - `correlate`
   - `pivot_across_cases`
4. Corroborate by lane.
   - Ingress/access: MOTW, browser/download, RDP/SMB/WinRM, external media.
   - Execution/impact: Prefetch, SRUM, EVTX 4688/Sysmon, BAM, WER.
   - Persistence/cleanup: services, scheduled tasks, Run keys, WMI, IFEO, COM, log clearing, Defender tamper.
5. Refute before concluding.
   - `hypothesis_refutation_pack`
   - `investigation_gap_report`
   - Re-run truncated rules with narrower scope.
6. Report.
   - `extract_iocs`
   - `map_to_mitre`
   - `generate_report`

### Flow B. Raw E01/VMDK/Raw Image

1. Mount image and check minimum coverage.
   - `mount_image`
   - `raw_image_triage_gate`
   - `service_persistence_gate`
2. Build searchable indexes.
   - `build_raw_file_index`
   - `build_raw_artifact_index`
3. Search and timeline from indexed artifacts.
   - `search_artifacts`
   - `build_timeline`
   - `coverage_explainer`
4. Verify high-value raw sources directly.
   - `query_evtx_file`
   - `query_registry_hive`
   - `query_prefetch_files`
   - `srum_by_process`
   - `get_file_timestamps`
5. If cleanup/deletion is suspected, inspect VSS separately.
   - `list_vss_snapshots`
   - `vss_query_evtx_file`
   - `vss_query_registry_hive`
   - `vss_get_file_timestamps`
6. Extract files only for static analysis.
   - `extract_file`
   - `inspect_pe_file`
   - `analyze_binary`
   - `ghidra_imports`, `ghidra_strings`, `ghidra_suspicious_apis`, `ghidra_decompile`

### Flow C. Defender-Centric Investigation

1. Check whether Defender sources exist.
   - `coverage_explainer(artifact_types="Defender MPLog Activity,Windows Event Logs")`
   - `query_evtx_file` against Defender Operational EVTX
2. Run Defender EVTX rules.
   - `hunt_evtx_rules(rule_ids="fw-evtx-034,fw-evtx-035")`
3. Search MPLog aggregate records.
   - `search_artifacts(artifact_type="Defender MPLog Activity")`
   - Pivot on `Kind`, suspicious process path, or detection keyword.
4. Corroborate detections.
   - threat path -> `get_file_timestamps`, `search_by_hash`, `inspect_pe_file`
   - process_execution -> Prefetch/SRUM/BAM/EVTX 4688
   - tamper -> `detect_anti_forensics`, System/Security EVTX, service registry state
5. Treat missing Defender logs as a gap.
   - Defender disabled, cleaned logs, or unsupported image access can all produce no rows.

## Manual Query Patterns

Use these as reproducible analyst pivots.

```text
coverage_explainer(artifact_types="Defender MPLog Activity,Windows Event Logs,System Services,WMI Persistence,BITS Transfer")
search_artifacts(artifact_type="Defender MPLog Activity", keyword="threat_detection")
search_artifacts(artifact_type="Windows Event Logs", keyword="Event ID=4688")
search_artifacts(artifact_type="System Services", keyword="Service DLL")
search_artifacts(artifact_type="WMI Persistence")
search_artifacts(artifact_type="BITS Transfer")
query_evtx_file(evtx_path="/c:/Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx", event_ids="1116,1117,5001,5007,1119")
query_registry_hive(key_path="HKLM\\SYSTEM\\CurrentControlSet\\Services")
query_prefetch_files(keyword="powershell")
srum_by_process(process_name="powershell")
```

## Evidence Strength Guidance

| Strength | Examples |
| --- | --- |
| Confirmed | Prefetch + SRUM in same window, MFT/NTFS timestamp corroboration, decisive EVTX such as 4688/7045/1102 when source coverage is healthy |
| Strong | Prefetch last run, Sysmon process/network/registry events, PowerShell ScriptBlock, USN Journal file-change records, `$LogFile` page candidates, Defender MPLog process_execution with corroboration |
| Moderate | BAM, PCA `pca.db`, ShellBags, Windows Timeline, LNK/JumpList, AmCache, UserAssist, Scheduled Task state, Registry state, WMI repository state |
| Weak | ShimCache, PE link timestamp, simple file existence, temporal proximity alone |

Registry state proves configuration existed in the captured hive. It does not prove execution.
MPLog `injection_source` is monitoring context. It does not prove malicious injection.
BITS URL/path extraction is best-effort from opaque blobs. Treat it as a lead until corroborated.

## Coverage Gaps and Negative Evidence

Before writing "not found" or "no activity", record:

- Which source was searched: parsed case, raw index, direct raw parser, VSS, memory.
- Which artifact family was available and loaded.
- Whether the parser reported `coverage_gap`, `not_evaluable`, decode errors, or cap reached.
- Whether date range, keyword, and artifact type filters were stacked.
- Whether the relevant audit policy or Windows feature was enabled.

Use `explain_zero_results` after an empty query and `coverage_explainer` before interpreting absence.

## Current Limitations

These limitations are not acceptable as the final project state. They define
the current gap between the implementation and the E01-only analyst parity goal.

- MPLog has no dedicated MCP query function. It is indexed as `Defender MPLog Activity` and queried through `search_artifacts`.
- MPLog timestamps are device-local strings, not normalized UTC timestamps.
- BITS `qmgr.db` parsing extracts URL/path strings best-effort; it does not fully decode every job blob field.
- PCA `pca.db` parsing is schema-introspected and extracts path/timestamp candidates; it does not claim full semantic coverage for every PCA table on every Windows build.
- ShellBags parsing extracts BagMRU path hints with best-effort ShellItem string recovery; it does not claim full ShellItem binary semantic coverage.
- ActivitiesCache.db parsing is schema-introspected and extracts app/display/path/timestamp candidates; it does not claim full semantic coverage for every Timeline table on every Windows build.
- LNK/JumpList parsing extracts embedded path candidates and LNK header times best-effort; it does not claim full LECmd/JLECmd semantic coverage.
- Browser raw indexing parses Chrome/Edge/Naver Whale Chromium `History` visits/downloads, Firefox `places.sqlite` visits/download annotations, IE/Legacy Edge WebCacheV*.dat URL/download/cache candidates, and records Chromium Cache/Code Cache file anchors; it does not claim full browser-forensics parity for cookies, sessions, credential stores, or cache content reconstruction.
- Recycle Bin raw indexing parses `$I` metadata and links `$R` companion paths when present; it cannot prove secure deletion or anti-forensic cleanup by itself.
- USN Journal raw indexing parses `$UsnJrnl:$J` USN_RECORD_V2/V3 entries and reason flags, can attach MFT-backed parent/path candidates when raw `File System Entry` MFT segment rows exist, and can pair nearby `RENAME_OLD_NAME` / `RENAME_NEW_NAME` rows into `USN Rename Transitions`. When MFT sequence numbers are indexed, USN path candidates are labelled `sequence_verified` or `sequence_mismatch_candidate`; this still does not reconstruct complete historical FRN chains or replay all rename history.
- `$LogFile` raw indexing identifies RSTR/RCRD page candidates and embedded path/name/operation strings; it does not replay redo/undo transactions, reconstruct complete FRN paths, or prove actor intent by itself.
- EVTX raw index stores a high-value event subset, not every EVTX record. Rule-pack coverage must distinguish parsed-case rules from raw-index-evaluable rules.
- `hunt_evtx_rules` is currently parsed-case oriented. In raw-only mode, unsupported rule evaluation must remain `not_evaluable`, never silent clean.
- SRUM SRUDB.dat is raw-sidecar indexed for Network Usage and Application Resource Usage via schema-introspection; it does not claim full SrumECmd-equivalent semantic coverage for every Windows build-specific table.
- AmCache/UserAssist/ShimCache are raw-sidecar indexed as first-class families, but the parsers are best-effort: AmCache focuses on file/program/driver metadata roots, UserAssist decodes Count values, and ShimCache recovers UTF-16 path candidates from AppCompatCache blobs. They do not claim full Eric Zimmerman parser parity.
- Raw sidecar service/BAM/USBSTOR artifact indexing currently focuses on the current control set. Historical/control-set comparison remains a manual or gate-level verification item.
- Some parsed-case artifact families depend on upstream AXIOM/KAPE output and may be structurally unavailable in raw-only mode.
- Static Ghidra analysis describes binary capability only; it does not prove execution.
