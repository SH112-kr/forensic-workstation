"""KAPE + Eric Zimmerman tool CSV column mappings to AXIOM-compatible schema.

Each tool mapping defines:
  - artifact_name: AXIOM artifact type name (for ArtifactQueries compatibility)
  - file_pattern: glob pattern to match CSV filenames
  - field_mapping: {csv_column: (data_type, axiom_field_name)}
      data_type: "String", "Date", "Int", "Float"
  - hash_columns: CSV columns containing hash values
  - location_column: CSV column for source path/location
"""

from __future__ import annotations

# Korean schtasks headers → English
SCHTASKS_KR_TO_EN = {
    "호스트 이름": "HostName", "작업 이름": "TaskName", "다음 실행 시간": "Next Run Time",
    "상태": "Status", "로그온 모드": "Logon Mode", "마지막 실행 시간": "Last Run Time",
    "마지막 결과": "Last Result", "만든 이": "Author", "실행할 작업": "Task To Run",
    "시작 위치": "Start In", "설명": "Comment", "예약된 작업 상태": "Scheduled Task State",
    "유휴 시간": "Idle Time", "전원 관리": "Power Management",
    "다음 사용자로 실행": "Run As User", "일정": "Schedule", "일정 유형": "Schedule Type",
    "시작 시간": "Start Time", "시작 날짜": "Start Date", "종료 날짜": "End Date",
}

# Header-based fallback detection signatures
HEADER_SIGNATURES = {
    "SBECmd": {"AbsolutePath", "ShellType", "MFTEntry"},
    "JLECmd": {"AppIdDescription", "TargetIDAbsolutePath"},
    "WxTCmd": {"ActivityType", "DisplayText", "ContentInfo", "Executable"},
}


def detect_tool_by_headers(headers: list[str]) -> str | None:
    header_set = set(headers)
    for tool, sig in HEADER_SIGNATURES.items():
        if sig.issubset(header_set):
            return tool
    return None


# EZ tool timestamp formats (tried in order)
TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f",       # 2026-03-03 10:14:44.1234567
    "%Y-%m-%d %H:%M:%S",           # 2026-03-03 10:14:44
    "%Y-%m-%dT%H:%M:%S.%f",        # 2026-03-03T10:14:44.1234567
    "%Y-%m-%dT%H:%M:%S.%fZ",       # 2026-03-03T10:14:44.1234567Z
    "%Y-%m-%dT%H:%M:%S",           # 2026-03-03T10:14:44
    "%Y-%m-%dT%H:%M:%SZ",          # 2026-03-03T10:14:44Z
    "%m/%d/%Y %H:%M:%S",           # 03/03/2026 10:14:44
    "%m/%d/%Y %I:%M:%S %p",        # 03/03/2026 10:14:44 AM
]

TOOL_MAPPINGS: dict[str, dict] = {

    # ── EvtxECmd: Windows Event Logs ──
    "EvtxECmd": {
        "artifact_name": "Windows Event Logs",
        "file_pattern": "*EvtxECmd*Output*.csv",
        "field_mapping": {
            "TimeCreated":    ("Date",   "Created Date/Time - UTC"),
            "EventId":        ("Int",    "Event ID"),
            "Provider":       ("String", "Provider Name"),
            "Channel":        ("String", "Channel"),
            "Computer":       ("String", "Computer"),
            "UserId":         ("String", "User ID"),
            "MapDescription": ("String", "Event Description Summary"),
            "UserName":       ("String", "Username"),
            "PayloadData1":   ("String", "Event Data"),
            "PayloadData2":   ("String", "Event Data 2"),
            "PayloadData3":   ("String", "Event Data 3"),
            "PayloadData4":   ("String", "Event Data 4"),
            "PayloadData5":   ("String", "Event Data 5"),
            "PayloadData6":   ("String", "Event Data 6"),
            "ExecutableInfo": ("String", "Executable"),
            "SourceFile":     ("String", "Source File"),
        },
        "hash_columns": [],
        "location_column": "SourceFile",
    },

    # ── PECmd: Prefetch ──
    "PECmd": {
        "artifact_name": "Prefetch Files - Windows 8/10/11",
        "file_pattern": "*PECmd*Output*.csv",
        "field_mapping": {
            "SourceFilename":       ("String", "Source File"),
            "ExecutableName":       ("String", "Application Name"),
            "SourceCreated":        ("Date",   "Source Created"),
            "SourceModified":       ("Date",   "Source Modified"),
            "LastRun":              ("Date",   "Last Run Time"),
            "PreviousRun0":         ("Date",   "Previous Run 0"),
            "PreviousRun1":         ("Date",   "Previous Run 1"),
            "PreviousRun2":         ("Date",   "Previous Run 2"),
            "PreviousRun3":         ("Date",   "Previous Run 3"),
            "PreviousRun4":         ("Date",   "Previous Run 4"),
            "PreviousRun5":         ("Date",   "Previous Run 5"),
            "PreviousRun6":         ("Date",   "Previous Run 6"),
            "RunCount":             ("Int",    "Run Count"),
            "Size":                 ("String", "Size"),
            "Hash":                 ("String", "Prefetch Hash"),
            "Version":              ("String", "Version"),
            "Volume0Name":          ("String", "Volume 0 Name"),
            "Volume0Serial":        ("String", "Volume 0 Serial"),
            "FilesLoaded":          ("String", "Files Loaded"),
            "Directories":          ("String", "Directories"),
        },
        "hash_columns": ["Hash"],
        "location_column": "ExecutableName",
    },

    # ── AmcacheParser: AmCache File Entries ──
    "AmcacheParser": {
        "artifact_name": "AmCache File Entries",
        "file_pattern": "*Amcache*Output*.csv",
        "field_mapping": {
            "ApplicationName":           ("String", "Name"),
            "FullPath":                  ("String", "Full Path"),
            "SHA1":                      ("String", "SHA-1"),
            "FileKeyLastWriteTimestamp": ("Date",   "File Key Last Write Time"),
            "LinkDate":                  ("Date",   "Link Date"),
            "ProductName":               ("String", "Product Name"),
            "CompanyName":               ("String", "Company Name"),
            "FileVersion":               ("String", "File Version"),
            "FileDescription":           ("String", "File Description"),
            "Size":                      ("String", "Size"),
            "Publisher":                  ("String", "Publisher"),
            "IsPeFile":                  ("String", "Is PE File"),
            "BinaryType":                ("String", "Binary Type"),
            "ProgramId":                 ("String", "Program ID"),
        },
        "hash_columns": ["SHA1"],
        "location_column": "FullPath",
    },

    # ── AppCompatCacheParser: Shim Cache ──
    "AppCompatCacheParser": {
        "artifact_name": "Shim Cache",
        "file_pattern": "*AppCompatCache*Output*.csv",
        "field_mapping": {
            "Path":                ("String", "Path"),
            "LastModifiedTimeUTC": ("Date",   "Last Modified Time"),
            "Executed":            ("String", "Executed"),
            "CacheEntryPosition":  ("Int",    "Cache Entry Position"),
            "ControlSet":          ("String", "Control Set"),
        },
        "hash_columns": [],
        "location_column": "Path",
    },

    # ── SrumECmd: SRUM (Network Usage + App Resource Usage) ──
    "SrumECmd_Network": {
        "artifact_name": "SRUM Network Usage",
        "file_pattern": "*SrumECmd*NetworkUsages*Output*.csv",
        "field_mapping": {
            "Timestamp":      ("Date",   "Timestamp"),
            "ExeInfo":        ("String", "Application Name"),
            "ExeInfoDescription": ("String", "Application Description"),
            "SidType":        ("String", "SID Type"),
            "Sid":            ("String", "SID"),
            "UserId":         ("String", "User ID"),
            "InterfaceLuid":  ("String", "Interface LUID"),
            "L2ProfileId":    ("String", "L2 Profile ID"),
            "BytesSent":      ("Int",    "Bytes Sent"),
            "BytesReceived":  ("Int",    "Bytes Received"),
        },
        "hash_columns": [],
        "location_column": "",
    },

    "SrumECmd_App": {
        "artifact_name": "SRUM Application Resource Usage",
        "file_pattern": "*SrumECmd*AppResourceUseInfo*Output*.csv",
        "field_mapping": {
            "Timestamp":             ("Date",   "Timestamp"),
            "ExeInfo":               ("String", "Application Name"),
            "ExeInfoDescription":    ("String", "Application Description"),
            "SidType":               ("String", "SID Type"),
            "Sid":                   ("String", "SID"),
            "ForegroundCycleTime":   ("Int",    "Foreground Cycle Time"),
            "BackgroundCycleTime":   ("Int",    "Background Cycle Time"),
            "FaceTime":              ("Int",    "Face Time"),
            "ForegroundBytesRead":   ("Int",    "Foreground Bytes Read"),
            "ForegroundBytesWritten":("Int",    "Foreground Bytes Written"),
            "BackgroundBytesRead":   ("Int",    "Background Bytes Read"),
            "BackgroundBytesWritten":("Int",    "Background Bytes Written"),
        },
        "hash_columns": [],
        "location_column": "",
    },

    # ── MFTECmd: MFT Entries ──
    "MFTECmd": {
        "artifact_name": "MFT Entries",
        "file_pattern": "*MFTECmd*Output*.csv",
        "field_mapping": {
            "EntryNumber":       ("Int",    "Entry Number"),
            "SequenceNumber":    ("Int",    "Sequence Number"),
            "ParentPath":        ("String", "Parent Path"),
            "FileName":          ("String", "File Name"),
            "Extension":         ("String", "Extension"),
            "FileSize":          ("Int",    "File Size"),
            "IsDirectory":       ("String", "Is Directory"),
            "Created0x10":       ("Date",   "$SI Created"),
            "LastModified0x10":  ("Date",   "$SI Modified"),
            "LastRecordChange0x10": ("Date", "$SI MFT Modified"),
            "LastAccess0x10":    ("Date",   "$SI Accessed"),
            "Created0x30":       ("Date",   "$FN Created"),
            "LastModified0x30":  ("Date",   "$FN Modified"),
            "LastRecordChange0x30": ("Date", "$FN MFT Modified"),
            "LastAccess0x30":    ("Date",   "$FN Accessed"),
            "InUse":             ("String", "In Use"),
            "ReferenceCount":    ("Int",    "Reference Count"),
            "LogfileSequenceNumber": ("Int", "LogFile Sequence Number"),
            "ZoneIdContents":    ("String", "Zone ID Contents"),
        },
        "hash_columns": [],
        "location_column": "ParentPath",
        "dedup_columns": ["EntryNumber", "SequenceNumber"],  # VSS dedup key
    },

    # ── LECmd: LNK Files ──
    "LECmd": {
        "artifact_name": "LNK Files",
        "file_pattern": "*LECmd*Output*.csv",
        "field_mapping": {
            "SourceFile":        ("String", "Source File"),
            "SourceCreated":     ("Date",   "Source Created"),
            "SourceModified":    ("Date",   "Source Modified"),
            "SourceAccessed":    ("Date",   "Source Accessed"),
            "TargetCreated":     ("Date",   "Target Created"),
            "TargetModified":    ("Date",   "Target Modified"),
            "TargetAccessed":    ("Date",   "Target Accessed"),
            "FileSize":          ("Int",    "File Size"),
            "RelativePath":      ("String", "Relative Path"),
            "WorkingDirectory":  ("String", "Working Directory"),
            "Arguments":         ("String", "Arguments"),
            "LocalPath":         ("String", "Linked Path"),
            "NetworkPath":       ("String", "Network Path"),
            "CommonPath":        ("String", "Common Path"),
            "VolumeSerialNumber":("String", "Volume Serial"),
            "DriveType":         ("String", "Drive Type"),
            "MachineMACAddress": ("String", "MAC Address"),
            "MachineID":         ("String", "Machine ID"),
            "TrackerCreatedOn":  ("Date",   "Tracker Created"),
        },
        "hash_columns": [],
        "location_column": "SourceFile",
    },

    # ── RECmd: Registry ──
    "RECmd": {
        "artifact_name": "Registry",
        "file_pattern": "*RECmd*Output*.csv",
        "field_mapping": {
            "HivePath":            ("String", "Hive Path"),
            "HiveType":            ("String", "Hive Type"),
            "Description":         ("String", "Description"),
            "Category":            ("String", "Category"),
            "KeyPath":             ("String", "Key Path"),
            "ValueName":           ("String", "Value Name"),
            "ValueType":           ("String", "Value Type"),
            "ValueData":           ("String", "Value Data"),
            "ValueData2":          ("String", "Value Data 2"),
            "ValueData3":          ("String", "Value Data 3"),
            "Comment":             ("String", "Comment"),
            "LastWriteTimestamp":   ("Date",   "Last Write Time"),
            "PluginDetailFile":    ("String", "Plugin Detail File"),
        },
        "hash_columns": [],
        "location_column": "HivePath",
    },

    # ── JLECmd: Jump Lists ──
    "JLECmd": {
        "artifact_name": "Jump Lists",
        "file_pattern": "*JLECmd*Output*.csv",
        "field_mapping": {
            "SourceFile":        ("String", "Source File"),
            "SourceCreated":     ("Date",   "Source Created"),
            "SourceModified":    ("Date",   "Source Modified"),
            "SourceAccessed":    ("Date",   "Source Accessed"),
            "TargetCreated":     ("Date",   "Target Created"),
            "TargetModified":    ("Date",   "Target Modified"),
            "TargetAccessed":    ("Date",   "Target Accessed"),
            "AppIdDescription":  ("String", "App ID Description"),
            "TargetIDAbsolutePath": ("String", "Linked Path"),
            "Arguments":         ("String", "Arguments"),
            "LocalPath":         ("String", "Local Path"),
            "MachineID":         ("String", "Machine ID"),
            "MachineMACAddress": ("String", "MAC Address"),
            "FileSize":          ("Int",    "File Size"),
        },
        "hash_columns": [],
        "location_column": "SourceFile",
    },

    # ── RBCmd: Recycle Bin ──
    "RBCmd": {
        "artifact_name": "Recycle Bin",
        "file_pattern": "*RBCmd*Output*.csv",
        "field_mapping": {
            "FileName":     ("String", "File Name"),
            "FileSize":     ("Int",    "File Size"),
            "DeletedOn":    ("Date",   "Deleted On"),
            "SourceFile":   ("String", "Source File"),
        },
        "hash_columns": [],
        "location_column": "FileName",
    },

    # ── WxTCmd: Windows Timeline (ActivitiesCache.db) ──
    "WxTCmd": {
        "artifact_name": "Windows Timeline",
        "file_pattern": "*WxTCmd*Output*.csv",
        "field_mapping": {
            "StartTime":       ("Date",   "Start Time"),
            "EndTime":         ("Date",   "End Time"),
            "LastModifiedTime":("Date",   "Last Modified Time"),
            "ExpirationTime":  ("Date",   "Expiration Time"),
            "CreatedInCloud":  ("Date",   "Created In Cloud"),
            "Executable":      ("String", "Executable"),
            "DisplayText":     ("String", "Display Text"),
            "ContentInfo":     ("String", "Content Info"),
            "ActivityType":    ("String", "Activity Type"),
            "Duration":        ("String", "Duration"),
        },
        "hash_columns": [],
        "location_column": "Executable",
    },

    # ── SBECmd: ShellBags ──
    "SBECmd": {
        "artifact_name": "Shell Bags",
        "file_pattern": "*SBECmd*Output*.csv",
        "field_mapping": {
            "AbsolutePath":    ("String", "Absolute Path"),
            "ShellType":       ("String", "Shell Type"),
            "Value":           ("String", "Value"),
            "CreatedOn":       ("Date",   "Created On"),
            "ModifiedOn":      ("Date",   "Modified On"),
            "AccessedOn":      ("Date",   "Accessed On"),
            "LastWriteTime":   ("Date",   "Last Write Time"),
            "MFTEntry":        ("Int",    "MFT Entry"),
            "MFTSequenceNumber":("Int",   "MFT Sequence Number"),
        },
        "hash_columns": [],
        "location_column": "AbsolutePath",
    },

    # ══════════════════════════════════════════
    # AmCache Program Entries (install history)
    # ══════════════════════════════════════════

    "AmcacheParser_Programs": {
        "artifact_name": "AmCache Program Entries",
        "file_pattern": "*Amcache*ProgramEntries*.csv",
        "field_mapping": {
            "Name":                     ("String", "Program Name"),
            "Version":                  ("String", "Version"),
            "Publisher":                ("String", "Publisher"),
            "Manufacturer":             ("String", "Manufacturer"),
            "InstallDate":              ("String", "Install Date"),
            "InstallDateMsi":           ("String", "Install Date MSI"),
            "InstallDateArpLastModified": ("Date", "Install Date ARP"),
            "InstallDateFromLinkFile":  ("Date",   "Install Date Link File"),
            "KeyLastWriteTimestamp":    ("Date",   "Key Last Write Time"),
            "OSVersionAtInstallTime":   ("String", "OS Version At Install"),
            "RootDirPath":              ("String", "Install Path"),
            "UninstallString":          ("String", "Uninstall String"),
            "Source":                   ("String", "Source"),
            "Type":                     ("String", "Type"),
            "ProgramId":                ("String", "Program ID"),
            "Language":                 ("String", "Language"),
            "MsiPackageCode":           ("String", "MSI Package Code"),
            "MsiProductCode":           ("String", "MSI Product Code"),
            "RegistryKeyPath":          ("String", "Registry Key Path"),
        },
        "hash_columns": [],
        "location_column": "RootDirPath",
    },

    # ══════════════════════════════════════════
    # Autoruns — persistence mechanisms
    # ══════════════════════════════════════════

    "Autoruns": {
        "artifact_name": "AutoRun Items",
        "file_pattern": "Autoruns.csv",
        "field_mapping": {
            "Time":            ("Date",   "Timestamp"),
            "Entry Location":  ("String", "Entry Location"),
            "Entry":           ("String", "Entry"),
            "Enabled":         ("String", "Enabled"),
            "Category":        ("String", "Category"),
            "Profile":         ("String", "Profile"),
            "Description":     ("String", "Description"),
            "Signer":          ("String", "Signer"),
            "Company":         ("String", "Company"),
            "Image Path":      ("String", "Image Path"),
            "Version":         ("String", "Version"),
            "Launch String":   ("String", "Launch String"),
            "SHA-1":           ("String", "SHA-1"),
            "SHA-256":         ("String", "SHA-256"),
            "MD5":             ("String", "MD5"),
        },
        "hash_columns": ["SHA-1", "SHA-256", "MD5"],
        "location_column": "Image Path",
    },

    # ══════════════════════════════════════════
    # RECmd Kroll — registry analysis
    # ══════════════════════════════════════════

    "RECmd_Kroll": {
        "artifact_name": "Registry",
        "file_pattern": "*RECmd*Kroll*.csv",
        "field_mapping": {
            "HivePath":            ("String", "Hive Path"),
            "HiveType":            ("String", "Hive Type"),
            "Description":         ("String", "Description"),
            "Category":            ("String", "Category"),
            "KeyPath":             ("String", "Key Path"),
            "ValueName":           ("String", "Value Name"),
            "ValueType":           ("String", "Value Type"),
            "ValueData":           ("String", "Value Data"),
            "ValueData2":          ("String", "Value Data 2"),
            "ValueData3":          ("String", "Value Data 3"),
            "Comment":             ("String", "Comment"),
            "LastWriteTimestamp":   ("Date",   "Last Write Time"),
            "PluginDetailFile":    ("String", "Plugin Detail File"),
        },
        "hash_columns": [],
        "location_column": "HivePath",
    },

    # ══════════════════════════════════════════
    # RECmd Kroll — System Services (filtered)
    # ══════════════════════════════════════════

    "RECmd_Kroll_Services": {
        "artifact_name": "System Services",
        "file_pattern": "*RECmd*Kroll*.csv",
        "field_mapping": {
            "ValueName":           ("String", "Service Name"),
            "ValueData":           ("String", "Service Location"),
            "ValueData2":          ("String", "Start Type"),
            "ValueData3":          ("String", "User Account"),
            "KeyPath":             ("String", "Registry Key Path"),
            "LastWriteTimestamp":   ("Date",   "Registry Modified"),
            "HivePath":            ("String", "Hive Path"),
            "Description":         ("String", "Description"),
        },
        "hash_columns": [],
        "location_column": "ValueData",
        "category_filter": "Services",
    },

    # ══════════════════════════════════════════
    # Scheduled Tasks
    # ══════════════════════════════════════════

    "ScheduledTasks": {
        "artifact_name": "Scheduled Tasks",
        "file_pattern": "Scheduled Tasks*.csv",
        "field_mapping": {
            "TaskName":              ("String", "Name"),
            "Task To Run":           ("String", "Command"),
            "Author":                ("String", "Author"),
            "Run As User":           ("String", "Run As"),
            "Last Run Time":         ("Date",   "Last Run Time"),
            "Next Run Time":         ("Date",   "Next Run Time"),
            "Status":                ("String", "Status"),
            "Schedule Type":         ("String", "Schedule Type"),
            "Start Time":            ("String", "Start Time"),
            "Start Date":            ("String", "Start Date"),
            "Comment":               ("String", "Comment"),
            "Scheduled Task State":  ("String", "State"),
            "HostName":              ("String", "Computer"),
        },
        "hash_columns": [],
        "location_column": "Task To Run",
    },

    # ══════════════════════════════════════════
    # AmCache Driver Binaries
    # ══════════════════════════════════════════

    "AmcacheParser_DriveBinaries": {
        "artifact_name": "AmCache Driver Binaries",
        "file_pattern": "*Amcache*DriverBinaries*.csv",
        "field_mapping": {
            "DriverName":               ("String", "Driver Name"),
            "DriverCompany":            ("String", "Company"),
            "DriverVersion":            ("String", "Version"),
            "Product":                  ("String", "Product"),
            "ProductVersion":           ("String", "Product Version"),
            "KeyLastWriteTimestamp":     ("Date",   "Key Last Write Time"),
            "Service":                  ("String", "Service"),
            "DriverCheckSum":           ("String", "Checksum"),
            "DriverSigned":             ("String", "Signed"),
            "DriverIsKernelMode":       ("String", "Is Kernel Mode"),
            "DriverInBox":              ("String", "In Box"),
            "ImageSize":                ("String", "Image Size"),
        },
        "hash_columns": ["DriverCheckSum"],
        "location_column": "DriverName",
    },

    # ══════════════════════════════════════════
    # SRUM Network Connections
    # ══════════════════════════════════════════

    "SrumECmd_NetworkConnections": {
        "artifact_name": "SRUM Network Connections",
        "file_pattern": "*SrumECmd*NetworkConnection*Output*.csv",
        "field_mapping": {
            "Timestamp":             ("Date",   "Timestamp"),
            "ExeInfo":               ("String", "Application Name"),
            "ExeInfoDescription":    ("String", "Application Description"),
            "ConnectedTime":         ("Int",    "Connected Time"),
            "ConnectStartTime":      ("Date",   "Connect Start Time"),
            "InterfaceLuid":         ("String", "Interface LUID"),
            "InterfaceType":         ("String", "Interface Type"),
            "ProfileName":           ("String", "Profile Name"),
            "SidType":               ("String", "SID Type"),
            "Sid":                   ("String", "SID"),
        },
        "hash_columns": [],
        "location_column": "",
    },

    # ══════════════════════════════════════════
    # SRUM Energy Usage
    # ══════════════════════════════════════════

    "SrumECmd_EnergyUsage": {
        "artifact_name": "SRUM Energy Usage",
        "file_pattern": "*SrumECmd*EnergyUsage*Output*.csv",
        "field_mapping": {
            "Timestamp":             ("Date",   "Timestamp"),
            "ExeInfo":               ("String", "Application Name"),
            "ExeInfoDescription":    ("String", "Application Description"),
            "ChargeLevel":           ("Int",    "Charge Level"),
            "DesignedCapacity":      ("Int",    "Designed Capacity"),
            "FullChargedCapacity":   ("Int",    "Full Charged Capacity"),
        },
        "hash_columns": [],
        "location_column": "",
    },

    # ══════════════════════════════════════════
    # Hayabusa — Sigma-based threat detection
    # ══════════════════════════════════════════

    # Hayabusa csv-timeline (standard profile)
    "Hayabusa": {
        "artifact_name": "Hayabusa Alerts",
        "file_pattern": "*hayabusa*events*.csv",
        "field_mapping": {
            "Timestamp":    ("Date",   "Timestamp"),
            "RuleTitle":    ("String", "Rule Title"),
            "Level":        ("String", "Level"),
            "Computer":     ("String", "Computer"),
            "Channel":      ("String", "Channel"),
            "EventID":      ("Int",    "Event ID"),
            "RecordID":     ("Int",    "Record ID"),
            "Details":      ("String", "Details"),
            "ExtraFieldInfo": ("String", "Extra Field Info"),
            "RuleFile":     ("String", "Rule File"),
            "RuleID":       ("String", "Rule ID"),
            "EvtxFile":     ("String", "EVTX File"),
            "MitreTactics": ("String", "MITRE Tactics"),
            "MitreTags":    ("String", "MITRE Tags"),
            "OtherTags":    ("String", "Other Tags"),
        },
        "hash_columns": [],
        "location_column": "EvtxFile",
    },

    # Hayabusa event statistics
    "Hayabusa_Stats": {
        "artifact_name": "Hayabusa Event Statistics",
        "file_pattern": "*hayabusa*statistics*.csv",
        "field_mapping": {
            "Channel":    ("String", "Channel"),
            "EventID":    ("Int",    "Event ID"),
            "Count":      ("Int",    "Count"),
            "Level":      ("String", "Level"),
            "RuleTitle":  ("String", "Rule Title"),
        },
        "hash_columns": [],
        "location_column": "",
    },

    # Hayabusa logon summary
    "Hayabusa_Logon": {
        "artifact_name": "Hayabusa Logon Summary",
        "file_pattern": "*hayabusa*logon*.csv",
        "field_mapping": {
            "TargetUser":       ("String", "Target User"),
            "TargetComputer":   ("String", "Target Computer"),
            "LogonType":        ("String", "Logon Type"),
            "SourceIP":         ("String", "Source IP"),
            "SourceComputer":   ("String", "Source Computer"),
            "FirstLogon":       ("Date",   "First Logon"),
            "LastLogon":        ("Date",   "Last Logon"),
            "SuccessfulLogons": ("Int",    "Successful Logons"),
            "FailedLogons":     ("Int",    "Failed Logons"),
        },
        "hash_columns": [],
        "location_column": "",
    },

    # ══════════════════════════════════════════
    # SQLECmd — Browser Artifacts
    # ══════════════════════════════════════════
    # Output pattern: <CSVPrefix>_<BaseFileName>.csv
    # e.g., GoogleChrome_HistoryVisits.csv, ChromiumBrowser_HistoryVisits.csv

    # ── Chrome History ──
    "SQLECmd_ChromeHistory": {
        "artifact_name": "Chrome Web Visits",
        "file_pattern": "*GoogleChrome*HistoryVisits*.csv",
        "field_mapping": {
            "VisitTime":                ("Date",   "Visit Time"),
            "LastVisitedTime":          ("Date",   "Last Visited Time"),
            "URL":                      ("String", "URL"),
            "URLTitle":                 ("String", "Title"),
            "VisitCount":               ("Int",    "Visit Count"),
            "TypedCount":               ("Int",    "Typed Count"),
            "Hidden":                   ("String", "Hidden"),
            "VisitID":                  ("Int",    "Visit ID"),
            "FromVisitID":              ("Int",    "From Visit ID"),
            "VisitDurationInSeconds":   ("Float",  "Visit Duration (s)"),
        },
        "hash_columns": [],
        "location_column": "URL",
    },

    # ── Chrome Downloads ──
    "SQLECmd_ChromeDownloads": {
        "artifact_name": "Chrome Downloads",
        "file_pattern": "*GoogleChrome*Downloads*.csv",
        "field_mapping": {
            "StartTime":          ("Date",   "Start Time"),
            "EndTime":            ("Date",   "End Time"),
            "Opened":             ("Date",   "Opened"),
            "LastAccessTime":     ("Date",   "Last Access Time"),
            "CurrentPath":        ("String", "Path"),
            "TargetPath":         ("String", "Target Path"),
            "DownloadURL":        ("String", "URL"),
            "TabURL":             ("String", "Tab URL"),
            "ReferrerURL":        ("String", "Referrer URL"),
            "OriginalMIMEType":   ("String", "MIME Type"),
            "ReceivedBytes":      ("Int",    "Received Bytes"),
            "TotalBytes":         ("Int",    "Total Bytes"),
            "State":              ("String", "State"),
            "DangerType":         ("String", "Danger Type"),
        },
        "hash_columns": [],
        "location_column": "TargetPath",
    },

    # ── Chrome Cookies ──
    "SQLECmd_ChromeCookies": {
        "artifact_name": "Chrome Cookies",
        "file_pattern": "*GoogleChrome*Cookies*.csv",
        "field_mapping": {
            "CreationUTC":    ("Date",   "Created Date/Time"),
            "ExpiresUTC":     ("Date",   "Expires"),
            "LastAccessUTC":  ("Date",   "Last Accessed"),
            "HostKey":        ("String", "Host"),
            "Name":           ("String", "Name"),
            "Path":           ("String", "Path"),
            "IsSecure":       ("String", "Secure"),
            "IsHttpOnly":     ("String", "HTTP Only"),
            "IsPersistent":   ("String", "Persistent"),
        },
        "hash_columns": [],
        "location_column": "HostKey",
    },

    # ── Chrome Keyword Searches ──
    "SQLECmd_ChromeKeywords": {
        "artifact_name": "Chrome Keyword Search Terms",
        "file_pattern": "*GoogleChrome*KeywordSearch*.csv",
        "field_mapping": {
            "DateCreated":    ("Date",   "Date Created"),
            "URL":            ("String", "URL"),
            "Title":          ("String", "Title"),
            "Term":           ("String", "Search Term"),
        },
        "hash_columns": [],
        "location_column": "URL",
    },

    # ── Edge/Chromium Browser History ──
    "SQLECmd_EdgeHistory": {
        "artifact_name": "Edge Web Visits",
        "file_pattern": "*ChromiumBrowser*HistoryVisits*.csv",
        "field_mapping": {
            "VisitTime (Local)":        ("Date",   "Visit Time"),
            "LastVisitedTime (Local)":  ("Date",   "Last Visited Time"),
            "URL":                      ("String", "URL"),
            "URLTitle":                 ("String", "Title"),
            "VisitCount":               ("Int",    "Visit Count"),
            "TypedCount":               ("Int",    "Typed Count"),
            "Hidden":                   ("String", "Hidden"),
            "VisitID":                  ("Int",    "Visit ID"),
            "FromVisitID":              ("Int",    "From Visit ID"),
            "VisitDurationInSeconds":   ("Float",  "Visit Duration (s)"),
        },
        "hash_columns": [],
        "location_column": "URL",
    },

    # ── Edge/Chromium Downloads ──
    "SQLECmd_EdgeDownloads": {
        "artifact_name": "Edge Downloads",
        "file_pattern": "*ChromiumBrowser*Downloads*.csv",
        "field_mapping": {
            "StartTime":          ("Date",   "Start Time"),
            "EndTime":            ("Date",   "End Time"),
            "Opened":             ("Date",   "Opened"),
            "LastAccessTime":     ("Date",   "Last Access Time"),
            "CurrentPath":        ("String", "Path"),
            "TargetPath":         ("String", "Target Path"),
            "DownloadURL":        ("String", "URL"),
            "TabURL":             ("String", "Tab URL"),
            "ReferrerURL":        ("String", "Referrer URL"),
            "OriginalMIMEType":   ("String", "MIME Type"),
            "ReceivedBytes":      ("Int",    "Received Bytes"),
            "TotalBytes":         ("Int",    "Total Bytes"),
            "State":              ("String", "State"),
            "DangerType":         ("String", "Danger Type"),
        },
        "hash_columns": [],
        "location_column": "TargetPath",
    },

    # ── Edge/Chromium Cookies ──
    "SQLECmd_EdgeCookies": {
        "artifact_name": "Edge Cookies",
        "file_pattern": "*ChromiumBrowser*Cookies*.csv",
        "field_mapping": {
            "CreationUTC":    ("Date",   "Created Date/Time"),
            "ExpiresUTC":     ("Date",   "Expires"),
            "LastAccessUTC":  ("Date",   "Last Accessed"),
            "HostKey":        ("String", "Host"),
            "Name":           ("String", "Name"),
            "Path":           ("String", "Path"),
            "IsSecure":       ("String", "Secure"),
            "IsHttpOnly":     ("String", "HTTP Only"),
            "IsPersistent":   ("String", "Persistent"),
        },
        "hash_columns": [],
        "location_column": "HostKey",
    },

    # ── Firefox History ──
    "SQLECmd_FirefoxHistory": {
        "artifact_name": "Firefox Web Visits",
        "file_pattern": "*Firefox*History*.csv",
        "field_mapping": {
            "VisitDate":      ("Date",   "Visit Time"),
            "URL":            ("String", "URL"),
            "Title":          ("String", "Title"),
            "VisitCount":     ("Int",    "Visit Count"),
            "Typed":          ("Int",    "Typed Count"),
            "Description":    ("String", "Description"),
            "PreviewImageURL":("String", "Preview Image URL"),
        },
        "hash_columns": [],
        "location_column": "URL",
    },

    # ── Firefox Downloads ──
    "SQLECmd_FirefoxDownloads": {
        "artifact_name": "Firefox Downloads",
        "file_pattern": "*Firefox*Downloads*.csv",
        "field_mapping": {
            "DateAdded":      ("Date",   "Date Added"),
            "URL":            ("String", "URL"),
            "Title":          ("String", "Title"),
            "Content":        ("String", "Content"),
            "PlaceVisitCount":("Int",    "Visit Count"),
        },
        "hash_columns": [],
        "location_column": "URL",
    },

    # ── Firefox Cookies ──
    "SQLECmd_FirefoxCookies": {
        "artifact_name": "Firefox Cookies",
        "file_pattern": "*Firefox*Cookies*.csv",
        "field_mapping": {
            "CreationTime":   ("Date",   "Created Date/Time"),
            "Expiry":         ("Date",   "Expires"),
            "LastAccessed":   ("Date",   "Last Accessed"),
            "Host":           ("String", "Host"),
            "Name":           ("String", "Name"),
            "Path":           ("String", "Path"),
            "IsSecure":       ("String", "Secure"),
            "IsHttpOnly":     ("String", "HTTP Only"),
        },
        "hash_columns": [],
        "location_column": "Host",
    },
}


def detect_tool(filename: str) -> str | list[str] | None:
    """Detect EZ tool name from CSV filename.

    KAPE output filenames follow the pattern:
      <timestamp>_<ToolName>_Output.csv
      <timestamp>_<ToolName>_<SubType>_Output.csv
    """
    fn_lower = filename.lower()

    # SRUM has multiple sub-types — check specific patterns first
    if "srumecmd" in fn_lower:
        if "networkusage" in fn_lower:
            return "SrumECmd_Network"
        if "appresourceuseinfo" in fn_lower:
            return "SrumECmd_App"
        if "networkconnection" in fn_lower:
            return "SrumECmd_NetworkConnections"
        if "energyusage" in fn_lower:
            return "SrumECmd_EnergyUsage"
        # Unknown SRUM sub-type (AppTimelineProvider, vfuprov, etc.) — skip
        return None

    # Hayabusa outputs
    if "hayabusa" in fn_lower:
        if "statistic" in fn_lower:
            return "Hayabusa_Stats"
        if "logon" in fn_lower:
            return "Hayabusa_Logon"
        if "event" in fn_lower or "timeline" in fn_lower:
            return "Hayabusa"
        return "Hayabusa"

    # SQLECmd browser outputs: <CSVPrefix>_<BaseFileName>.csv
    # Check specific browser patterns before generic tool names
    _sqle_patterns = [
        # Chrome (GoogleChrome prefix)
        ("googlechrome", "keywordsearch",  "SQLECmd_ChromeKeywords"),
        ("googlechrome", "downloads",      "SQLECmd_ChromeDownloads"),
        ("googlechrome", "cookies",        "SQLECmd_ChromeCookies"),
        ("googlechrome", "historyvisits",  "SQLECmd_ChromeHistory"),
        # Edge/Chromium (ChromiumBrowser prefix)
        ("chromiumbrowser", "downloads",     "SQLECmd_EdgeDownloads"),
        ("chromiumbrowser", "cookies",       "SQLECmd_EdgeCookies"),
        ("chromiumbrowser", "historyvisits", "SQLECmd_EdgeHistory"),
        # Firefox
        ("firefox", "downloads",  "SQLECmd_FirefoxDownloads"),
        ("firefox", "cookies",    "SQLECmd_FirefoxCookies"),
        ("firefox", "history",    "SQLECmd_FirefoxHistory"),
    ]
    for prefix, suffix, tool_id in _sqle_patterns:
        if prefix in fn_lower and suffix in fn_lower:
            return tool_id

    # JLECmd: AutomaticDestinations / CustomDestinations (no "JLECmd" in name)
    if "automaticdestinations" in fn_lower or "customdestinations" in fn_lower:
        return "JLECmd"

    # SBECmd: username_UsrClass.csv (no "SBECmd" in name)
    # Pattern: alphanumeric_UsrClass.csv — specific enough to avoid false matches
    if "_usrclass." in fn_lower and fn_lower.endswith(".csv"):
        return "SBECmd"

    # WxTCmd: timestamp_Activity.csv or Activity_PackageIDs.csv
    # Only match when prefixed with timestamp (14+ digits) to avoid false matches
    import re as _re
    if _re.match(r'^\d{14,}_activity\.csv$', fn_lower):
        return "WxTCmd"

    # Scheduled Tasks
    if fn_lower.startswith("scheduled tasks"):
        return "ScheduledTasks"

    # Amcache outputs: <timestamp>_Amcache_<SubType>.csv (no "Parser" in filename)
    if "amcache" in fn_lower:
        if "drivebinaries" in fn_lower:
            return "AmcacheParser_DriveBinaries"
        if "programentries" in fn_lower:
            return "AmcacheParser_Programs"
        if "associatedfileentries" in fn_lower or "unassociatedfileentries" in fn_lower:
            return "AmcacheParser"
        return None

    # AppCompatCache: <timestamp>_Windows10Creators_SYSTEM_AppCompatCache.csv
    if "appcompatcache" in fn_lower:
        return "AppCompatCacheParser"

    # Autoruns.csv (from autorunsc.exe)
    if fn_lower == "autoruns.csv":
        return "Autoruns"

    # RECmd Kroll batch output
    if "recmd" in fn_lower and "kroll" in fn_lower:
        return ["RECmd_Kroll", "RECmd_Kroll_Services"]

    # Match by tool name in filename (check longer names first to avoid false matches)
    tool_names = [
        "AppCompatCacheParser", "AmcacheParser",
        "EvtxECmd", "MFTECmd", "SBECmd", "JLECmd", "WxTCmd", "RBCmd",
        "PECmd", "LECmd", "RECmd",
    ]
    for tool in tool_names:
        if tool.lower() in fn_lower:
            return tool

    return None
