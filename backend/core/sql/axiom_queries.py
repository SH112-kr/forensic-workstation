"""Pre-built SQL queries for AXIOM .mfdb database."""

# ── Metadata & Lookups ──

CASE_INFO = """
SELECT case_number, case_name, created_on FROM case_info LIMIT 1
"""

SOURCE_EVIDENCE = """
SELECT source_evidence_number, evidence_location FROM source_evidence
"""

SCAN_INFO = """
SELECT scan_id, scan_start_date, scan_end_date, status FROM scan
WHERE status = 'Completed' ORDER BY scan_id
"""

FRAGMENT_DEFINITIONS = """
SELECT fragment_definition_id, artifact_version_id, name, data_type
FROM fragment_definition
"""

ARTIFACT_VERSIONS = """
SELECT artifact_version_id, artifact_id, artifact_name
FROM artifact_version
"""

ARTIFACTS = """
SELECT artifact_id, artifact_name, artifact_description FROM artifact
"""

TAGS = """
SELECT tag_id, tag_name, tag_description, tag_color FROM tag
"""

# ── Artifact Type Counts ──

ARTIFACT_TYPE_COUNTS = """
SELECT av.artifact_name, COUNT(*) AS hit_count
FROM scan_artifact_hit sah
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
GROUP BY av.artifact_name
ORDER BY hit_count DESC
"""

# ── Date Range ──

DATE_RANGE = """
SELECT MIN(unix_timestamp_ms) AS min_ts, MAX(unix_timestamp_ms) AS max_ts
FROM hit_fragment_date
WHERE unix_timestamp_ms > 946684800000
"""

# ── Hit ID Search ──

SEARCH_BY_ARTIFACT_TYPE = """
SELECT sah.hit_id
FROM scan_artifact_hit sah
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
WHERE av.artifact_name = ?
LIMIT ? OFFSET ?
"""

SEARCH_BY_KEYWORD = """
SELECT DISTINCT hfs.hit_id
FROM hit_fragment_string hfs
WHERE hfs.value LIKE ?
LIMIT ? OFFSET ?
"""

SEARCH_BY_KEYWORD_AND_TYPE = """
SELECT DISTINCT hfs.hit_id
FROM hit_fragment_string hfs
JOIN scan_artifact_hit sah ON hfs.hit_id = sah.hit_id
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
WHERE hfs.value LIKE ? AND av.artifact_name = ?
LIMIT ? OFFSET ?
"""

SEARCH_BY_ARTIFACT_TYPE_AND_DATE = """
SELECT DISTINCT sah.hit_id
FROM scan_artifact_hit sah
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
JOIN hit_fragment_date hfd ON sah.hit_id = hfd.hit_id
WHERE av.artifact_name = ?
  AND hfd.unix_timestamp_ms BETWEEN ? AND ?
LIMIT ? OFFSET ?
"""

SEARCH_BY_DATE_RANGE = """
SELECT DISTINCT hfd.hit_id
FROM hit_fragment_date hfd
WHERE hfd.unix_timestamp_ms BETWEEN ? AND ?
LIMIT ? OFFSET ?
"""

SEARCH_BY_KEYWORD_AND_DATE = """
SELECT DISTINCT hfs.hit_id
FROM hit_fragment_string hfs
JOIN hit_fragment_date hfd ON hfs.hit_id = hfd.hit_id
WHERE hfs.value LIKE ?
  AND hfd.unix_timestamp_ms BETWEEN ? AND ?
LIMIT ? OFFSET ?
"""

SEARCH_FULL = """
SELECT DISTINCT hfs.hit_id
FROM hit_fragment_string hfs
JOIN scan_artifact_hit sah ON hfs.hit_id = sah.hit_id
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
JOIN hit_fragment_date hfd ON hfs.hit_id = hfd.hit_id
WHERE hfs.value LIKE ?
  AND av.artifact_name = ?
  AND hfd.unix_timestamp_ms BETWEEN ? AND ?
LIMIT ? OFFSET ?
"""

# ── Hit Hydration (get fields for specific hit_ids) ──

HYDRATE_STRINGS = """
SELECT hit_id, fragment_definition_id, value
FROM hit_fragment_string
WHERE hit_id IN ({placeholders})
"""

HYDRATE_DATES = """
SELECT hit_id, fragment_definition_id, formatted_value, unix_timestamp_ms
FROM hit_fragment_date
WHERE hit_id IN ({placeholders})
"""

HYDRATE_INTS = """
SELECT hit_id, fragment_definition_id, value
FROM hit_fragment_int
WHERE hit_id IN ({placeholders})
"""

HYDRATE_FLOATS = """
SELECT hit_id, fragment_definition_id, value
FROM hit_fragment_float
WHERE hit_id IN ({placeholders})
"""

# ── Hit Artifact Type Mapping ──

HIT_ARTIFACT_TYPES = """
SELECT sah.hit_id, av.artifact_name
FROM scan_artifact_hit sah
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
WHERE sah.hit_id IN ({placeholders})
"""

# ── Location & Source ──

HIT_LOCATIONS = """
SELECT hl.hit_id, hl.location_value, s.source_friendly_value, sp.source_path
FROM hit_location hl
LEFT JOIN source s ON hl.source_id = s.source_id
LEFT JOIN source_path sp ON hl.source_id = sp.source_id
WHERE hl.hit_id IN ({placeholders})
  AND hl.sort_order = 0
"""

# ── Hash ──

HIT_HASHES = """
SELECT hit_id, hash FROM hit_hash
WHERE hit_id IN ({placeholders})
"""

SEARCH_BY_HASH = """
SELECT hit_id FROM hit_hash WHERE hash = ? LIMIT ? OFFSET ?
"""

ALL_HASHES = """
SELECT DISTINCT hh.hash, av.artifact_name
FROM hit_hash hh
JOIN scan_artifact_hit sah ON hh.hit_id = sah.hit_id
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
WHERE hh.hash != ''
LIMIT ?
"""

# ── Tags ──

TAGGED_HITS = """
SELECT hct.hit_id, t.tag_name, t.tag_color
FROM hit_case_tag hct
JOIN case_tag ct ON hct.case_tag_id = ct.case_tag_id
JOIN tag t ON ct.tag_id = t.tag_id
"""

TAGGED_HITS_BY_NAME = """
SELECT hct.hit_id, t.tag_name, t.tag_color
FROM hit_case_tag hct
JOIN case_tag ct ON hct.case_tag_id = ct.case_tag_id
JOIN tag t ON ct.tag_id = t.tag_id
WHERE t.tag_name LIKE ?
"""

# ── Timeline ──

TIMELINE = """
SELECT hfd.hit_id, hfd.unix_timestamp_ms, hfd.formatted_value,
       fd.name AS time_field
FROM hit_fragment_date hfd
JOIN fragment_definition fd ON hfd.fragment_definition_id = fd.fragment_definition_id
WHERE hfd.unix_timestamp_ms BETWEEN ? AND ?
ORDER BY hfd.unix_timestamp_ms ASC
LIMIT ?
"""

TIMELINE_ALL = """
SELECT hfd.hit_id, hfd.unix_timestamp_ms, hfd.formatted_value,
       fd.name AS time_field, av.artifact_name
FROM hit_fragment_date hfd
JOIN fragment_definition fd ON hfd.fragment_definition_id = fd.fragment_definition_id
JOIN scan_artifact_hit sah ON hfd.hit_id = sah.hit_id
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
ORDER BY hfd.unix_timestamp_ms ASC
LIMIT ?
"""

TIMELINE_WITH_KEYWORD = """
SELECT DISTINCT hfd.hit_id, hfd.unix_timestamp_ms, hfd.formatted_value,
       fd.name AS time_field
FROM hit_fragment_date hfd
JOIN fragment_definition fd ON hfd.fragment_definition_id = fd.fragment_definition_id
JOIN hit_fragment_string hfs ON hfd.hit_id = hfs.hit_id
WHERE hfd.unix_timestamp_ms BETWEEN ? AND ?
  AND ({keyword_conditions})
ORDER BY hfd.unix_timestamp_ms ASC
LIMIT ?
"""

TIMELINE_WITH_TYPE = """
SELECT hfd.hit_id, hfd.unix_timestamp_ms, hfd.formatted_value,
       fd.name AS time_field, av.artifact_name
FROM hit_fragment_date hfd
JOIN fragment_definition fd ON hfd.fragment_definition_id = fd.fragment_definition_id
JOIN scan_artifact_hit sah ON hfd.hit_id = sah.hit_id
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
WHERE hfd.unix_timestamp_ms BETWEEN ? AND ?
  AND av.artifact_name IN ({placeholders})
ORDER BY hfd.unix_timestamp_ms ASC
LIMIT ?
"""

# ── Suspicious Pattern Detection (SQL-based) ──

SEARCH_STRING_PATTERN = """
SELECT DISTINCT hfs.hit_id
FROM hit_fragment_string hfs
WHERE hfs.value LIKE ?
LIMIT ?
"""

SEARCH_STRING_PATTERNS_MULTI = """
SELECT DISTINCT hfs.hit_id
FROM hit_fragment_string hfs
WHERE ({conditions})
LIMIT ?
"""

# ── IOC Extraction ──

STRINGS_WITH_PATTERN = """
SELECT hfs.hit_id, hfs.value
FROM hit_fragment_string hfs
WHERE hfs.value LIKE ?
LIMIT ?
"""

# ── Source Path Search ──

SEARCH_BY_SOURCE_PATH = """
SELECT DISTINCT hl.hit_id
FROM hit_location hl
WHERE hl.location_value LIKE ?
LIMIT ? OFFSET ?
"""

# ── SRUM Aggregation (full-dataset totals, not limited by LIMIT) ──

SRUM_NETWORK_AGGREGATE = """
SELECT COUNT(*) AS total_records,
       COALESCE(SUM(sent.value), 0) AS total_bytes_sent,
       COALESCE(SUM(recv.value), 0) AS total_bytes_received
FROM (
    SELECT DISTINCT hfs.hit_id
    FROM hit_fragment_string hfs
    JOIN scan_artifact_hit sah ON hfs.hit_id = sah.hit_id
    JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
    WHERE av.artifact_name = 'SRUM Network Usage'
      AND hfs.value LIKE ?
) matched
LEFT JOIN hit_fragment_int sent
       ON matched.hit_id = sent.hit_id AND sent.fragment_definition_id = ?
LEFT JOIN hit_fragment_int recv
       ON matched.hit_id = recv.hit_id AND recv.fragment_definition_id = ?
"""

SRUM_APP_COUNT = """
SELECT COUNT(DISTINCT hfs_app.hit_id) AS total_records
FROM hit_fragment_string hfs_app
JOIN scan_artifact_hit sah ON hfs_app.hit_id = sah.hit_id
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
WHERE av.artifact_name = 'SRUM Application Resource Usage'
  AND hfs_app.value LIKE ?
"""

# ── Count Queries ──

COUNT_TOTAL_HITS = """
SELECT COUNT(*) FROM scan_artifact_hit
"""

COUNT_BY_KEYWORD = """
SELECT COUNT(DISTINCT hit_id) FROM hit_fragment_string WHERE value LIKE ?
"""

COUNT_BY_TYPE_AND_KEYWORD = """
SELECT COUNT(DISTINCT hfs.hit_id)
FROM hit_fragment_string hfs
JOIN scan_artifact_hit sah ON hfs.hit_id = sah.hit_id
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
WHERE hfs.value LIKE ? AND av.artifact_name = ?
"""

COUNT_BY_ARTIFACT_TYPE = """
SELECT COUNT(*) FROM scan_artifact_hit sah
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
WHERE av.artifact_name = ?
"""

COUNT_BY_DATE_RANGE = """
SELECT COUNT(DISTINCT hfd.hit_id)
FROM hit_fragment_date hfd
WHERE hfd.unix_timestamp_ms BETWEEN ? AND ?
"""

COUNT_BY_KEYWORD_AND_DATE = """
SELECT COUNT(DISTINCT hfs.hit_id)
FROM hit_fragment_string hfs
JOIN hit_fragment_date hfd ON hfs.hit_id = hfd.hit_id
WHERE hfs.value LIKE ?
  AND hfd.unix_timestamp_ms BETWEEN ? AND ?
"""

COUNT_BY_ARTIFACT_TYPE_AND_DATE = """
SELECT COUNT(DISTINCT sah.hit_id)
FROM scan_artifact_hit sah
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
JOIN hit_fragment_date hfd ON sah.hit_id = hfd.hit_id
WHERE av.artifact_name = ?
  AND hfd.unix_timestamp_ms BETWEEN ? AND ?
"""

COUNT_FULL = """
SELECT COUNT(DISTINCT hfs.hit_id)
FROM hit_fragment_string hfs
JOIN scan_artifact_hit sah ON hfs.hit_id = sah.hit_id
JOIN artifact_version av ON sah.artifact_version_id = av.artifact_version_id
JOIN hit_fragment_date hfd ON hfs.hit_id = hfd.hit_id
WHERE hfs.value LIKE ?
  AND av.artifact_name = ?
  AND hfd.unix_timestamp_ms BETWEEN ? AND ?
"""

COUNT_BY_HASH = """
SELECT COUNT(*) FROM hit_hash WHERE hash = ?
"""

COUNT_BY_SOURCE_PATH = """
SELECT COUNT(DISTINCT hit_id) FROM hit_location WHERE location_value LIKE ?
"""
