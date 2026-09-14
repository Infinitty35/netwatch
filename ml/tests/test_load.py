import json
import math
import tempfile
import unittest
from pathlib import Path

from netwatch_ml.load import SchemaMismatch, load, schema_hash

META = ["episode", "source", "os", "trigger", "ts", "issue", "rule", "rule_top_cause", "label", "label_source"]
FEATURES = [
    {"name": "dns.rtt_p50_ms", "group": "observation"},
    {"name": "check.dns.slow_resolver.upstream_slow.alt_resolver_is_fast", "group": "check"},
]


def write(tmp: Path, header=None, rows=None, features=FEATURES, hash_override=None):
    schema = {
        "schema_version": 1,
        "hash": hash_override or schema_hash(features),
        "meta_columns": META,
        "features": features,
    }
    (tmp / "schema.json").write_text(json.dumps(schema))
    header = header or META + [f["name"] for f in features]
    rows = rows or [
        ["ep1", "lab:dns_upstream_slow", "linux", "opened", "2026-09-14 10:00:00", "dns.slow_resolver#1",
         "dns.slow_resolver", "dns.slow_resolver/upstream_slow", "dns.slow_resolver/upstream_slow", "lab", "40", "1"],
        ["ep2", "live", "linux", "opened", "2026-09-14 11:00:00", "dns.slow_resolver#1",
         "dns.slow_resolver", "dns.slow_resolver/upstream_slow", "", "", "", "0"],
    ]
    (tmp / "features.csv").write_text("\n".join(",".join(r) for r in [header, *rows]) + "\n")
    return tmp / "features.csv", tmp / "schema.json"


class LoadTest(unittest.TestCase):
    def test_loads_rows_with_nan_for_missing(self):
        with tempfile.TemporaryDirectory() as d:
            ds = load(*write(Path(d)))
        self.assertEqual(len(ds), 2)
        self.assertEqual(ds.column("dns.rtt_p50_ms")[0], 40.0)
        self.assertTrue(math.isnan(ds.column("dns.rtt_p50_ms")[1]))
        self.assertEqual(ds.groups_of(), ["ep1", "ep2"])
        self.assertEqual(len(ds.labelled()), 1)
        self.assertEqual(ds.feature_names("check"), [FEATURES[1]["name"]])

    def test_refuses_a_header_that_does_not_match(self):
        with tempfile.TemporaryDirectory() as d:
            paths = write(Path(d), header=META + ["dns.rtt_p50_ms", "renamed"])
            with self.assertRaises(SchemaMismatch):
                load(*paths)

    def test_refuses_a_tampered_schema_or_an_unexpected_one(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SchemaMismatch):
                load(*write(Path(d), hash_override="0000000000000000"))
            paths = write(Path(d))
            with self.assertRaises(SchemaMismatch):
                load(*paths, expect_hash="ffffffffffffffff")


if __name__ == "__main__":
    unittest.main()
