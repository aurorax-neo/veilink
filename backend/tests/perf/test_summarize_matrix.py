import tempfile
import unittest
from pathlib import Path

from summarize_matrix import summarize


class MatrixSummaryTest(unittest.TestCase):
    def check(self, log, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "perf.log"
            path.write_text(log, encoding="utf-8")
            return summarize([path], **kwargs)

    def log(self):
        lines = []
        for network, mux in [("tcp", "off"), ("tcp", "smux"), ("tcp", "yamux"), ("tcp", "h2mux"), ("udp", "udp")]:
            fields = f"protocol=TLS network={network} mux={mux} pool=1 round=1 bytes=1024"
            lines += [f"PERF_EXPECT {fields}", f"PERF {fields} seconds=0.01 MiBps=0.098 p50_us=10 p95_us=20 switches=0/0"]
        return "\n".join(lines + ["PASS"])

    def test_complete(self):
        self.assertEqual(len(self.check(self.log(), expected_cases=1, expected_rounds=1)["measurements"]), 5)

    def test_missing_duplicate_failure_and_nonfinite(self):
        log = self.log()
        for broken in [log.replace("PERF protocol=TLS network=tcp mux=off", "LOST protocol=TLS network=tcp mux=off"),
                       log + "\n" + log.splitlines()[1], log.replace("PASS", "FAIL"),
                       log.replace("MiBps=0.098", "MiBps=nan"), log.replace("bytes=1024 seconds", "bytes=512 seconds")]:
            with self.subTest(log=broken), self.assertRaises(ValueError):
                self.check(broken)

    def test_missing_case_and_round(self):
        for kwargs in [{"expected_cases": 2}, {"expected_rounds": 2}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.check(self.log(), **kwargs)


if __name__ == "__main__":
    unittest.main()
