import unittest

from smda.common.SmdaReport import SmdaReport


class TestSmdaReportXmetadataDefault(unittest.TestCase):
    def test_fromDict_defaults_xmetadata_to_empty_dict(self):
        # 31: fromDict left xmetadata as None (asymmetric with __init__'s {}), so a reader
        # doing report.xmetadata["symbols"] raised TypeError. It must default to {}.
        report = SmdaReport()
        report_dict = report.toDict()
        self.assertIn("xmetadata", report_dict)
        del report_dict["xmetadata"]
        restored = SmdaReport.fromDict(report_dict)
        self.assertEqual(restored.xmetadata, {})


if __name__ == "__main__":
    unittest.main()
