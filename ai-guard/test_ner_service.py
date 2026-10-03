import unittest
from types import SimpleNamespace

import ner_service


class NERServiceTests(unittest.TestCase):
    def test_offsets_are_utf8_bytes_for_the_go_gateway(self):
        text = "Zażółć: Łucja Nowak"
        start = text.index("Łucja")
        fake = SimpleNamespace(detect=lambda t: [SimpleNamespace(start=start, end=start + 5, label="NAME", score=0.99, source="model")])
        original = ner_service._engine
        ner_service._engine = fake
        try:
            span = ner_service.detect(text)[0]
        finally:
            ner_service._engine = original
        self.assertEqual(text.encode()[span["start"]:span["end"]].decode(), "Łucja")

    def test_unavailable_model_is_reported_not_faked(self):
        original = ner_service._engine
        ner_service._engine = None
        try:
            with self.assertRaises(ner_service.Unavailable):
                ner_service.detect("Anna Kowalska")
        finally:
            ner_service._engine = original


if __name__ == "__main__":
    unittest.main()
