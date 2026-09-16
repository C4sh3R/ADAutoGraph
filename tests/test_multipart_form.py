import io
import unittest
from email.message import Message
from types import SimpleNamespace

import server


def multipart_request(content_type, body):
    headers = Message()
    headers["Content-Type"] = content_type
    headers["Content-Length"] = str(len(body))
    return SimpleNamespace(headers=headers, rfile=io.BytesIO(body))


class MultipartFormTests(unittest.TestCase):
    def test_parses_uploaded_file(self):
        boundary = "test-boundary"
        body = (
            b"--test-boundary\r\n"
            b'Content-Disposition: form-data; name="zip"; filename="graph.zip"\r\n'
            b"Content-Type: application/zip\r\n\r\n"
            b"zip-content\r\n"
            b"--test-boundary--\r\n"
        )

        form = server.multipart_form(
            multipart_request(f"multipart/form-data; boundary={boundary}", body)
        )
        upload = form.get("zip")

        self.assertIsNotNone(upload)
        self.assertEqual(upload.filename, "graph.zip")
        self.assertEqual(upload.file.read(), b"zip-content")

    def test_rejects_non_multipart_content_type(self):
        with self.assertRaises(ValueError):
            server.multipart_form(
                multipart_request("application/json", b"{}")
            )


if __name__ == "__main__":
    unittest.main()
