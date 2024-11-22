# modules/response.py

from .cookies import cookiejar_from_dict, RequestsCookieJar
from .structures import CaseInsensitiveDict

from typing import Union, Generator
import json


class Response:
    """Object that contains the response to an HTTP request."""

    def __init__(self):
        # Reference of URL the response is coming from (especially useful with redirects)
        self.url = None

        # Integer Code of responded HTTP Status, e.g. 404 or 200.
        self.status_code = None

        # String of responded HTTP Body.
        self.text = None

        # Case-insensitive Dictionary of Response Headers.
        self.headers = CaseInsensitiveDict()

        # A CookieJar of Cookies the server sent back.
        self.cookies = cookiejar_from_dict({})
        
        self._content = False
        self._content_consumed = False  # Inicialização adicionada

    def __enter__(self):
        return self

    def __repr__(self):
        return f"<Response [{self.status_code}]>"

    def json(self, **kwargs):
        """Parse response body to JSON (dict/list)"""
        return json.loads(self.text, **kwargs)
    
    @property
    def content(self):
        """Content of the response, in bytes."""
        
        if self._content is False:
            if self._content_consumed:
                raise RuntimeError("The content for this response was already consumed")

            if self.status_code == 0:
                self._content = None
            else:
                self._content = b"".join(self.iter_content(10 * 1024)) or b""
        self._content_consumed = True
        return self._content

    def iter_content(self, chunk_size: int = 1, decode_unicode: bool = False) -> Generator[bytes, None, None]:
        """
        Iterates over the response data in chunks.

        :param chunk_size: The size of each chunk in bytes.
        :param decode_unicode: If True, decode the bytes to a string using utf-8.
        :return: Generator yielding chunks of the response content.
        """
        if not self._content:
            return  # Nothing to yield

        if decode_unicode:
            yield self._content.decode('utf-8')
        else:
            for i in range(0, len(self._content), chunk_size):
                yield self._content[i:i + chunk_size]

    def read(self, amt: int = -1) -> bytes:
        """
        Reads and returns `amt` bytes from the response content.

        :param amt: The number of bytes to read. Default is -1 (read all).
        :return: Bytes read from the response content.
        """
        if not self._content:
            return b""

        if amt < 0:
            return self._content

        return self._content[:amt]

def build_response(res: Union[dict, list], res_cookies: RequestsCookieJar) -> Response:
    """Builds a Response object """
    response = Response()
    # Add target / url
    response.url = res.get("target")
    # Add status code
    response.status_code = res.get("status")
    # Add headers
    response_headers = {}
    if res.get("headers") is not None:
        for header_key, header_value in res["headers"].items():
            if isinstance(header_value, list) and len(header_value) == 1:
                response_headers[header_key] = header_value[0]
            else:
                response_headers[header_key] = header_value
    response.headers = response_headers
    # Add cookies
    response.cookies = res_cookies
    # Add response body
    response.text = res.get("body", "")
    # Add response content (bytes)
    response._content = res.get("body", "").encode()
    return response
