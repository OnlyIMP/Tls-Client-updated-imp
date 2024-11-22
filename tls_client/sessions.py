from .cffi import (
    request, freeMemory, destroySession, destroyAll,
    getCookiesFromSession, addCookiesToSession
)
from .cookies import cookiejar_from_dict, merge_cookies, extract_cookies_to_jar
from .exceptions import TLSClientException
from .response import build_response, Response
from .settings import ClientIdentifiers
from .structures import CaseInsensitiveDict
from .__version__ import __version__

from typing import Any, Dict, List, Optional, Union
from json import dumps, loads
import urllib.parse
import base64
import ctypes
import uuid


class Session:
    
    def __init__(
        self,
        client_identifier: ClientIdentifiers = "chrome_131",
        ja3_string: Optional[str] = None,
        h2_settings: Optional[Dict[str, int]] = None,
        h2_settings_order: Optional[List[str]] = None,
        supported_signature_algorithms: Optional[List[str]] = None,
        supported_delegated_credentials_algorithms: Optional[List[str]] = None,
        supported_versions: Optional[List[str]] = None,
        key_share_curves: Optional[List[str]] = None,
        cert_compression_algo: Optional[str] = None,
        additional_decode: Optional[str] = None,
        pseudo_header_order: Optional[List[str]] = None,
        connection_flow: Optional[int] = None,
        priority_frames: Optional[list] = None,
        header_order: Optional[List[str]] = None,
        header_priority: Optional[List[str]] = None,
        random_tls_extension_order: Optional[bool] = False,
        force_http1: Optional[bool] = False,
        catch_panics: Optional[bool] = False,
        debug: Optional[bool] = False,
        certificate_pinning: Optional[Dict[str, List[str]]] = None,
        is_rotating_proxy: Optional[bool] = False,  # Novo parâmetro adicionado
    ) -> None:
        self._session_id = str(uuid.uuid4())
        self.is_rotating_proxy = is_rotating_proxy  # Salva o novo parâmetro na instância
        # --- Standard Settings ------------------------------------------------------------------------------------

        # Case-insensitive dictionary of headers, send on each request
        self.headers = CaseInsensitiveDict(
            {
                "User-Agent": f"tls-client/{__version__}",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": "*/*",
                "Connection": "keep-alive",
            }
        )

        # Proxies
        self.proxies = {}

        # Query parameters
        self.params = {}

        # CookieJar
        self.cookies = cookiejar_from_dict({})

        # Timeout
        self.timeout_seconds = 30

        # Certificate pinning
        self.certificate_pinning = certificate_pinning

        # --- Advanced Settings ------------------------------------------------------------------------------------

        self.client_identifier = client_identifier
        self.ja3_string = ja3_string
        self.h2_settings = h2_settings
        self.h2_settings_order = h2_settings_order
        self.supported_signature_algorithms = supported_signature_algorithms
        self.supported_delegated_credentials_algorithms = supported_delegated_credentials_algorithms
        self.supported_versions = supported_versions
        self.key_share_curves = key_share_curves
        self.cert_compression_algo = cert_compression_algo
        self.additional_decode = additional_decode
        self.pseudo_header_order = pseudo_header_order
        self.connection_flow = connection_flow
        self.priority_frames = priority_frames
        self.header_order = header_order
        self.header_priority = header_priority
        self.random_tls_extension_order = random_tls_extension_order
        self.force_http1 = force_http1
        self.catch_panics = catch_panics
        self.debug = debug
    

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self) -> str:
        destroy_session_payload = {
            "sessionId": self._session_id
        }

        try:
            destroy_session_response = destroySession(dumps(destroy_session_payload).encode('utf-8'))
            # Dereference the pointer to a byte array
            destroy_session_response_bytes = ctypes.string_at(destroy_session_response)
            # Convert byte array to string (tls client returns json)
            destroy_session_response_string = destroy_session_response_bytes.decode('utf-8')
            # Convert response string to json
            destroy_session_response_object = loads(destroy_session_response_string)
        finally:
            # Assegura que freeMemory seja chamado se 'id' estiver presente
            if 'id' in destroy_session_response_object:
                try:
                    freeMemory(destroy_session_response_object['id'].encode('utf-8'))
                except Exception as e:
                    # Opcional: Log ou tratamento adicional do erro de liberação de memória
                    print(f"Erro ao liberar memória para response_id {destroy_session_response_object['id']}: {e}")

        return destroy_session_response_string

    def execute_request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,  # Optional[dict[str, str]]
        data: Optional[Union[str, dict]] = None,
        headers: Optional[dict] = None,  # Optional[dict[str, str]]
        cookies: Optional[dict] = None,  # Optional[dict[str, str]]
        json: Optional[dict] = None,      # Parâmetro corrigido para 'json'
        allow_redirects: Optional[bool] = False,
        insecure_skip_verify: Optional[bool] = False,
        timeout_seconds: Optional[int] = None,
        proxy: Optional[dict] = None       # Optional[dict[str, str]]
    ) -> Response:
        response_object = None
        response_id = None
        try:
            # --- URL ------------------------------------------------------------------------------------------------------
            # Prepare URL - add params to url
            if params is not None:
                query_string = urllib.parse.urlencode(params, doseq=True)
                url = f"{url}?{query_string}"

            # --- Request Body ---------------------------------------------------------------------------------------------
            # Prepare request body - build request body
            # Data has priority. JSON é usado apenas se data for None.
            if data is None and json is not None:
                if isinstance(json, (dict, list)):
                    json = dumps(json)
                request_body = json
                content_type = "application/json"
            elif data is not None and not isinstance(data, (str, bytes)):
                request_body = urllib.parse.urlencode(data, doseq=True)
                content_type = "application/x-www-form-urlencoded"
            else:
                request_body = data
                content_type = None
            # set content type if it isn't set
            if content_type is not None and "content-type" not in self.headers:
                self.headers["Content-Type"] = content_type

            # --- Headers --------------------------------------------------------------------------------------------------
            if self.headers is None:
                headers_final = CaseInsensitiveDict(headers)
            elif headers is None:
                headers_final = self.headers
            else:
                merged_headers = CaseInsensitiveDict(self.headers)
                merged_headers.update(headers)

                # Remove items where the key or value is set to None.
                none_keys = [k for (k, v) in merged_headers.items() if v is None or k is None]
                for key in none_keys:
                    del merged_headers[key]

                headers_final = merged_headers

            # --- Cookies --------------------------------------------------------------------------------------------------
            cookies = cookies or {}
            # Merge with session cookies
            cookies = merge_cookies(self.cookies, cookies)
            # Turn cookie jar into list of dicts
            request_cookies = [
                {'domain': c.domain, 'expires': c.expires, 'name': c.name, 'path': c.path, 'value': c.value.replace('"', "")}
                for c in cookies
            ]

            # --- Proxy ----------------------------------------------------------------------------------------------------
            proxy = proxy or self.proxies
            
            if isinstance(proxy, dict) and "http" in proxy:
                proxy = proxy["http"]
            elif isinstance(proxy, str):
                proxy = proxy
            else:
                proxy = ""

            # --- Timeout --------------------------------------------------------------------------------------------------
            timeout_seconds = timeout_seconds or self.timeout_seconds

            # --- Certificate pinning --------------------------------------------------------------------------------------
            certificate_pinning = self.certificate_pinning

            # --- Request --------------------------------------------------------------------------------------------------
            is_byte_request = isinstance(request_body, (bytes, bytearray))
            request_payload = {
                "sessionId": self._session_id,
                "followRedirects": allow_redirects,
                "forceHttp1": self.force_http1,
                "withDebug": self.debug,
                "catchPanics": self.catch_panics,
                "headers": dict(headers_final),
                "headerOrder": self.header_order,
                "insecureSkipVerify": insecure_skip_verify,
                "isByteRequest": is_byte_request,
                "additionalDecode": self.additional_decode,
                "proxyUrl": proxy,
                "isRotatingProxy": self.is_rotating_proxy,  # Inclui o novo parâmetro
                "requestUrl": url,
                "requestMethod": method,
                "requestBody": base64.b64encode(request_body).decode() if is_byte_request else request_body,
                "requestCookies": request_cookies,
                "timeoutSeconds": timeout_seconds,
            }
            if certificate_pinning:
                request_payload["certificatePinningHosts"] = certificate_pinning
            if self.client_identifier is None:
                request_payload["customTlsClient"] = {
                    "ja3String": self.ja3_string,
                    "h2Settings": self.h2_settings,
                    "h2SettingsOrder": self.h2_settings_order,
                    "pseudoHeaderOrder": self.pseudo_header_order,
                    "connectionFlow": self.connection_flow,
                    "priorityFrames": self.priority_frames,
                    "headerPriority": self.header_priority,
                    "certCompressionAlgo": self.cert_compression_algo,
                    "supportedVersions": self.supported_versions,
                    "supportedSignatureAlgorithms": self.supported_signature_algorithms,
                    "supportedDelegatedCredentialsAlgorithms": self.supported_delegated_credentials_algorithms,
                    "keyShareCurves": self.key_share_curves,
                }
            else:
                request_payload["tlsClientIdentifier"] = self.client_identifier
                request_payload["withRandomTLSExtensionOrder"] = self.random_tls_extension_order

            # Chama a função request da biblioteca Go
            response = request(dumps(request_payload).encode('utf-8'))
            # Dereference the pointer to a byte array
            response_bytes = ctypes.string_at(response)
            # Convert byte array to string (tls client returns json)
            response_string = response_bytes.decode('utf-8')
            # Convert response string to json
            response_object = loads(response_string)
            response_id = response_object.get('id')

            # --- Response -------------------------------------------------------------------------------------------------
            # Error handling
            if response_object.get("status") == 0:
                raise TLSClientException(response_object.get("body", "Unknown error"))

            # Set response cookies
            response_cookie_jar = extract_cookies_to_jar(
                request_url=url,
                request_headers=headers_final,
                cookie_jar=cookies,
                response_headers=response_object.get("headers", {})
            )

            # build response class
            return build_response(response_object, response_cookie_jar)

        finally:
            # Assegura que freeMemory seja chamado se response_id estiver disponível
            if response_id:
                try:
                    freeMemory(response_id.encode('utf-8'))
                except Exception as e:
                    # Opcional: Log ou tratamento adicional do erro de liberação de memória
                    print(f"Erro ao liberar memória para response_id {response_id}: {e}")

    # Métodos HTTP de Conveniência
    def get(
        self,
        url: str,
        **kwargs: Any
    ) -> Response:
        """Sends a GET request"""
        return self.execute_request(method="GET", url=url, **kwargs)

    def options(
        self,
        url: str,
        **kwargs: Any
    ) -> Response:
        """Sends an OPTIONS request"""
        return self.execute_request(method="OPTIONS", url=url, **kwargs)

    def head(
        self,
        url: str,
        **kwargs: Any
    ) -> Response:
        """Sends a HEAD request"""
        return self.execute_request(method="HEAD", url=url, **kwargs)

    def post(
        self,
        url: str,
        data: Optional[Union[str, dict]] = None,
        json: Optional[dict] = None,
        **kwargs: Any
    ) -> Response:
        """Sends a POST request"""
        return self.execute_request(method="POST", url=url, data=data, json=json, **kwargs)

    def put(
        self,
        url: str,
        data: Optional[Union[str, dict]] = None,
        json: Optional[dict] = None,
        **kwargs: Any
    ) -> Response:
        """Sends a PUT request"""
        return self.execute_request(method="PUT", url=url, data=data, json=json, **kwargs)

    def patch(
        self,
        url: str,
        data: Optional[Union[str, dict]] = None,
        json: Optional[dict] = None,
        **kwargs: Any
    ) -> Response:
        """Sends a PATCH request"""
        return self.execute_request(method="PATCH", url=url, data=data, json=json, **kwargs)

    def delete(
        self,
        url: str,
        **kwargs: Any
    ) -> Response:
        """Sends a DELETE request"""
        return self.execute_request(method="DELETE", url=url, **kwargs)

    # Novos Métodos para as Funções Adicionadas

    def destroy_all(self) -> Dict[str, Any]:
        """Destroys all sessions."""
        try:
            response = destroyAll()
            response_bytes = ctypes.string_at(response)
            response_string = response_bytes.decode('utf-8')
            response_object = loads(response_string)
            response_id = response_object.get('id')
            return response_object
        finally:
            if 'id' in response_object:
                try:
                    freeMemory(response_id.encode('utf-8'))
                except Exception as e:
                    print(f"Erro ao liberar memória para response_id {response_id}: {e}")

    def get_cookies_from_session(self, session_id: str, url: str) -> List[Dict[str, Any]]:
        """Obtém cookies de uma sessão específica."""
        get_cookies_payload = {
            "sessionId": session_id,
            "url": url
        }
        try:
            response = getCookiesFromSession(dumps(get_cookies_payload).encode('utf-8'))
            response_bytes = ctypes.string_at(response)
            response_string = response_bytes.decode('utf-8')
            response_object = loads(response_string)
            response_id = response_object.get('id')
            return response_object.get('cookies', [])
        finally:
            if 'id' in response_object:
                try:
                    freeMemory(response_id.encode('utf-8'))
                except Exception as e:
                    print(f"Erro ao liberar memória para response_id {response_id}: {e}")

    def add_cookies_to_session(self, session_id: str, url: str, cookies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Adiciona cookies a uma sessão específica."""
        add_cookies_payload = {
            "sessionId": session_id,
            "url": url,
            "cookies": cookies
        }
        try:
            response = addCookiesToSession(dumps(add_cookies_payload).encode('utf-8'))
            response_bytes = ctypes.string_at(response)
            response_string = response_bytes.decode('utf-8')
            response_object = loads(response_string)
            response_id = response_object.get('id')
            return response_object.get('cookies', [])
        finally:
            if 'id' in response_object:
                try:
                    freeMemory(response_id.encode('utf-8'))
                except Exception as e:
                    print(f"Erro ao liberar memória para response_id {response_id}: {e}")
