#!/usr/bin/env python3

# Written by z5513520
# A HTTP 1.1 proxy server, support GET, POST, HEAD, CONNECT method 

import sys
import select
import socket
import threading
import re
import time
import argparse
from pathlib import Path
from collections import OrderedDict

zid="z5513520"

# ProxyCache use LRU replacement policy
class ProxyCache:
    # Initialize cache
    def __init__(self, capacity):
        self.capacity = capacity
        self.total_size = 0
        self.cache = OrderedDict()
        self.lock = threading.Lock()

    # Get value from cache
    def get(self, key):
        with self.lock:
            # If key does not exist then return None
            if key not in self.cache:
                return None
            # Update key to recently used
            self.cache.move_to_end(key)
            return self.cache[key]

    # Put value into cache
    def put(self, key, value):
        with self.lock:
            # If key is exist then cover the value
            if key in self.cache:
                self.total_size -= len(self.cache[key]["body"])
                self.cache.move_to_end(key)
            self.cache[key] = value
            self.total_size += len(value["body"])
            # If capacity no enough then pop oldest value
            while self.total_size > self.capacity:
                old_key, old_value = self.cache.popitem(last=False)
                self.total_size -= len(old_value["body"])

# ProxyThread handle client request and response in a separate thread
class ProxyThread(threading.Thread):
    # Initialize thread
    def __init__(self, proxy, client_socket, client_address=None):
        super().__init__()
        self.alive = True
        self.proxy = proxy
        self.client_socket = client_socket
        self.client_address = client_address
        self.reset_request_response()
        self.buffer = b""

    # Reset request and response data
    def reset_request_response(self):
        self.request_start = {"method": None, "url": None, "version": None, "host": None, "port": None, "path": None, "query": None}
        self.request_header = {}
        self.request_body = b""
        self.response_start = {"version": None, "status_code": None, "reason_phrase": None}
        self.response_header = {}
        self.response_body = b""

    # Run thread to handle client request
    def run(self):
        try:
            while self.alive:
                self.reset_request_response()
                try:
                    self.handle_client(self.client_socket)
                except socket.timeout:
                    break
                except Exception as e:
                    break
        finally:
            try:
                self.client_socket.close()
            except Exception:
                pass

    # Handle client request
    def handle_client(self, client_socket):
        # Reset client socket timeout
        client_socket.settimeout(self.proxy.timeout)
        
        # Try to read request data from client
        while b"\r\n\r\n" not in self.buffer:
            data = client_socket.recv(1024)
            if not data:
                self.alive = False
                return
            self.buffer += data

        # Parse request data
        if not self.parse_request(self.buffer):
            self.alive = False
            return

        # If request method is CONNECT, handle it separately
        if self.request_start["method"] == "CONNECT":
            self.connect_handler(self.request_start["url"], client_socket)
            self.do_log()
            self.alive = False
            return

        # If request method is not CONNECT, handle it normally
        cache_flag = "-"
        cache_key = self.normalize_url(self.request_start["url"])

        # If request method is GET, check cache
        if self.request_start["method"] == "GET":
            cache_flag = "M"
            cached = self.proxy.cache.get(cache_key)
            # If cache hit, use cached response
            if cached:
                status_code = cached["start"]["status_code"]
                cache_flag = "H"
                self.response_start = cached["start"]
                self.response_header = cached["header"]
                self.response_body =cached["body"]

        # If cache miss, fetch from server
        if cache_flag != "H":
            server_request_start = self.modify_request_start()
            server_request_headers = self.modify_request_header()
            request_data = server_request_start + server_request_headers + b"\r\n" + self.request_body

            if not self.fetch_from_server(request_data):
                self.alive = False
                return

            if self.request_start["method"] == "GET" and self.response_start["status_code"] == 200 and len(self.response_body) <= self.proxy.max_object_size:
                self.proxy.cache.put(cache_key, {"start": self.response_start, "header": self.response_header, "body": self.response_body})

        # Send response to client
        response_header = self.modify_response_header()
        self.send_http_response(client_socket, self.response_start["status_code"], self.response_start["reason_phrase"], self.response_body, response_header)
        
        # Logging
        self.do_log(cache_flag)
    
    # Parse request data from client
    def parse_request(self, buffer):
        # Try to split the request into start line, headers, and body
        try:
            parts = buffer.split(b"\r\n\r\n", 1)
            if len(parts) < 2:
                return False
            
            lines = parts[0].decode(errors="replace").split("\r\n")
            start_line = lines[0]
            headers = lines[1:] if len(lines) > 1 else []
            body = parts[1] if len(parts) > 1 else b""
        except Exception:
            return False

        # Parse start line
        if not start_line or len(start_line.split()) != 3:
            return False
        self.request_start["method"] = start_line.split()[0]
        self.request_start["url"] = start_line.split()[1]
        self.request_start["version"] = start_line.split()[2]

        # Handle different URL formats
        if self.request_start["method"] == "CONNECT":
            # Authority-Form URL: host:port
            m = re.match(r"(?P<host>[^:]+)(?::(?P<port>\d+))", self.request_start["url"])
            if not m:
                self.send_http_response(self.client_socket, 400, "Bad Request", b"no host")
                return False
            if not m.group("port"):
                self.send_http_response(self.client_socket, 400, "Bad Request", b"invalid port")
                return False
            self.request_start["host"] = m.group("host").lower()
            self.request_start["port"] = str(int(m.group("port")))
            if self.request_start["port"] != "443":
                self.send_http_response(self.client_socket, 400, "Bad Request", b"invalid port")
                return False
        elif self.request_start["url"].startswith("http://"):
            # Absolute-Form URL: http://host[:port]/path[?query]
            m = re.match(r"http://(?P<host>[^:/]+)(?::(?P<port>\d+))?(?P<path>[^?]*)?(?:\?(?P<query>.*))?", self.request_start["url"])
            if not m:
                self.send_http_response(self.client_socket, 400, "Bad Request", b"no host")
                return False
            self.request_start["host"] = m.group("host").lower()
            self.request_start["port"] = str(int(m.group("port"))) if m.group("port") else "80"
            self.request_start["path"] = m.group("path") or "/"
            self.request_start["query"] = m.group("query") or None
        elif self.request_start["url"].startswith("/"):
            # Origin-Form URL: /[path][?query]
            m = re.match(r"(?P<path>[^?]*)(?:\?(?P<query>.*))?", self.request_start["url"])
            self.request_start["port"] = "80"
            self.request_start["path"] = m.group("path") or "/"
            self.request_start["query"] = m.group("query") or None
        else:
            # Invalid URL format
            self.send_http_response(self.client_socket, 400, "Bad Request", b"no host")
            return False

        # Check if host is localhost or proxy address
        if self.request_start["host"] in ("127.0.0.1", "localhost") or self.request_start["port"] == self.proxy.port:
            self.send_http_response(self.client_socket, 421, "Misdirected Request", b"proxy address")
            return False

        # Parse headers
        request_header = {}
        for line in headers:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            request_header[key.strip()] = value.strip()
        self.request_header = dict(request_header)

        # Set host in case of missing host in start line
        if self.request_start["host"] == None and "Host" in self.request_header:
            self.request_start["host"] = self.request_header["Host"].lower()
        elif not self.request_start.get("host"):
            self.send_http_response(self.client_socket, 400, "Bad Request", b"no host")
            return False

        # Check if connection should be closed
        if self.request_header.get("Connection", "").lower() == "close" or self.request_header.get("Proxy-Connection", "").lower() == "close":
            self.alive = False

        # If Content-Length is present, read the body
        if "Content-Length" in self.request_header:
            try:
                content_length = int(self.request_header["Content-Length"])
                if content_length > 0:
                    while len(body) < content_length:
                        data = self.client_socket.recv(1024)
                        if not data:
                            return False
                        body += data
            except ValueError:
                return False
            self.request_body = body[:content_length]
            self.buffer = body[content_length:]
        else:
            self.request_body = b""
            self.buffer = body

        return True
    
    # Modify request start line
    def modify_request_start(self):
        if self.request_start["method"] == "GET" or self.request_start["method"] == "POST":
            if self.request_start["query"]:
                return f"{self.request_start['method']} {self.request_start['path']}?{self.request_start['query']} {self.request_start['version']}\r\n".encode()
            else:
                return f"{self.request_start['method']} {self.request_start['path']} {self.request_start['version']}\r\n".encode()
        else:
            return f"{self.request_start['method']} {self.request_start['url']} {self.request_start['version']}\r\n".encode()

    # Modify request header
    def modify_request_header(self):
        new_header = self.request_header.copy()

        # Connection to target server must be closed
        if "Connection" in new_header:
            new_header["Connection"] = "close"
        
        if "Proxy-Connection" in new_header:
            new_header["Proxy-Connection"] = "close"

        # Add Via header
        via_val = f"1.1 {zid}"
        if "Via" in new_header:
            new_header["Via"] = new_header["Via"] + ", " + via_val
        else:
            new_header["Via"] = via_val

        # If Host is not in header, set it from request start line
        if "Host" not in new_header:
            if self.request_start["host"]:
                new_header["Host"] = self.request_start["host"]

        out = b""
        for key, value in new_header.items():
            out += f"{key}: {value}\r\n".encode()
        return out
    
    # Fetch response from server
    def fetch_from_server(self, request_data):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.settimeout(self.proxy.timeout)
        try:
            # Try to connect to the server
            try:
                server.connect((self.request_start["host"], int(self.request_start["port"])))
            except socket.gaierror:
                server.close()
                self.response_start["status_code"] = 502
                self.response_start["reason_phrase"] = "Bad Gateway"
                self.response_body = b"could not resolve"
                return False
            except ConnectionRefusedError:
                server.close()
                self.response_start["status_code"] = 502
                self.response_start["reason_phrase"] = "Bad Gateway"
                self.response_body = b"connection refused"
                return False
            except socket.timeout:
                server.close()
                self.response_start["status_code"] = 504
                self.response_start["reason_phrase"] = "Bad Gateway"
                self.response_body = b"timed out"
                return False
            except Exception as e:
                server.close()
                self.response_start["status_code"] = 502
                self.response_start["reason_phrase"] = "connection refused"
                self.response_body = b"could not resolve"
                return False

            # Send request data to server
            try:
                server.sendall(request_data)
            except Exception:
                server.close()
                self.response_start["status_code"] = 502
                self.response_start["reason_phrase"] = "Bad Gateway"
                self.response_body = b"closed unexpectedly"
                return False

            # Read response from server
            buffer = b""
            while b"\r\n\r\n" not in buffer:
                try:
                    data = server.recv(1024)
                    if not data:
                        server.close()
                        self.response_start["status_code"] = 502
                        self.response_start["reason_phrase"] = "Bad Gateway"
                        self.response_body = b"closed unexpectedly"
                        return False
                    buffer += data
                except socket.timeout:
                    server.close()
                    self.response_start["status_code"] = 504
                    self.response_start["reason_phrase"] = "Bad Gateway"
                    self.response_body = b"timed out"
                    return False
                except Exception:
                    server.close()
                    self.response_start["status_code"] = 502
                    self.response_start["reason_phrase"] = "Bad Gateway"
                    self.response_body = b"closed unexpectedly"
                    return False

            if not self.parse_response(buffer):
                server.close()
                return False

            server.close()
            return True
        except Exception as e:
            server.close()
            self.response_start["status_code"] = 502
            self.response_start["reason_phrase"] = "Bad Gateway"
            self.response_body = b"closed unexpectedly"
            return False

    # Parse response from server
    def parse_response(self, buffer):
        # Try to split the response into start line, headers, and body
        try:
            parts = buffer.split(b"\r\n\r\n", 1)
            if len(parts) != 2:
                return False
            header_bytes, body = parts
            lines = header_bytes.decode(errors="replace").split("\r\n")

            if not lines or len(lines[0].split(" ")) < 2:
                return False
            version, status_code, *reason = lines[0].split(" ")
            self.response_start["version"] = version
            self.response_start["status_code"] = int(status_code)
            self.response_start["reason_phrase"] = " ".join(reason) if reason else ""

            # Parse headers
            header_dict = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    header_dict[key.strip()] = value.strip()
            self.response_header = header_dict

            full_body = b""

            # Handle Transfer-Encoding
            if header_dict.get("Transfer-Encoding", "").lower() == "chunked":
                rest = body
                while True:
                    idx = rest.find(b"\r\n")
                    if idx == -1:
                        return False
                    chunk_size_line = rest[:idx].decode(errors="replace").strip()
                    try:
                        chunk_size = int(chunk_size_line, 16)
                    except Exception:
                        return False
                    rest = rest[idx+2:]

                    if chunk_size == 0:
                        break

                    if len(rest) < chunk_size + 2:
                        return False

                    chunk = rest[:chunk_size]
                    full_body += chunk
                    rest = rest[chunk_size+2:]

                self.response_body = full_body
                return True

            # Handle Content-Length
            elif "Content-Length" in header_dict:
                try:
                    content_length = int(header_dict["Content-Length"])
                except Exception:
                    return False

                if len(body) < content_length:
                    return False

                self.response_body = body[:content_length]
                return True

            # No Transfer-Encoding or Content-Length
            else:
                self.response_body = body
                return True

        except Exception:
            return False
    
    # Modify response header
    def modify_response_header(self):
        new_header = self.response_header.copy()

        # Set Connection header based on whether the connection is alive
        new_header["Connection"] = "keep-alive" if self.alive else "close"

        # Add Via header
        via_val = f"1.1 {zid}"
        if "Via" in new_header:
            new_header["Via"] = new_header["Via"] + ", " + via_val
        else:
            new_header["Via"] = via_val

        return new_header

    # Handle CONNECT method
    def connect_handler(self, url, client_socket):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(self.proxy.timeout)
            server_socket.connect((self.request_start['host'], int(self.request_start['port'])))
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.response_start['status_code'] = 200
            self.response_start['reason_phrase'] = "Connection Established"
            self.tunnel(client_socket, server_socket)
        except Exception as e:
            try:
                client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                self.response_start['status_code'] = 502
                self.response_start['reason_phrase'] = "Bad Gateway"
            except Exception:
                pass
        finally:
            try:
                if server_socket:
                    server_socket.close()
            except Exception:
                pass
            try:
                client_socket.close()
            except Exception:
                pass

    # Tunnel data between client and server
    def tunnel(self, client_socket, server_socket):
        # Set non-blocking mode for both sockets
        client_socket.setblocking(False)
        server_socket.setblocking(False)
        sockets = [client_socket, server_socket]

        # Use select to handle multiple sockets
        try:
            while True:
                rlist, _, _ = select.select(sockets, [], [], self.proxy.timeout)
                if not rlist:
                    break
                for s in rlist:
                    try:
                        data = s.recv(4096)
                        if not data:
                            return
                        if s is client_socket:
                            server_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                    except Exception:
                        return
        except Exception:
            pass
    
    # Send HTTP response
    def send_http_response(self, sock, status_code=200, reason="OK", body_text=b"", headers=None):
        if isinstance(body_text, str):
            body = body_text.encode()
        else:
            body = body_text
        if headers is None:
            headers = {}

        is_client = (sock is self.client_socket)

        # If is client sock, set Connection header to keep-alive, otherwise set to close
        headers["Connection"] = "keep-alive" if is_client else "close"

        # Add Via header
        via_value = f"1.1 {zid}"
        if "Via" in headers:
            headers["Via"] = headers["Via"] + ", " + via_value
        else:
            headers["Via"] = via_value

        header_lines = [f"HTTP/1.1 {status_code} {reason}"]
        if "Content-Length" not in headers:
            headers["Content-Length"] = str(len(body))
        for k, v in headers.items():
            header_lines.append(f"{k}: {v}")
        header_str = "\r\n".join(header_lines) + "\r\n\r\n"
        try:
            sock.sendall(header_str.encode() + body)
        except Exception:
            pass
    
    # Normalize URL to a standard format for caching
    def normalize_url(self, raw_url):
        match = re.match(
            r'^(?P<scheme>https?)://'
            r'(?P<host>[^/:?#]+)'
            r'(:(?P<port>\d+))?'
            r'(?P<path>/[^?#]*)?'
            r'(\?(?P<query>[^#]*))?',
            raw_url,
            re.IGNORECASE
        )

        if not match:
            return url

        scheme = match.group('scheme').lower()
        host = match.group('host').lower()
        port = match.group('port') or '80'
        path = match.group('path') or '/'
        query = match.group('query')
        
        port = str(int(port))
        if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
            port = ''
        else:
            port = f':{port}'
        
        url = f"{scheme}://{host}{port}{path}"
        if query:
            url += f"?{query}"

        return url

    # Log request and response
    def do_log(self, cache_flag="-"):
        try:
            if hasattr(self, "client_address") and self.client_address is not None:
                client_addr, client_port = self.client_address
            else:
                client_addr, client_port = self.client_socket.getpeername()
        except Exception:
            client_addr, client_port = "-", "-"
        date = time.strftime("%d/%b/%Y:%H:%M:%S %z", time.localtime())
        request_line = f'{self.request_start.get("method", "")} {self.request_start.get("url", "")} {self.request_start.get("version", "")}'
        status_code = self.response_start.get("status_code", "-")
        content_length = self.response_header.get('Content-Length')
        try:
            body_size = int(content_length) if content_length is not None else len(self.response_body)
        except Exception:
            body_size = len(self.response_body)
        log_line = f'{client_addr} {client_port} {cache_flag} [{date}] "{request_line}" {status_code} {body_size}'
        print(log_line)
        try:
            with open("log.txt", "a") as f:
                f.write(log_line + "\n")
        except Exception:
            pass

# ProxyServer setup a proxy server on given port and listen for connections
class ProxyServer:
    def __init__(self, port, timeout, max_object_size, max_cache_size):
        self.port = port
        self.timeout =timeout
        self.max_object_size = max_object_size
        self.max_cache_size = max_cache_size
        self.cache = ProxyCache(max_cache_size)

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('', self.port))
        server_socket.listen(10)
        print(f"##### Proxy server started on port {self.port} #####")

        try:
            while True:
                client_socket, addr = server_socket.accept()
                thread = ProxyThread(self, client_socket, addr)
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print("##### Proxy server shutting down #####")
        finally:
            server_socket.close()

# Main function
def main():
    # Get args from stdin
    parser = argparse.ArgumentParser(description="HTTP web Proxy Server")
    parser.add_argument("port", type=int)
    parser.add_argument("timeout", type=int)
    parser.add_argument("max_object_size", type=int)
    parser.add_argument("max_cache_size", type=int)
    args = parser.parse_args()

    # Start proxy server
    proxy = ProxyServer(args.port, args.timeout, args.max_object_size, args.max_cache_size)
    proxy.start()

if __name__ == "__main__":
    main()