import socket
import struct
import threading
import select
import logging
import sys
import os
import json
import time
from typing import Optional, Tuple
from urllib.parse import urlparse, urlsplit

import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import scrolledtext


# ----------------------------
# Traffic Statistics
# ----------------------------
class TrafficStats:
    """流量统计类"""
    def __init__(self):
        self._lock = threading.Lock()
        self.upload_bytes = 0      # 总上行流量（字节）
        self.download_bytes = 0    # 总下行流量（字节）
        self.last_upload_bytes = 0  # 上次记录的上行流量
        self.last_download_bytes = 0  # 上次记录的下行流量
        self.last_update_time = time.time()
        self.upload_speed = 0  # 上行速度（字节/秒）
        self.download_speed = 0  # 下行速度（字节/秒）

    def add_upload(self, bytes_count: int):
        """添加上行流量"""
        with self._lock:
            self.upload_bytes += bytes_count

    def add_download(self, bytes_count: int):
        """添加下行流量"""
        with self._lock:
            self.download_bytes += bytes_count

    def update_speed(self):
        """更新速度统计"""
        with self._lock:
            current_time = time.time()
            time_diff = current_time - self.last_update_time

            if time_diff > 0:
                # 计算速度（字节/秒）
                self.upload_speed = (self.upload_bytes - self.last_upload_bytes) / time_diff
                self.download_speed = (self.download_bytes - self.last_download_bytes) / time_diff

                # 更新记录
                self.last_upload_bytes = self.upload_bytes
                self.last_download_bytes = self.download_bytes
                self.last_update_time = current_time

    def get_stats(self):
        """获取统计信息"""
        with self._lock:
            return {
                'upload_bytes': self.upload_bytes,
                'download_bytes': self.download_bytes,
                'upload_speed': self.upload_speed,
                'download_speed': self.download_speed
            }

    def reset(self):
        """重置统计"""
        with self._lock:
            self.upload_bytes = 0
            self.download_bytes = 0
            self.last_upload_bytes = 0
            self.last_download_bytes = 0
            self.last_update_time = time.time()
            self.upload_speed = 0
            self.download_speed = 0


# ----------------------------
# Configuration Management
# ----------------------------
def get_config_path() -> str:
    """获取配置文件路径，位于程序同目录下的config.json"""
    # 判断是否为打包后的exe程序
    if getattr(sys, 'frozen', False):
        # 打包后，使用exe文件所在目录
        base_dir = os.path.dirname(sys.executable)
    else:
        # 开发模式，使用脚本文件所在目录
        base_dir = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_dir, "config.json")


def load_config() -> dict:
    """
    加载配置文件，返回配置字典
    如果文件不存在或格式错误，返回默认配置
    """
    default_config = {
        "protocol": "SOCKS5",
        "bind_host": "0.0.0.0", 
        "bind_port": 1080,
        "upstream_host": "",
        "upstream_port": 1080,
        "timeout": 10,
        # 端口转发默认配置
        "forward_enabled": False,
        "forward_rules": []  # 默认为空的端口转发规则列表
    }
    
    config_path = get_config_path()
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                # 确保所有必需的键都存在
                for key, default_value in default_config.items():
                    if key not in config:
                        config[key] = default_value
                
                # 兼容旧版本配置格式
                if "forward_port" in config and "forward_rules" not in config:
                    # 将旧的单个端口转发配置转换为新的规则列表格式
                    old_rule = {
                        "forward_port": config.get("forward_port", 8888),
                        "target_host": config.get("forward_target_host", "127.0.0.1"),
                        "target_port": config.get("forward_target_port", 80)
                    }
                    config["forward_rules"] = [old_rule]
                    # 清理旧的配置项
                    config.pop("forward_port", None)
                    config.pop("forward_target_host", None)
                    config.pop("forward_target_port", None)
                
                return config
    except (json.JSONDecodeError, IOError) as e:
        print(f"配置文件读取失败，使用默认配置: {e}")
    
    return default_config


def save_config(config: dict) -> None:
    """
    保存配置到文件
    """
    config_path = get_config_path()
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
    except IOError as e:
        print(f"配置文件保存失败: {e}")


# ----------------------------
# Logging handler for Tkinter
# ----------------------------
class TkTextHandler(logging.Handler):
    """Thread-safe logging handler that writes to a Tkinter Text widget."""

    def __init__(self, text_widget: tk.Text, max_lines: int = 5000):
        super().__init__()
        self.text_widget = text_widget
        self.text_widget.configure(state=tk.NORMAL)
        self.max_lines = max_lines

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        # Schedule UI update in the main thread
        self.text_widget.after(0, self._append, msg)

    def _append(self, msg: str) -> None:
        try:
            self.text_widget.insert(tk.END, msg + "\n")
            # Autoscroll
            self.text_widget.see(tk.END)
            # Trim if too long
            current_lines = int(self.text_widget.index('end-1c').split('.')[0])
            if current_lines > self.max_lines:
                # Remove oldest lines
                remove_count = current_lines - self.max_lines
                self.text_widget.delete('1.0', f"{remove_count}.0")
        except tk.TclError:
            # Widget might be destroyed during shutdown
            pass


# ----------------------------
# SOCKS5 Proxy Server
# ----------------------------
class Socks5Server:
    def __init__(
        self,
        bind_host: str = "0.0.0.0",
        bind_port: int = 1080,
        upstream_host: Optional[str] = None,
        upstream_port: Optional[int] = None,
        timeout: int = 10,
        logger: Optional[logging.Logger] = None,
        traffic_stats: Optional[TrafficStats] = None,
    ) -> None:
        self.bind_host = bind_host
        self.bind_port = int(bind_port)
        self.upstream_host = upstream_host or None
        self.upstream_port = int(upstream_port) if upstream_port else None
        self.timeout = int(timeout)
        self.logger = logger or logging.getLogger("mproxy")
        self.traffic_stats = traffic_stats

        self._server_socket: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._client_threads: list[threading.Thread] = []

    def start(self) -> None:
        if self._accept_thread and self._accept_thread.is_alive():
            self.logger.warning("SOCKS5 服务已在运行")
            return
        self._stop_event.clear()
        self._accept_thread = threading.Thread(target=self._serve_forever, name="Socks5Accept", daemon=True)
        self._accept_thread.start()
        self.logger.info(f"SOCKS5 服务启动: {self.bind_host}:{self.bind_port}")

    def stop(self) -> None:
        self._stop_event.set()
        try:
            if self._server_socket:
                try:
                    self._server_socket.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self._server_socket.close()
        except Exception as e:
            self.logger.debug(f"关闭服务器套接字异常: {e}")
        if self._accept_thread:
            self._accept_thread.join(timeout=2)
        # Best effort: join client threads
        for t in list(self._client_threads):
            if t.is_alive():
                t.join(timeout=2)
        self._client_threads.clear()
        self.logger.info("SOCKS5 服务已停止")

    def _serve_forever(self) -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket = srv
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.bind_host, self.bind_port))
            srv.listen(128)
            srv.settimeout(1.0)
            self.logger.info("等待客户端连接...")
        except Exception as e:
            self.logger.error(f"绑定监听失败: {e}")
            return

        while not self._stop_event.is_set():
            try:
                client_sock, client_addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                self.logger.error(f"接受连接异常: {e}")
                continue
            self.logger.info(f"客户端连接: {client_addr}")
            t = threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True)
            self._client_threads.append(t)
            t.start()

    def _handle_client(self, client: socket.socket, client_addr: Tuple[str, int]) -> None:
        client.settimeout(self.timeout)
        try:
            # Handshake: VER, NMETHODS, METHODS
            header = self._recv_exact(client, 2)
            if not header:
                raise Exception("握手读取失败")
            ver, nmethods = header[0], header[1]
            if ver != 0x05:
                self.logger.warning(f"非 SOCKS5 版本: {ver}")
                client.close()
                return
            methods = self._recv_exact(client, nmethods)
            # We support 'NO AUTH' only
            client.sendall(b"\x05\x00")

            # Request: VER CMD RSV ATYP ...
            req = self._recv_exact(client, 4)
            if not req:
                raise Exception("请求头读取失败")
            ver, cmd, rsv, atyp = req
            if ver != 0x05:
                raise Exception("请求版本错误")
            if cmd != 0x01:  # CONNECT
                # Reply: command not supported
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                raise Exception(f"不支持的CMD: {cmd}")

            if atyp == 0x01:  # IPv4
                addr = self._recv_exact(client, 4)
                dest_host = socket.inet_ntoa(addr)
            elif atyp == 0x03:  # DOMAIN
                ln = self._recv_exact(client, 1)[0]
                domain = self._recv_exact(client, ln).decode("utf-8", errors="replace")
                dest_host = domain
            elif atyp == 0x04:  # IPv6
                addr = self._recv_exact(client, 16)
                dest_host = socket.inet_ntop(socket.AF_INET6, addr)
            else:
                client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                raise Exception(f"未知地址类型: {atyp}")

            port_bytes = self._recv_exact(client, 2)
            dest_port = struct.unpack("!H", port_bytes)[0]
            self.logger.info(f"请求 CONNECT 到 {dest_host}:{dest_port}")

            # Establish remote connection (direct or via upstream)
            if self.upstream_host and self.upstream_port:
                remote = self._connect_via_upstream(dest_host, dest_port)
            else:
                remote = socket.create_connection((dest_host, dest_port), timeout=self.timeout)
                remote.settimeout(self.timeout)

            # Reply success to client
            bnd_addr, bnd_port = remote.getsockname()[:2]
            try:
                ip = socket.inet_pton(socket.AF_INET, bnd_addr)
                rep = b"\x05\x00\x00\x01" + ip + struct.pack("!H", bnd_port)
            except OSError:
                # Fallback to IPv6 reply
                ip6 = socket.inet_pton(socket.AF_INET6, bnd_addr)
                rep = b"\x05\x00\x00\x04" + ip6 + struct.pack("!H", bnd_port)
            client.sendall(rep)

            # Relay data
            self._relay_bidirectional(client, remote)
        except Exception as e:
            self.logger.warning(f"处理客户端 {client_addr} 异常: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _connect_via_upstream(self, dest_host: str, dest_port: int) -> socket.socket:
        """Chain to upstream SOCKS5 (no-auth)."""
        self.logger.info(f"通过上游 SOCKS5 连接: {self.upstream_host}:{self.upstream_port} -> {dest_host}:{dest_port}")
        upstream = socket.create_connection((self.upstream_host, self.upstream_port), timeout=self.timeout)
        upstream.settimeout(self.timeout)
        # Handshake: no-auth
        upstream.sendall(b"\x05\x01\x00")
        resp = self._recv_exact(upstream, 2)
        if resp != b"\x05\x00":
            raise Exception("上游不支持无认证")

        # Build CONNECT request
        atyp, addr_bytes = self._pack_addr(dest_host)
        req = b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + struct.pack("!H", dest_port)
        upstream.sendall(req)
        # Parse reply
        ver_cmd_rsv_atyp = self._recv_exact(upstream, 4)
        if not ver_cmd_rsv_atyp or ver_cmd_rsv_atyp[1] != 0x00:
            raise Exception("上游连接失败")
        # Consume BND.ADDR + BND.PORT per ATYP
        if ver_cmd_rsv_atyp[3] == 0x01:
            self._recv_exact(upstream, 4)
        elif ver_cmd_rsv_atyp[3] == 0x03:
            ln = self._recv_exact(upstream, 1)[0]
            self._recv_exact(upstream, ln)
        elif ver_cmd_rsv_atyp[3] == 0x04:
            self._recv_exact(upstream, 16)
        self._recv_exact(upstream, 2)
        return upstream

    @staticmethod
    def _pack_addr(host: str) -> Tuple[int, bytes]:
        # Try IPv4
        try:
            return 0x01, socket.inet_pton(socket.AF_INET, host)
        except OSError:
            pass
        # Try IPv6
        try:
            return 0x04, socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            pass
        # Domain name
        host_bytes = host.encode('utf-8')
        if len(host_bytes) > 255:
            raise ValueError("域名过长")
        return 0x03, bytes([len(host_bytes)]) + host_bytes

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("对端关闭连接")
            data += chunk
        return data

    def _relay_bidirectional(self, client: socket.socket, remote: socket.socket) -> None:
        try:
            sockets = [client, remote]
            while True:
                rlist, _, _ = select.select(sockets, [], [], 1.0)
                if not rlist:
                    # Check stop
                    if self._stop_event.is_set():
                        break
                    continue
                for s in rlist:
                    try:
                        data = s.recv(4096)
                    except Exception:
                        data = b""
                    if not data:
                        return
                    if s is client:
                        # 客户端到远程：上行
                        if self.traffic_stats:
                            self.traffic_stats.add_upload(len(data))
                        remote.sendall(data)
                    else:
                        # 远程到客户端：下行
                        if self.traffic_stats:
                            self.traffic_stats.add_download(len(data))
                        client.sendall(data)
        finally:
            try:
                remote.close()
            except Exception:
                pass


# ----------------------------
# HTTP Proxy Server
# ----------------------------
class HTTPProxyServer:
    def __init__(
        self,
        bind_host: str = "0.0.0.0",
        bind_port: int = 8080,
        upstream_host: Optional[str] = None,
        upstream_port: Optional[int] = None,
        timeout: int = 10,
        logger: Optional[logging.Logger] = None,
        traffic_stats: Optional[TrafficStats] = None,
    ) -> None:
        self.bind_host = bind_host
        self.bind_port = int(bind_port)
        self.upstream_host = upstream_host or None
        self.upstream_port = int(upstream_port) if upstream_port else None
        self.timeout = int(timeout)
        self.logger = logger or logging.getLogger("mproxy")
        self.traffic_stats = traffic_stats

        self._server_socket: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._client_threads: list[threading.Thread] = []

    def start(self) -> None:
        if self._accept_thread and self._accept_thread.is_alive():
            self.logger.warning("HTTP 代理已在运行")
            return
        self._stop_event.clear()
        self._accept_thread = threading.Thread(target=self._serve_forever, name="HttpAccept", daemon=True)
        self._accept_thread.start()
        self.logger.info(f"HTTP 代理启动: {self.bind_host}:{self.bind_port}")

    def stop(self) -> None:
        self._stop_event.set()
        try:
            if self._server_socket:
                try:
                    self._server_socket.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self._server_socket.close()
        except Exception as e:
            self.logger.debug(f"关闭服务器套接字异常: {e}")
        if self._accept_thread:
            self._accept_thread.join(timeout=2)
        for t in list(self._client_threads):
            if t.is_alive():
                t.join(timeout=2)
        self._client_threads.clear()
        self.logger.info("HTTP 代理已停止")

    def _serve_forever(self) -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket = srv
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.bind_host, self.bind_port))
            srv.listen(128)
            srv.settimeout(1.0)
            self.logger.info("等待客户端连接...")
        except Exception as e:
            self.logger.error(f"绑定监听失败: {e}")
            return

        while not self._stop_event.is_set():
            try:
                client_sock, client_addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                self.logger.error(f"接受连接异常: {e}")
                continue
            self.logger.info(f"客户端连接: {client_addr}")
            t = threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True)
            self._client_threads.append(t)
            t.start()

    def _handle_client(self, client: socket.socket, client_addr: Tuple[str, int]) -> None:
        """
        处理HTTP代理客户端连接
        支持CONNECT方法（用于HTTPS隧道）和GET/POST等方法（用于HTTP请求转发）
        """
        client.settimeout(self.timeout)
        try:
            header_bytes, rest = self._read_headers(client)
            if not header_bytes or len(header_bytes.strip()) == 0:
                self.logger.warning(f"客户端 {client_addr} 发送空请求，可能是连接探测或异常断开")
                return
            
            # Parse first line
            try:
                lines = header_bytes.split(b"\r\n")
                if not lines or not lines[0]:
                    self.logger.warning(f"客户端 {client_addr} 请求行为空")
                    client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                    return
                    
                request_line = lines[0].decode("iso-8859-1", errors="replace")
                parts = request_line.split(" ")
                if len(parts) < 3:
                    self.logger.warning(f"客户端 {client_addr} 请求行格式错误: {request_line}")
                    client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                    return
                    
                method, target, version = parts[0], parts[1], parts[2]
            except Exception as e:
                self.logger.warning(f"客户端 {client_addr} 请求解析失败: {e}")
                client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return

            # Collect headers dict for convenience
            headers = {}
            for line in lines[1:]:
                if not line:
                    continue
                k, sep, v = line.partition(b":")
                if not sep:
                    continue
                headers[k.strip().decode("iso-8859-1")] = v.strip().decode("iso-8859-1")

            if method.upper() == "CONNECT":
                dest_host, dest_port = self._parse_connect_target(target)
                self.logger.info(f"HTTP CONNECT -> {dest_host}:{dest_port}")
                if self.upstream_host and self.upstream_port:
                    # Connect to upstream HTTP proxy and issue CONNECT
                    upstream = socket.create_connection((self.upstream_host, self.upstream_port), timeout=self.timeout)
                    upstream.settimeout(self.timeout)
                    connect_req = f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\nHost: {dest_host}:{dest_port}\r\nProxy-Connection: Keep-Alive\r\n\r\n".encode("iso-8859-1")
                    upstream.sendall(connect_req)
                    upstream_resp, _ = self._read_headers(upstream)
                    if not upstream_resp.startswith(b"HTTP/1.1 200") and not upstream_resp.startswith(b"HTTP/1.0 200"):
                        # Forward upstream response to client
                        try:
                            client.sendall(upstream_resp)
                        except Exception:
                            pass
                        upstream.close()
                        return
                    # Inform client tunnel established
                    client.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: mproxy\r\n\r\n")
                    self._relay_bidirectional(client, upstream)
                    return
                else:
                    # Direct connect
                    remote = socket.create_connection((dest_host, dest_port), timeout=self.timeout)
                    remote.settimeout(self.timeout)
                    client.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: mproxy\r\n\r\n")
                    # Any remaining bytes after headers should be part of tunneling data (rare)
                    if rest:
                        remote.sendall(rest)
                    self._relay_bidirectional(client, remote)
                    return

            # Non-CONNECT request (e.g., GET/POST)
            # Determine destination
            dest_host, dest_port, path, is_absolute = self._determine_destination(target, headers)
            self.logger.info(f"HTTP {method} -> {dest_host}:{dest_port} {path}")

            if self.upstream_host and self.upstream_port:
                # Send request to upstream HTTP proxy, ensure absolute-form
                url = f"http://{dest_host}:{dest_port}{path}"
                first_line = f"{method} {url} {version}\r\n".encode("iso-8859-1")
                out_headers = self._rewrite_headers(headers, to_origin=False)
                upstream = socket.create_connection((self.upstream_host, self.upstream_port), timeout=self.timeout)
                upstream.settimeout(self.timeout)
                upstream.sendall(first_line + out_headers + b"\r\n")
                if rest:
                    upstream.sendall(rest)
                self._relay_bidirectional(client, upstream)
                return
            else:
                # Direct to origin server, use origin-form
                first_line = f"{method} {path} {version}\r\n".encode("iso-8859-1")
                out_headers = self._rewrite_headers(headers, host=f"{dest_host}:{dest_port}", to_origin=True)
                remote = socket.create_connection((dest_host, dest_port), timeout=self.timeout)
                remote.settimeout(self.timeout)
                remote.sendall(first_line + out_headers + b"\r\n")
                if rest:
                    remote.sendall(rest)
                self._relay_bidirectional(client, remote)
                return

        except Exception as e:
            self.logger.warning(f"处理客户端 {client_addr} 异常: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _parse_connect_target(self, target: str) -> Tuple[str, int]:
        try:
            if isinstance(target, bytes):
                target = target.decode("iso-8859-1")
            if ":" in target:
                host, port_str = target.rsplit(":", 1)
                return host, int(port_str)
            return target, 443
        except Exception:
            return target, 443

    def _determine_destination(self, target: str, headers: dict) -> Tuple[str, int, str, bool]:
        # target may be absolute-form (http://host:port/path) or origin-form (/path)
        if isinstance(target, bytes):
            target = target.decode("iso-8859-1", errors="replace")
        split = urlsplit(target)
        if split.scheme and split.netloc:
            host_port = split.netloc
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                port = int(port_str)
            else:
                host = host_port
                port = 80 if split.scheme == "http" else 443
            path = split.path or "/"
            if split.query:
                path += f"?{split.query}"
            return host, port, path, True
        # origin-form: use Host header
        host_header = headers.get("Host") or headers.get("host")
        if not host_header:
            raise Exception("缺少 Host 头")
        if ":" in host_header:
            host, port_str = host_header.rsplit(":", 1)
            try:
                port = int(port_str)
            except Exception:
                port = 80
        else:
            host = host_header
            port = 80
        path = target if target else "/"
        return host, port, path, False

    def _rewrite_headers(self, headers: dict, host: Optional[str] = None, to_origin: bool = True) -> bytes:
        # Remove Proxy-Connection; ensure Host header when going to origin
        out_lines = []
        for k, v in headers.items():
            lk = k.lower()
            if lk == "proxy-connection":
                continue
            if to_origin and lk == "proxy-authorization":
                # Do not forward proxy auth to origin
                continue
            if lk == "connection" and v.lower() == "keep-alive":
                out_lines.append(f"Connection: keep-alive")
            else:
                out_lines.append(f"{k}: {v}")
        if to_origin and host:
            # Ensure Host header
            has_host = any(l.lower().startswith("host:") for l in out_lines)
            if not has_host:
                out_lines.append(f"Host: {host}")
        # End headers
        return ("\r\n".join(out_lines)).encode("iso-8859-1")

    @staticmethod
    def _read_headers(sock: socket.socket, max_size: int = 65536) -> Tuple[bytes, bytes]:
        """
        读取HTTP请求头，返回头部数据和剩余数据
        处理客户端连接异常和不完整请求
        """
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = b""
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    # 超时可能是正常的，客户端可能在等待
                    break
                except Exception:
                    # 其他异常，客户端可能断开连接
                    break
                if not chunk:
                    # 客户端关闭连接
                    break
                data += chunk
                if len(data) > max_size:
                    raise Exception("请求头过大")
        except Exception:
            # 读取过程中出现异常
            pass
            
        if b"\r\n\r\n" not in data:
            # 没有完整的HTTP头部，返回已读取的数据
            return data, b""
        idx = data.index(b"\r\n\r\n") + 4
        return data[:idx], data[idx:]

    def _relay_bidirectional(self, client: socket.socket, remote: socket.socket) -> None:
        try:
            sockets = [client, remote]
            while True:
                rlist, _, _ = select.select(sockets, [], [], 1.0)
                if not rlist:
                    if self._stop_event.is_set():
                        break
                    continue
                for s in rlist:
                    try:
                        data = s.recv(4096)
                    except Exception:
                        data = b""
                    if not data:
                        return
                    if s is client:
                        # 客户端到远程：上行
                        if self.traffic_stats:
                            self.traffic_stats.add_upload(len(data))
                        remote.sendall(data)
                    else:
                        # 远程到客户端：下行
                        if self.traffic_stats:
                            self.traffic_stats.add_download(len(data))
                        client.sendall(data)
        finally:
            try:
                remote.close()
            except Exception:
                pass


class PortForwardServer:
    """
    TCP端口转发服务器
    将本地端口的连接转发到指定的目标主机和端口
    """
    def __init__(
        self,
        bind_host: str = "0.0.0.0",
        bind_port: int = 8888,
        target_host: str = "127.0.0.1",
        target_port: int = 80,
        timeout: int = 10,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.bind_host = bind_host
        self.bind_port = int(bind_port)
        self.target_host = target_host
        self.target_port = int(target_port)
        # 使用界面设置的超时时间，不再强制限制外部IP的超时
        self.timeout = int(timeout)
        self.logger = logger or logging.getLogger("mproxy")
        
        # 记录超时设置信息
        if target_host != "127.0.0.1" and target_host != "localhost":
            self.logger.info(f"外部目标IP {target_host}，使用配置的连接超时 {self.timeout} 秒")

        self._server_socket: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._client_threads: list[threading.Thread] = []

    def start(self) -> None:
        """启动端口转发服务"""
        if self._accept_thread and self._accept_thread.is_alive():
            self.logger.warning("端口转发已在运行")
            return
        self._stop_event.clear()
        self._accept_thread = threading.Thread(target=self._serve_forever, name="PortForwardAccept", daemon=True)
        self._accept_thread.start()
        self.logger.info(f"端口转发启动: {self.bind_host}:{self.bind_port} -> {self.target_host}:{self.target_port}")

    def stop(self) -> None:
        """停止端口转发服务"""
        self._stop_event.set()
        try:
            if self._server_socket:
                try:
                    self._server_socket.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self._server_socket.close()
        except Exception as e:
            self.logger.debug(f"关闭端口转发服务器套接字异常: {e}")
        if self._accept_thread:
            self._accept_thread.join(timeout=2)
        for t in list(self._client_threads):
            if t.is_alive():
                t.join(timeout=2)
        self._client_threads.clear()
        self.logger.info("端口转发已停止")

    def _serve_forever(self) -> None:
        """服务器主循环，接受客户端连接"""
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket = srv
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.bind_host, self.bind_port))
            srv.listen(128)
            srv.settimeout(1.0)
            
            while not self._stop_event.is_set():
                try:
                    client_sock, client_addr = srv.accept()
                    self.logger.info(f"端口转发客户端连接: {client_addr}")
                    t = threading.Thread(
                        target=self._handle_client, 
                        args=(client_sock, client_addr), 
                        daemon=True
                    )
                    self._client_threads.append(t)
                    t.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if not self._stop_event.is_set():
                        self.logger.error(f"端口转发接受连接异常: {e}")
                    break
        except Exception as e:
            self.logger.error(f"端口转发服务器异常: {e}")

    def _handle_client(self, client: socket.socket, client_addr: Tuple[str, int]) -> None:
        """
        处理客户端连接，建立到目标服务器的连接并进行数据转发
        """
        client.settimeout(self.timeout)
        target_sock = None
        
        try:
            # 连接到目标服务器
            self.logger.info(f"端口转发尝试连接目标: {self.target_host}:{self.target_port}")
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.settimeout(self.timeout)
            
            # 尝试连接目标服务器
            try:
                target_sock.connect((self.target_host, self.target_port))
                self.logger.info(f"端口转发建立连接成功: {client_addr} -> {self.target_host}:{self.target_port}")
            except socket.timeout:
                self.logger.error(f"端口转发连接超时: {self.target_host}:{self.target_port} (超时时间: {self.timeout}秒)")
                raise
            except socket.gaierror as e:
                self.logger.error(f"端口转发DNS解析失败: {self.target_host} - {e}")
                raise
            except ConnectionRefusedError:
                self.logger.error(f"端口转发连接被拒绝: {self.target_host}:{self.target_port} (目标端口可能未开放)")
                raise
            except OSError as e:
                if "Network is unreachable" in str(e) or "No route to host" in str(e):
                    self.logger.error(f"端口转发网络不可达: {self.target_host}:{self.target_port} - {e}")
                elif "Permission denied" in str(e):
                    self.logger.error(f"端口转发权限被拒绝: {self.target_host}:{self.target_port} - {e}")
                else:
                    self.logger.error(f"端口转发网络错误: {self.target_host}:{self.target_port} - {e}")
                raise
            
            # 开始双向数据转发
            self._relay_bidirectional(client, target_sock)
            
        except Exception as e:
            self.logger.error(f"端口转发处理客户端 {client_addr} 异常: {e}")
            # 向客户端发送连接失败的响应（如果可能）
            try:
                if isinstance(e, (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError)):
                    # 对于连接错误，尝试关闭客户端连接
                    client.close()
            except Exception:
                pass
        finally:
            try:
                if target_sock:
                    target_sock.close()
                client.close()
            except Exception:
                pass
            self.logger.info(f"端口转发客户端 {client_addr} 连接关闭")

    def _relay_bidirectional(self, client: socket.socket, target: socket.socket) -> None:
        """
        双向数据转发
        在客户端和目标服务器之间转发数据
        """
        def forward_data(src: socket.socket, dst: socket.socket, direction: str) -> None:
            """单向数据转发"""
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        # 创建两个线程分别处理双向数据转发
        client_to_target = threading.Thread(
            target=forward_data, 
            args=(client, target, "client->target"), 
            daemon=True
        )
        target_to_client = threading.Thread(
            target=forward_data, 
            args=(target, client, "target->client"), 
            daemon=True
        )

        client_to_target.start()
        target_to_client.start()

        # 等待任一方向的转发结束
        client_to_target.join()
        target_to_client.join()


# ----------------------------
# Tkinter GUI Application
# ----------------------------
class ForwardRuleDialog:
    """
    端口转发规则配置对话框
    用于添加和编辑端口转发规则
    """
    def __init__(self, parent, title="端口转发规则", initial_values=None):
        self.result = None
        self.parent = parent
        
        # 创建对话框窗口
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x200")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        
        # 居中显示
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (200 // 2)
        self.dialog.geometry(f"400x200+{x}+{y}")
        
        # 创建主框架
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill="both", expand=True)
        
        # 转发端口
        ttk.Label(main_frame, text="转发端口:").grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.entry_forward_port = ttk.Entry(main_frame, width=20)
        self.entry_forward_port.grid(row=0, column=1, sticky="ew", pady=(0, 10), padx=(10, 0))
        
        # 目标主机
        ttk.Label(main_frame, text="目标主机:").grid(row=1, column=0, sticky="w", pady=(0, 10))
        self.entry_target_host = ttk.Entry(main_frame, width=20)
        self.entry_target_host.grid(row=1, column=1, sticky="ew", pady=(0, 10), padx=(10, 0))
        
        # 目标端口
        ttk.Label(main_frame, text="目标端口:").grid(row=2, column=0, sticky="w", pady=(0, 20))
        self.entry_target_port = ttk.Entry(main_frame, width=20)
        self.entry_target_port.grid(row=2, column=1, sticky="ew", pady=(0, 20), padx=(10, 0))
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=(10, 0))
        
        ttk.Button(button_frame, text="确定", command=self._on_ok).pack(side="left", padx=(0, 10))
        ttk.Button(button_frame, text="取消", command=self._on_cancel).pack(side="left")
        
        # 设置列权重
        main_frame.columnconfigure(1, weight=1)
        
        # 如果有初始值，填充到输入框
        if initial_values:
            forward_port, target_host, target_port = initial_values
            self.entry_forward_port.insert(0, str(forward_port))
            self.entry_target_host.insert(0, target_host)
            self.entry_target_port.insert(0, str(target_port))
        else:
            # 默认值
            self.entry_forward_port.insert(0, "8888")
            self.entry_target_host.insert(0, "127.0.0.1")
            self.entry_target_port.insert(0, "80")
        
        # 焦点设置到第一个输入框
        self.entry_forward_port.focus()
        self.entry_forward_port.select_range(0, tk.END)
        
        # 绑定回车键
        self.dialog.bind('<Return>', lambda e: self._on_ok())
        self.dialog.bind('<Escape>', lambda e: self._on_cancel())
        
        # 设置窗口关闭协议
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_cancel)
        
        # 使用grab_set()和wait_window()的正确组合
        self.dialog.grab_set()
        self.parent.wait_window(self.dialog)
    
    def _on_ok(self):
        """确定按钮处理"""
        try:
            forward_port = int(self.entry_forward_port.get().strip())
            target_host = self.entry_target_host.get().strip()
            target_port = int(self.entry_target_port.get().strip())
            
            # 验证输入
            if not (1 <= forward_port <= 65535):
                messagebox.showerror("错误", "转发端口必须在1-65535之间")
                return
            
            if not target_host:
                messagebox.showerror("错误", "目标主机不能为空")
                return
            
            if not (1 <= target_port <= 65535):
                messagebox.showerror("错误", "目标端口必须在1-65535之间")
                return
            
            self.result = (forward_port, target_host, target_port)
            self.dialog.destroy()
            
        except ValueError:
            messagebox.showerror("错误", "请输入有效的端口号")
    
    def _on_cancel(self):
        """取消按钮处理"""
        self.dialog.destroy()


class MProxyApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("MPROXY 多功能代理")
        # Set fixed initial window size
        self.root.geometry("900x600")
        # Disable maximize, allow minimize
        self.root.resizable(False, False)

        # Set icon: prefer ICO file if available, fallback to generated PhotoImage
        try:
            ico_path = os.path.join(os.path.dirname(__file__), "assets", "icon.ico")
            if os.path.exists(ico_path):
                self.root.iconbitmap(ico_path)
            else:
                icon = generate_app_icon()
                self.root.iconphoto(True, icon)
        except Exception:
            # Graceful fallback
            try:
                icon = generate_app_icon()
                self.root.iconphoto(True, icon)
            except Exception:
                pass

        # Configure grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        main = ttk.Frame(self.root, padding=6)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(2, weight=1)  # 让日志区域可以扩展

        # === 顶部区域：代理配置和监控面板并排 ===
        # 创建一个容器来放置两个并排的框架
        top_container = ttk.Frame(main)
        top_container.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        top_container.columnconfigure(0, weight=1)
        top_container.columnconfigure(1, weight=1)

        # === 代理服务配置 (左侧50%) ===
        proxy_frame = ttk.LabelFrame(top_container, text="代理服务配置", padding=6)
        proxy_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 2))
        for i in range(4):
            proxy_frame.columnconfigure(i, weight=1)

        # Inputs - 紧凑布局
        ttk.Label(proxy_frame, text="监听地址").grid(row=0, column=0, sticky="w", padx=(0, 4))
        self.entry_host = ttk.Entry(proxy_frame, width=12)
        self.entry_host.insert(0, "0.0.0.0")
        self.entry_host.grid(row=0, column=1, sticky="ew", padx=(0, 8))

        ttk.Label(proxy_frame, text="监听端口").grid(row=0, column=2, sticky="w", padx=(0, 4))
        self.entry_port = ttk.Entry(proxy_frame, width=8)
        self.entry_port.insert(0, "1080")
        self.entry_port.grid(row=0, column=3, sticky="ew")

        ttk.Label(proxy_frame, text="上游代理地址(可选)").grid(row=1, column=0, sticky="w", padx=(0, 4), pady=(4, 0))
        self.entry_up_host = ttk.Entry(proxy_frame, width=12)
        self.entry_up_host.grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=(4, 0))

        ttk.Label(proxy_frame, text="上游代理端口").grid(row=1, column=2, sticky="w", padx=(0, 4), pady=(4, 0))
        self.entry_up_port = ttk.Entry(proxy_frame, width=8)
        self.entry_up_port.insert(0, "1080")
        self.entry_up_port.grid(row=1, column=3, sticky="ew", pady=(4, 0))

        # 第三行：超时和协议
        ttk.Label(proxy_frame, text="连接超时(秒)").grid(row=2, column=0, sticky="w", padx=(0, 4), pady=(4, 0))
        self.entry_timeout = ttk.Entry(proxy_frame, width=8)
        self.entry_timeout.insert(0, "10")
        self.entry_timeout.grid(row=2, column=1, sticky="ew", padx=(0, 8), pady=(4, 0))

        ttk.Label(proxy_frame, text="协议").grid(row=2, column=2, sticky="w", padx=(0, 4), pady=(4, 0))
        self.protocol_var = tk.StringVar(value="SOCKS5")
        self.combo_protocol = ttk.Combobox(proxy_frame, textvariable=self.protocol_var, values=["SOCKS5", "HTTP"], state="readonly", width=10)
        self.combo_protocol.grid(row=2, column=3, sticky="ew", pady=(4, 0))

        # === 运行状态和流量监控 (右侧50%) ===
        monitor_frame = ttk.LabelFrame(top_container, text="运行状态与流量监控", padding=6)
        monitor_frame.grid(row=0, column=1, sticky="nsew", padx=(2, 0))
        monitor_frame.columnconfigure(0, weight=1)
        monitor_frame.columnconfigure(1, weight=1)

        # 代理运行状态
        ttk.Label(monitor_frame, text="状态:", font=("", 9, "bold")).grid(row=0, column=0, sticky="w")
        self.status_label = ttk.Label(monitor_frame, text="未启动", foreground="gray")
        self.status_label.grid(row=0, column=1, sticky="w", padx=(4, 0))

        # 实时速度 - 紧凑布局
        ttk.Label(monitor_frame, text="上行:", font=("", 9)).grid(row=1, column=0, sticky="w", pady=(6, 2))
        self.upload_speed_label = ttk.Label(monitor_frame, text="0 B/s", font=("", 9))
        self.upload_speed_label.grid(row=1, column=1, sticky="w", padx=(4, 0), pady=(6, 2))

        ttk.Label(monitor_frame, text="下行:", font=("", 9)).grid(row=2, column=0, sticky="w", pady=(2, 2))
        self.download_speed_label = ttk.Label(monitor_frame, text="0 B/s", font=("", 9))
        self.download_speed_label.grid(row=2, column=1, sticky="w", padx=(4, 0), pady=(2, 2))

        # 分隔线
        ttk.Separator(monitor_frame, orient="horizontal").grid(row=3, column=0, columnspan=2, sticky="ew", pady=4)

        # 累计流量
        ttk.Label(monitor_frame, text="累计上行:", font=("", 9)).grid(row=4, column=0, sticky="w", pady=(2, 2))
        self.upload_total_label = ttk.Label(monitor_frame, text="0 B", font=("", 9))
        self.upload_total_label.grid(row=4, column=1, sticky="w", padx=(4, 0), pady=(2, 2))

        ttk.Label(monitor_frame, text="累计下行:", font=("", 9)).grid(row=5, column=0, sticky="w", pady=(2, 0))
        self.download_total_label = ttk.Label(monitor_frame, text="0 B", font=("", 9))
        self.download_total_label.grid(row=5, column=1, sticky="w", padx=(4, 0), pady=(2, 0))

        # === 端口转发配置 ===
        forward_frame = ttk.LabelFrame(main, text="端口转发配置", padding=6)
        forward_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=4)
        forward_frame.columnconfigure(0, weight=1)

        # 启用端口转发复选框和按钮在同一行
        controls_frame = ttk.Frame(forward_frame)
        controls_frame.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        controls_frame.columnconfigure(0, weight=1)

        self.forward_enabled_var = tk.BooleanVar(value=False)
        self.check_forward_enabled = ttk.Checkbutton(controls_frame, text="启用端口转发", variable=self.forward_enabled_var, command=self._toggle_forward_controls)
        self.check_forward_enabled.grid(row=0, column=0, sticky="w")

        # 按钮放在右侧
        buttons_frame = ttk.Frame(controls_frame)
        buttons_frame.grid(row=0, column=1, sticky="e")
        
        self.btn_add_rule = ttk.Button(buttons_frame, text="添加规则", command=self._add_forward_rule)
        self.btn_edit_rule = ttk.Button(buttons_frame, text="编辑规则", command=self._edit_forward_rule)
        self.btn_delete_rule = ttk.Button(buttons_frame, text="删除规则", command=self._delete_forward_rule)
        
        self.btn_add_rule.grid(row=0, column=0, padx=(0, 2))
        self.btn_edit_rule.grid(row=0, column=1, padx=2)
        self.btn_delete_rule.grid(row=0, column=2, padx=(2, 0))

        # 端口转发规则列表 - 减少高度
        rules_frame = ttk.Frame(forward_frame)
        rules_frame.grid(row=1, column=0, sticky="ew")
        rules_frame.columnconfigure(0, weight=1)

        # 创建Treeview来显示端口转发规则 - 减少高度
        columns = ("forward_port", "target_host", "target_port", "status")
        self.forward_rules_tree = ttk.Treeview(rules_frame, columns=columns, show="headings", height=4)
        
        # 设置列标题和宽度
        self.forward_rules_tree.heading("forward_port", text="转发端口")
        self.forward_rules_tree.heading("target_host", text="目标主机")
        self.forward_rules_tree.heading("target_port", text="目标端口")
        self.forward_rules_tree.heading("status", text="状态")
        
        self.forward_rules_tree.column("forward_port", width=80, anchor="center")
        self.forward_rules_tree.column("target_host", width=120, anchor="center")
        self.forward_rules_tree.column("target_port", width=80, anchor="center")
        self.forward_rules_tree.column("status", width=80, anchor="center")
        
        # 添加滚动条
        rules_scrollbar = ttk.Scrollbar(rules_frame, orient="vertical", command=self.forward_rules_tree.yview)
        self.forward_rules_tree.configure(yscrollcommand=rules_scrollbar.set)
        
        self.forward_rules_tree.grid(row=0, column=0, sticky="ew")
        rules_scrollbar.grid(row=0, column=1, sticky="ns")

        # 端口转发规则数据存储
        self.forward_rules = []  # 存储转发规则的列表
        
        # 初始状态禁用端口转发控件
        self._toggle_forward_controls()

        # 启动/停止按钮 - 放在日志区域上方
        button_frame = ttk.Frame(main)
        button_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(4, 4))
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)

        self.btn_start = ttk.Button(button_frame, text="启动", command=self.on_start)
        self.btn_stop = ttk.Button(button_frame, text="停止", command=self.on_stop, state=tk.DISABLED)
        self.btn_start.grid(row=0, column=0, sticky="ew", padx=(0, 2))
        self.btn_stop.grid(row=0, column=1, sticky="ew", padx=(2, 0))

        # Log window - 调整高度以适应600px窗口
        self.log_text = scrolledtext.ScrolledText(main, height=15, bg="black", fg="#C0FFC0", insertbackground="#C0FFC0")
        self.log_text.configure(font=("Consolas", 9))
        self.log_text.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(0, 0))
        main.rowconfigure(3, weight=1)

        # Logger
        self.logger = logging.getLogger("mproxy")
        self.logger.setLevel(logging.INFO)
        fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(threadName)s] %(message)s")
        handler = TkTextHandler(self.log_text)
        handler.setFormatter(fmt)
        self.logger.handlers.clear()
        self.logger.addHandler(handler)

        # Traffic statistics
        self.traffic_stats = TrafficStats()
        self._update_timer = None

        # Server instances
        self.proxy_server = None
        self.forward_server = None

        # Close protocol
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Load and apply configuration
        self.load_and_apply_config()

    def _format_bytes(self, bytes_count: int) -> str:
        """格式化字节数为可读形式"""
        if bytes_count < 1024:
            return f"{bytes_count} B"
        elif bytes_count < 1024 * 1024:
            return f"{bytes_count / 1024:.2f} KB"
        elif bytes_count < 1024 * 1024 * 1024:
            return f"{bytes_count / (1024 * 1024):.2f} MB"
        else:
            return f"{bytes_count / (1024 * 1024 * 1024):.2f} GB"

    def _format_speed(self, bytes_per_second: float) -> str:
        """格式化速度为可读形式"""
        if bytes_per_second < 1024:
            return f"{bytes_per_second:.2f} B/s"
        elif bytes_per_second < 1024 * 1024:
            return f"{bytes_per_second / 1024:.2f} KB/s"
        else:
            return f"{bytes_per_second / (1024 * 1024):.2f} MB/s"

    def _update_traffic_display(self):
        """更新流量显示"""
        if self.proxy_server:
            # 更新速度统计
            self.traffic_stats.update_speed()
            stats = self.traffic_stats.get_stats()

            # 更新实时速度
            self.upload_speed_label.config(text=self._format_speed(stats['upload_speed']))
            self.download_speed_label.config(text=self._format_speed(stats['download_speed']))

            # 更新累计流量
            self.upload_total_label.config(text=self._format_bytes(stats['upload_bytes']))
            self.download_total_label.config(text=self._format_bytes(stats['download_bytes']))

            # 继续更新
            self._update_timer = self.root.after(1000, self._update_traffic_display)
        else:
            # 服务已停止，重置显示
            self._update_timer = None

    def _toggle_forward_controls(self) -> None:
        """切换端口转发控件的启用/禁用状态"""
        enabled = self.forward_enabled_var.get()
        state = "normal" if enabled else "disabled"
        
        # 更新按钮状态
        self.btn_add_rule.config(state=state)
        self.btn_edit_rule.config(state=state)
        self.btn_delete_rule.config(state=state)
        
        # 更新树形视图状态
        if enabled:
            self.forward_rules_tree.configure(selectmode="extended")
        else:
            self.forward_rules_tree.configure(selectmode="none")

    def _add_forward_rule(self) -> None:
        """
        添加新的端口转发规则
        弹出对话框让用户输入转发配置
        """
        dialog = ForwardRuleDialog(self.root, title="添加端口转发规则")
        if dialog.result:
            forward_port, target_host, target_port = dialog.result
            
            # 检查端口是否已被使用
            for rule in self.forward_rules:
                if rule["forward_port"] == forward_port:
                    messagebox.showerror("错误", f"端口 {forward_port} 已被使用")
                    return
            
            # 添加新规则
            rule = {
                "forward_port": forward_port,
                "target_host": target_host,
                "target_port": target_port,
                "server": None,  # PortForwardServer实例
                "status": "已停止"
            }
            self.forward_rules.append(rule)
            self._refresh_forward_rules_display()
            self.logger.info(f"添加端口转发规则: {forward_port} -> {target_host}:{target_port}")

    def _edit_forward_rule(self) -> None:
        """
        编辑选中的端口转发规则
        """
        selection = self.forward_rules_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要编辑的规则")
            return
        
        item_id = selection[0]
        rule_index = int(self.forward_rules_tree.item(item_id)["tags"][0])
        rule = self.forward_rules[rule_index]
        
        # 如果规则正在运行，不允许编辑
        if rule["status"] == "运行中":
            messagebox.showwarning("警告", "无法编辑正在运行的规则，请先停止服务")
            return
        
        dialog = ForwardRuleDialog(
            self.root, 
            title="编辑端口转发规则",
            initial_values=(rule["forward_port"], rule["target_host"], rule["target_port"])
        )
        
        if dialog.result:
            forward_port, target_host, target_port = dialog.result
            
            # 检查端口是否被其他规则使用
            for i, other_rule in enumerate(self.forward_rules):
                if i != rule_index and other_rule["forward_port"] == forward_port:
                    messagebox.showerror("错误", f"端口 {forward_port} 已被其他规则使用")
                    return
            
            # 更新规则
            rule["forward_port"] = forward_port
            rule["target_host"] = target_host
            rule["target_port"] = target_port
            self._refresh_forward_rules_display()
            self.logger.info(f"编辑端口转发规则: {forward_port} -> {target_host}:{target_port}")

    def _delete_forward_rule(self) -> None:
        """
        删除选中的端口转发规则
        """
        selection = self.forward_rules_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要删除的规则")
            return
        
        if messagebox.askyesno("确认", "确定要删除选中的端口转发规则吗？"):
            # 获取所有选中的规则索引
            indices_to_delete = []
            for item_id in selection:
                rule_index = int(self.forward_rules_tree.item(item_id)["tags"][0])
                indices_to_delete.append(rule_index)
            
            # 按索引倒序删除，避免索引变化问题
            for rule_index in sorted(indices_to_delete, reverse=True):
                rule = self.forward_rules[rule_index]
                
                # 如果规则正在运行，先停止
                if rule["server"] and rule["status"] == "运行中":
                    rule["server"].stop()
                    rule["server"] = None
                
                # 删除规则
                del self.forward_rules[rule_index]
                self.logger.info(f"删除端口转发规则: {rule['forward_port']} -> {rule['target_host']}:{rule['target_port']}")
            
            self._refresh_forward_rules_display()

    def _refresh_forward_rules_display(self) -> None:
        """
        刷新端口转发规则显示
        """
        # 清空现有显示
        for item in self.forward_rules_tree.get_children():
            self.forward_rules_tree.delete(item)
        
        # 重新添加所有规则
        for i, rule in enumerate(self.forward_rules):
            self.forward_rules_tree.insert(
                "", "end",
                values=(
                    rule["forward_port"],
                    rule["target_host"],
                    rule["target_port"],
                    rule["status"]
                ),
                tags=(str(i),)  # 使用索引作为标签
            )

    def load_and_apply_config(self) -> None:
        """加载配置文件并应用到UI控件"""
        config = load_config()
        
        # 清空并设置各个输入框的值
        self.entry_host.delete(0, tk.END)
        self.entry_host.insert(0, config.get("bind_host", "0.0.0.0"))
        
        self.entry_port.delete(0, tk.END)
        self.entry_port.insert(0, str(config.get("bind_port", 1080)))
        
        self.entry_up_host.delete(0, tk.END)
        self.entry_up_host.insert(0, config.get("upstream_host", ""))
        
        self.entry_up_port.delete(0, tk.END)
        self.entry_up_port.insert(0, str(config.get("upstream_port", 1080)))
        
        self.entry_timeout.delete(0, tk.END)
        self.entry_timeout.insert(0, str(config.get("timeout", 10)))
        
        # 设置协议选择
        self.protocol_var.set(config.get("protocol", "SOCKS5"))
        
        # 设置端口转发配置
        self.forward_enabled_var.set(config.get("forward_enabled", False))
        
        # 加载端口转发规则
        self.forward_rules = []
        forward_rules_config = config.get("forward_rules", [])
        for rule_config in forward_rules_config:
            rule = {
                "forward_port": rule_config.get("forward_port", 8888),
                "target_host": rule_config.get("target_host", "127.0.0.1"),
                "target_port": rule_config.get("target_port", 80),
                "server": None,
                "status": "已停止"
            }
            self.forward_rules.append(rule)
        
        # 刷新端口转发规则显示
        self._refresh_forward_rules_display()
        
        # 更新端口转发控件状态
        self._toggle_forward_controls()

    def collect_current_config(self) -> dict:
        """收集当前UI中的配置"""
        # 收集端口转发规则（不包含运行时状态）
        forward_rules_config = []
        for rule in self.forward_rules:
            rule_config = {
                "forward_port": rule["forward_port"],
                "target_host": rule["target_host"],
                "target_port": rule["target_port"]
            }
            forward_rules_config.append(rule_config)
        
        config = {
            "protocol": self.protocol_var.get(),
            "bind_host": self.entry_host.get().strip(),
            "bind_port": int(self.entry_port.get().strip()) if self.entry_port.get().strip().isdigit() else 1080,
            "upstream_host": self.entry_up_host.get().strip(),
            "upstream_port": int(self.entry_up_port.get().strip()) if self.entry_up_port.get().strip().isdigit() else 1080,
            "timeout": int(self.entry_timeout.get().strip()) if self.entry_timeout.get().strip().isdigit() else 10,
            # 端口转发配置
            "forward_enabled": self.forward_enabled_var.get(),
            "forward_rules": forward_rules_config
        }
        return config

    def _set_controls_state(self, enabled: bool) -> None:
        """
        设置所有配置控件的启用/禁用状态
        
        Args:
            enabled: True为启用，False为禁用
        """
        state = tk.NORMAL if enabled else tk.DISABLED
        
        # 代理服务配置控件
        self.entry_host.configure(state=state)
        self.entry_port.configure(state=state)
        self.entry_up_host.configure(state=state)
        self.entry_up_port.configure(state=state)
        self.entry_timeout.configure(state=state)
        self.combo_protocol.configure(state="readonly" if enabled else tk.DISABLED)
        
        # 端口转发配置控件
        self.check_forward_enabled.configure(state=state)
        
        # 端口转发管理按钮的状态需要根据是否启用端口转发来决定
        if enabled:
            # 如果重新启用，需要根据端口转发是否启用来设置按钮状态
            self._toggle_forward_controls()
        else:
            # 如果禁用，直接禁用所有端口转发相关按钮
            self.btn_add_rule.configure(state=tk.DISABLED)
            self.btn_edit_rule.configure(state=tk.DISABLED)
            self.btn_delete_rule.configure(state=tk.DISABLED)
            # 禁用Treeview的选择功能
            self.forward_rules_tree.configure(selectmode="none" if not enabled else "browse")

    def on_start(self) -> None:
        """启动代理服务和端口转发服务"""
        # 立即禁用启动按钮，启用停止按钮
        self.btn_start.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)
        
        # 在后台线程中执行启动逻辑，避免阻塞UI
        import threading
        start_thread = threading.Thread(target=self._start_services_background, daemon=True)
        start_thread.start()
    
    def _start_services_background(self) -> None:
        """
        在后台线程中启动服务，避免阻塞UI线程
        """
        try:
            bind_host = self.entry_host.get().strip()
            bind_port = int(self.entry_port.get().strip())
            timeout = int(self.entry_timeout.get().strip())
            up_host = self.entry_up_host.get().strip()
            up_port_raw = self.entry_up_port.get().strip()
            up_port = int(up_port_raw) if up_host and up_port_raw else None
        except ValueError:
            self.root.after(0, lambda: messagebox.showerror("错误", "请输入有效端口和超时"))
            # 恢复按钮状态
            self.root.after(0, lambda: self.btn_start.configure(state=tk.NORMAL))
            self.root.after(0, lambda: self.btn_stop.configure(state=tk.DISABLED))
            return

        try:
            # 重置流量统计
            self.traffic_stats.reset()

            # 保存当前配置
            current_config = self.collect_current_config()
            save_config(current_config)

            # 在主线程中禁用所有配置控件
            self.root.after(0, lambda: self._set_controls_state(False))

            # 启动代理服务
            protocol = (self.protocol_var.get() or "SOCKS5").upper()
            if protocol == "HTTP":
                self.proxy_server = HTTPProxyServer(
                    bind_host=bind_host,
                    bind_port=bind_port,
                    upstream_host=up_host if up_host else None,
                    upstream_port=up_port,
                    timeout=timeout,
                    logger=self.logger,
                    traffic_stats=self.traffic_stats,
                )
            else:
                self.proxy_server = Socks5Server(
                    bind_host=bind_host,
                    bind_port=bind_port,
                    upstream_host=up_host if up_host else None,
                    upstream_port=up_port,
                    timeout=timeout,
                    logger=self.logger,
                    traffic_stats=self.traffic_stats,
                )

            # 启动代理服务
            self.proxy_server.start()
            self.logger.info(f"代理服务已启动: {protocol} {bind_host}:{bind_port}")

            # 更新状态标签
            self.root.after(0, lambda: self.status_label.config(text="运行中", foreground="green"))

            # 启动流量监控更新
            self.root.after(0, self._update_traffic_display)
            
            # 启动端口转发服务（如果启用）
            if self.forward_enabled_var.get():
                failed_rules = []
                
                # 检查端口冲突
                proxy_port = int(self.entry_port.get().strip())
                for rule in self.forward_rules:
                    if rule["forward_port"] == proxy_port:
                        error_msg = f"端口转发端口 {rule['forward_port']} 与代理服务端口冲突"
                        self.logger.error(error_msg)
                        rule["status"] = "端口冲突"
                        failed_rules.append(f"{rule['forward_port']} -> {rule['target_host']}:{rule['target_port']} (与代理服务端口冲突)")
                        continue
                
                for rule in self.forward_rules:
                    # 跳过已经标记为冲突的规则
                    if rule.get("status") == "端口冲突":
                        continue
                        
                    try:
                        # 创建端口转发服务器
                        # 端口转发服务始终绑定到0.0.0.0以确保跨平台兼容性
                        server = PortForwardServer(
                            bind_host="0.0.0.0",
                            bind_port=rule["forward_port"],
                            target_host=rule["target_host"],
                            target_port=rule["target_port"],
                            timeout=timeout,
                            logger=self.logger,
                        )
                        server.start()
                        
                        # 更新规则状态
                        rule["server"] = server
                        rule["status"] = "运行中"
                        
                        self.logger.info(f"端口转发服务已启动: {bind_host}:{rule['forward_port']} -> {rule['target_host']}:{rule['target_port']}")
                        
                    except Exception as e:
                        error_msg = f"端口转发服务启动失败 {rule['forward_port']}: {e}"
                        self.logger.error(error_msg)
                        
                        # 记录详细的错误信息
                        if "Address already in use" in str(e) or "地址已在使用" in str(e):
                            self.logger.error(f"端口 {rule['forward_port']} 已被其他程序占用")
                        elif "Permission denied" in str(e) or "拒绝访问" in str(e):
                            self.logger.error(f"端口 {rule['forward_port']} 权限不足，可能需要管理员权限")
                        elif "Cannot assign requested address" in str(e):
                            self.logger.error(f"无法分配请求的地址，检查网络配置")
                        
                        rule["status"] = "启动失败"
                        failed_rules.append(f"{rule['forward_port']} -> {rule['target_host']}:{rule['target_port']} ({str(e)})")
                
                # 在主线程中刷新显示
                self.root.after(0, self._refresh_forward_rules_display)
                
                # 如果有失败的规则，在主线程中显示警告
                if failed_rules:
                    self.root.after(0, lambda: messagebox.showwarning("警告", f"以下端口转发规则启动失败:\n" + "\n".join(failed_rules)))
            
        except Exception as e:
            error_msg = f"启动失败: {str(e)}"
            self.logger.error(error_msg)
            self.root.after(0, lambda: messagebox.showerror("启动失败", f"代理服务启动失败: {str(e)}"))
            # 恢复按钮状态
            self.root.after(0, lambda: self.btn_start.configure(state=tk.NORMAL))
            self.root.after(0, lambda: self.btn_stop.configure(state=tk.DISABLED))
            self.root.after(0, lambda: self._set_controls_state(True))

    def on_stop(self) -> None:
        """停止代理服务和端口转发服务"""
        # 停止流量更新定时器
        if self._update_timer:
            self.root.after_cancel(self._update_timer)
            self._update_timer = None

        # 停止代理服务
        if self.proxy_server:
            self.proxy_server.stop()
            self.proxy_server = None
            self.logger.info("代理服务已停止")

        # 更新状态标签
        self.status_label.config(text="未启动", foreground="gray")

        # 重置流量显示
        self.upload_speed_label.config(text="0 B/s")
        self.download_speed_label.config(text="0 B/s")
        self.upload_total_label.config(text="0 B")
        self.download_total_label.config(text="0 B")

        # 停止所有端口转发服务
        for rule in self.forward_rules:
            if rule["server"] and rule["status"] == "运行中":
                try:
                    rule["server"].stop()
                    rule["status"] = "已停止"
                    self.logger.info(f"端口转发服务已停止: {rule['forward_port']} -> {rule['target_host']}:{rule['target_port']}")
                except Exception as e:
                    self.logger.error(f"停止端口转发服务失败 {rule['forward_port']}: {e}")
                    rule["status"] = "停止失败"
                finally:
                    rule["server"] = None

        # 刷新显示
        self._refresh_forward_rules_display()

        # 重新启用所有配置控件
        self._set_controls_state(True)

        # 保存当前配置
        current_config = self.collect_current_config()
        save_config(current_config)

        self.btn_start.configure(state=tk.NORMAL)
        self.btn_stop.configure(state=tk.DISABLED)

    def on_close(self) -> None:
        try:
            # 保存配置后关闭
            current_config = self.collect_current_config()
            save_config(current_config)
            self.on_stop()
        except Exception:
            pass
        self.root.destroy()


def generate_app_icon(size: int = 64) -> tk.PhotoImage:
    """Draw a simple icon for the application using PhotoImage."""
    img = tk.PhotoImage(width=size, height=size)
    # Background
    for y in range(size):
        img.put("#0B1A2A", to=(0, y, size, y+1))
    cx, cy = size // 2, size // 2
    r = size // 2 - 4
    # Blue circle
    for y in range(size):
        for x in range(size):
            dx, dy = x - cx, y - cy
            if dx*dx + dy*dy <= r*r:
                img.put("#2D7FFF", to=(x, y))
    # Right arrow (proxy symbol)
    arrow_color = "#FFFFFF"
    ax0, ay0 = cx - r//2, cy - 8
    ax1, ay1 = cx + r//2, cy
    ax2, ay2 = cx - r//2, cy + 8
    # Fill triangle
    for y in range(ay0, ay2 + 1):
        # Linear interpolation for triangle edges
        if y <= ay1:
            # Upper part
            t = (y - ay0) / max(1, (ay1 - ay0))
            x_start = int(ax0 + t * (ax1 - ax0))
            x_end = int(ax0 + t * (ax2 - ax0))
        else:
            # Lower part
            t = (y - ay1) / max(1, (ay2 - ay1))
            x_start = int(ax1 + t * (ax2 - ax1))
            x_end = int(ax2)
        if x_start > x_end:
            x_start, x_end = x_end, x_start
        for x in range(x_start, x_end + 1):
            img.put(arrow_color, to=(x, y))
    return img


def main() -> None:
    # Root logger config (also routed to TkTextHandler)
    logging.basicConfig(level=logging.INFO)
    root = tk.Tk()
    app = MProxyApp(root)
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"程序启动失败: {e}", file=sys.stderr)