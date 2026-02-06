import socket
import struct
import time
import threading
import sys
import subprocess

SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_TIMEOUT = 1

def test_handshake_no_auth(host='localhost', port=1080):
    print("Testing Handshake (No Auth)... ", end='')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKS5_TIMEOUT)
    try:
        s.connect((host, port))
        # Send version 5, 1 auth method (0x00 - No Auth)
        s.sendall(b'\x05\x01\x00')
        data = s.recv(2)
        assert len(data) == 2
        assert data[0] == 0x05
        assert data[1] == 0x00 # Selected No Auth
        print("PASS")
    except Exception as e:
        print(f"FAIL: {e}")
    finally:
        s.close()
        
def test_connect_ipv4(host='localhost', port=1080, target_host='8.8.8.8', target_port=53):
    print("Testing CONNECT (IPv4)... ", end='')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKS5_TIMEOUT)
    try:
        s.connect((host, port))
        s.sendall(b'\x05\x01\x00')
        s.recv(2)
        
        # CMD CONNECT (0x01) to IPv4
        cmd = b'\x05\x01\x00\x01' + socket.inet_aton(target_host) + struct.pack('!H', target_port)
        s.sendall(cmd)
        
        reply = s.recv(10)
        assert len(reply) >= 10
        assert reply[1] == 0x00 # Succeeded
        
        # Verify BND.ADDR is NOT 0.0.0.0 if possible (though on some setups it might return 0.0.0.0 if not bound specifically)
        # But we at least check structure
        bnd_addr = socket.inet_ntoa(reply[4:8])
        bnd_port = struct.unpack('!H', reply[8:10])[0]
        # print(f"(Bound: {bnd_addr}:{bnd_port}) ", end='')
        
        print("PASS")
    except Exception as e:
        print(f"FAIL: {e}")
    finally:
        s.close()

def test_unsupported_cmd(host='localhost', port=1080):
    print("Testing Unsupported CMD (BIND)... ", end='')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKS5_TIMEOUT)
    try:
        s.connect((host, port))
        s.sendall(b'\x05\x01\x00')
        s.recv(2)
        
        # CMD BIND (0x02)
        cmd = b'\x05\x02\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', 0)
        s.sendall(cmd)
        
        reply = s.recv(10)
        assert len(reply) >= 4
        assert reply[1] == 0x07 # Command not supported
        print("PASS")
    except Exception as e:
        print(f"FAIL: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 1080
    
    # Simple check if server is up
    try:
        test_handshake_no_auth(port=port)
        test_connect_ipv4(port=port)
        test_unsupported_cmd(port=port)
    except ConnectionRefusedError:
        print("Could not connect to server. Is it running?")
        sys.exit(1)
