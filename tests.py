import socket
import struct
import time
import subprocess
import sys
import os
import signal

SOCKS5_TIMEOUT = 1
SERVER_BIN = "./socks5"
BASE_PORT = 1090

def wait_for_port(port, timeout=2):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(('localhost', port), timeout=0.1):
                return True
        except (ConnectionRefusedError, socket.timeout):
            time.sleep(0.1)
    return False

def run_test_case(name, server_args, test_func):
    print(f"TEST: {name} ... ", end='', flush=True)
    port = BASE_PORT + (os.getpid() % 1000) # Simple collision avoidance
    # override port in args if present, or add it
    final_args = [SERVER_BIN, "--port", str(port)] + server_args
    
    proc = subprocess.Popen(final_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_for_port(port):
            print("FAIL (Server failed to start)")
            # Try to capture stderr if it failed quickly
            return False
            
        try:
            test_func(port)
            print("PASS")
            return True
        except Exception as e:
            print(f"FAIL ({e})")
            return False
    finally:
        proc.terminate()
        proc.wait()

def connect_socks5(port, methods=[0x00], auth_data=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(SOCKS5_TIMEOUT)
    s.connect(('localhost', port))
    
    # 1. Handshake
    # Ver 5, NMethods, Methods...
    msg = struct.pack('!BB', 5, len(methods)) + bytes(methods)
    s.sendall(msg)
    
    # Recv Method
    reply = s.recv(2)
    if len(reply) != 2 or reply[0] != 5:
        s.close()
        raise Exception(f"Invalid handshake reply: {reply}")
    
    method = reply[1]
    
    if method == 0xFF: # No Acceptable Methods
        return s, method
        
    if method == 0x02: # User/Pass
        if not auth_data:
            s.close()
            raise Exception("Server requested Auth, but none provided")
        
        user, password = auth_data
        # Auth Ver 1, ULen, User, PLen, Pass
        # Note: RFC 1929 Ver is 0x01
        msg = struct.pack('!BB', 1, len(user)) + user.encode() + struct.pack('!B', len(password)) + password.encode()
        s.sendall(msg)
        
        auth_reply = s.recv(2)
        if len(auth_reply) != 2 or auth_reply[1] != 0x00:
            s.close()
            raise Exception("Authentication Failed")
            
    elif method == 0x00:
        pass # No Auth
    else:
        s.close()
        raise Exception(f"Unexpected method: {method}")
        
    return s, method

def test_no_auth(port):
    s, method = connect_socks5(port, methods=[0x00])
    assert method == 0x00
    s.close()

def test_auth_success(port):
    s, method = connect_socks5(port, methods=[0x02], auth_data=("user", "pass"))
    assert method == 0x02
    s.close()

def test_auth_failure(port):
    try:
        connect_socks5(port, methods=[0x02], auth_data=("user", "wrongfail"))
    except Exception as e:
        if "Authentication Failed" in str(e):
            return
    raise Exception("Should have failed auth")

def test_auth_required_header_check(port):
    # Client offers NoAuth (0x00) only
    # Server requires Auth
    # Should select 0xFF
    s, method = connect_socks5(port, methods=[0x00])
    if method != 0xFF:
         raise Exception(f"Server should have rejected NoAuth (got {method})")
    s.close()
         
def test_connect_google(port):
    # Authenticate (if needed? This test assumes no auth for simplicity or needs valid auth)
    # We'll treat this as "Basic Connectivity" no auth
    s, _ = connect_socks5(port, methods=[0x00])
    # Connect to example.com:80 (IPv4: 93.184.216.34)
    # just sending the packet structure, not validating real connection response too deeply here
    # 0x05, 0x01(CONNECT), 0x00, 0x01(IPV4), 127.0.0.1, port 0
    cmd = b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', 1234)
    s.sendall(cmd)
    reply = s.recv(10)
    assert reply[1] == 0x00 or reply[1] == 0x04 or reply[1] == 0x03 # Success or Host Unreachable etc.
    s.close()

if __name__ == "__main__":
    # 1. Test Standard No Auth (Old behavior)
    run_test_case("Basic No Auth", [], test_no_auth)
    
    # 2. Test Auth - Valid
    run_test_case("Auth Success", ["--user", "user:pass"], test_auth_success)
    
    # 3. Test Auth - Invalid Pass
    run_test_case("Auth Fail", ["--user", "user:pass"], test_auth_failure)
    
    # 4. Test Enforced Auth (Client sends NoAuth)
    run_test_case("Auth Enforced", ["--user", "user:pass"], test_auth_required_header_check)

    # 5. CLI flag parsing checks
    run_test_case("Mixed Flags", ["-b", "127.0.0.1"], test_no_auth)

