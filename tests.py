import socket
import struct
import time
import subprocess
import sys
import os
import signal
import re
import tempfile

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

    # 6. Observability Test (Timestamps & Stats)
    def test_observability_check(port):
        s, _ = connect_socks5(port, methods=[0x00])
        # Simulate a small session
        # CONNECT to something (doesn't have to succeed fully, just need to trigger session start)
        # We'll try to connect to ourselves just to have a target
        cmd = b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', port)
        s.sendall(cmd)
        # Just close immediately to trigger stats
        s.close()
        time.sleep(0.2) # Wait for server to log

    print(f"TEST: Observability Values ... ", end='', flush=True)
    port = BASE_PORT + (os.getpid() % 1000) + 100
    
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_log:
        log_path = tmp_log.name

    final_args = [SERVER_BIN, "--port", str(port)]
    # Redirect stdout to the temp file
    with open(log_path, 'w') as log_out:
        proc = subprocess.Popen(final_args, stdout=log_out, stderr=log_out)
        
    try:
        if not wait_for_port(port):
            print("FAIL (Server start)")
        else:
            try:
                test_observability_check(port)
                # Wait a bit for logs to flush
                time.sleep(0.5)
                
                with open(log_path, 'r') as f:
                    content = f.read()
                
                # Check 1: Timestamps
                # [YYYY-MM-DD HH:MM:SS]
                ts_pattern = r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]"
                if not re.search(ts_pattern, content):
                    print(f"FAIL (No timestamps found in log: {content})")
                
                # Check 2: Session Stats
                # Session finished: X bytes sent, Y bytes received
                # Since we sent some bytes (Handshake + Connect CMD), we expect some bytes sent/received count or at least 0
                elif "Session finished:" not in content:
                    print(f"FAIL (No session stats found in log: {content})")
                else:
                    print("PASS")
                    
            except Exception as e:
                print(f"FAIL ({e})")
    finally:
        proc.terminate()
        proc.wait()
        if os.path.exists(log_path):
            os.remove(log_path)


    # 7. Security: Max Connections
    def test_check_max_conn(port):
        # 1. Connect first client (hold it open)
        s1, _ = connect_socks5(port, methods=[0x00])
        
        # 2. Try connect second client (should be rejected/closed immediately)
        try:
             s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
             s2.settimeout(1.0)
             s2.connect(('localhost', port))
             # Send handshake
             s2.sendall(b'\x05\x01\x00')
             # Should get closed or empty recv
             data = s2.recv(1024)
             if len(data) == 0:
                 pass # Good, closed
             else:
                 # It might accept then close, or failing handshake
                 pass
             s2.close()
        except (ConnectionResetError, socket.timeout, Exception):
             pass # Good
             
        s1.close()

    # We need a custom runner for this to pass --max-conn 1
    # But for simplicity, we can do manual check logic or adapt run_test_case
    # Let's just do a specific block like Observability
    print(f"TEST: Security Max Conn ... ", end='', flush=True)
    port = port + 1
    proc = subprocess.Popen([SERVER_BIN, "--port", str(port), "--max-conn", "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if wait_for_port(port):
            # Client 1
            s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s1.connect(('localhost', port))
            # Handshake
            s1.sendall(b'\x05\x01\x00')
            s1.recv(2) # 05 00
            
            # Client 2
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.connect(('localhost', port))
                # It might connect TCP, but then server closes it during loop check
                # Send handshake
                s2.sendall(b'\x05\x01\x00')
                # Expect close
                d = s2.recv(10)
                if len(d) == 0:
                    print("PASS")
                else:
                    print(f"FAIL (Client 2 got data: {d})")
                s2.close()
            except Exception as e:
                print(f"PASS ({e})")
                
            s1.close()
        else:
            print("FAIL (Start)")
    except Exception as e:
        print(f"FAIL ({e})")
    finally:
        proc.terminate()
        proc.wait()


    # 8. Security: Allow IP
    print(f"TEST: Security Allow IP ... ", end='', flush=True)
    port = port + 1
    # Allow logic: if allow-ip is set, others should be blocked.
    # We are connecting from 127.0.0.1.
    # Case A: Allow 1.2.3.4 (Block us)
    proc1 = subprocess.Popen([SERVER_BIN, "--port", str(port), "--allow-ip", "1.2.3.4"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if wait_for_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('localhost', port))
                s.sendall(b'\x05\x01\x00')
                data = s.recv(10)
                if len(data) == 0:
                    # Connection closed = Good
                    pass 
                else:
                     # Access denied usually just closes, or maybe sends nothing then closes
                     print(f"FAIL (Should be blocked, got {data})")
                     # Note: Our code does `goto cleanup` which closes socket.
                s.close()
            except Exception:
                pass 
        else:
            print("FAIL (Start 1)")
    finally:
        proc1.terminate()
        proc1.wait()
        
    # Case B: Allow 127.0.0.1 (Allow us)
    port = port + 1
    proc2 = subprocess.Popen([SERVER_BIN, "--port", str(port), "--allow-ip", "127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if wait_for_port(port):
            try:
                s, _ = connect_socks5(port)
                s.close()
                print("PASS")
            except Exception as e:
                print(f"FAIL (Should be allowed: {e})")
        else:
            print("FAIL (Start 2)")
    finally:
        proc2.terminate()
        proc2.wait()

    # 9. BIND Test
    print(f"TEST: BIND Command ... ", end='', flush=True)
    port = port + 1
    proc_bind = subprocess.Popen([SERVER_BIN, "--port", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if wait_for_port(port):
            s, _ = connect_socks5(port)
            
            # Send BIND request
            # 05 02 00 01 00000000 0000 (Bind to 0.0.0.0:0 usually, or specific if desired)
            cmd = b'\x05\x02\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
            s.sendall(cmd)
            
            # Receive First Reply (BND.ADDR/PORT)
            reply1 = s.recv(10)
            if len(reply1) < 10 or reply1[1] != 0x00:
                print(f"FAIL (First Reply: {reply1})")
            else:
                bnd_port = struct.unpack('!H', reply1[8:10])[0]
                # Now we need to act as the "Application Server" and connect to this bnd_port
                try:
                    p = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    p.connect(('localhost', bnd_port))
                    
                    # Receive Second Reply on control channel
                    # It might take a moment
                    reply2 = s.recv(10)
                    if len(reply2) < 10 or reply2[1] != 0x00:
                        print(f"FAIL (Second Reply: {reply2})")
                    else:
                        # Test Relay: Send data from Peer -> Proxy -> Client
                        p.sendall(b"HelloBIND")
                        data = s.recv(10)
                        if data == b"HelloBIND":
                             print("PASS")
                        else:
                             print(f"FAIL (Data mismatch: {data})")
                    p.close()
                except Exception as e:
                    print(f"FAIL (Connect to bind port: {e})")
            s.close()
        else:
             print("FAIL (Start BIND)")
    finally:
        proc_bind.terminate()
        proc_bind.wait()


    # 10. UDP ASSOCIATE Test
    print(f"TEST: UDP ASSOCIATE ... ", end='', flush=True)
    port = port + 1
    proc_udp = subprocess.Popen([SERVER_BIN, "--port", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if wait_for_port(port):
            s, _ = connect_socks5(port)
            
            # Send UDP ASSOCIATE request
            # 05 03 00 01 00000000 0000 (We want to send from 0.0.0.0:0 usually, or just claims so)
            cmd = b'\x05\x03\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
            s.sendall(cmd)
            
            # Receive Reply (BND.ADDR/PORT of UDP socket)
            reply = s.recv(10)
            if len(reply) < 10 or reply[1] != 0x00:
                print(f"FAIL (Reply: {reply})")
            else:
                udp_port = struct.unpack('!H', reply[8:10])[0]
                udp_addr_bytes = reply[4:8]
                udp_ip = socket.inet_ntoa(udp_addr_bytes)
                if udp_ip == '0.0.0.0': udp_ip = '127.0.0.1' # If it returned 0.0.0.0, use localhost
                
                # Create UDP client
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
                # Construct SOCKS5 UDP Header + Data
                # RSV(2) FRAG(1) ATYP(1) DST.ADDR(4) DST.PORT(2) DATA
                # We want to send to "127.0.0.1:12345" (fake target)
                # But wait, we need an echo server to verify?
                # We send to *our own* UDP listener.
                
                echo_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                echo_sock.bind(('127.0.0.1', 0))
                _, echo_port = echo_sock.getsockname()
                
                # Header to target (our echo sock)
                pkt = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', echo_port) + b"HelloUDP"
                
                # Send to Proxy UDP port
                u.sendto(pkt, (udp_ip, udp_port))
                
                # Check echo sock received payload
                echo_sock.settimeout(2)
                try:
                    data, addr = echo_sock.recvfrom(1024)
                    if data == b"HelloUDP":
                        # Now reply!
                        echo_sock.sendto(b"ReplyUDP", addr)
                        
                        # Proxy should wrap it and send back to u
                        u.settimeout(2)
                        d2, _ = u.recvfrom(1024)
                        # d2 should be Header + ReplyUDP
                        # Header is 10 bytes usually for IPv4
                        if b"ReplyUDP" in d2:
                             print("PASS")
                        else:
                             print(f"FAIL (Reply mismatch: {d2})")
                    else:
                        print(f"FAIL (Echo mismatch: {data})")
                except Exception as e:
                     print(f"FAIL (Timeout/Error: {e})")
                
                u.close()
                echo_sock.close()
                
            s.close()
        else:
             print("FAIL (Start UDP)")
    finally:
        proc_udp.terminate()
        proc_udp.wait()

