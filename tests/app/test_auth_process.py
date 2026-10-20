"""Actual executable/exec lifecycle, verified TLS, real MySQL, no secret diagnostics."""
from pathlib import Path
import os
import re
import selectors
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time


def unit(server):
    result = subprocess.run([server, '--help'], capture_output=True, timeout=10)
    assert result.returncode == 0 and b'SESSION_LIFETIME_MS' in result.stdout
    base = ['127.0.0.1', '19000', '/absent-cert', '/absent-key', '/absent-socket',
            'nobody', '/absent-password', 'test', '60000']
    cases = [[], ['--bad'], base]
    for index, values in [(0, ['localhost', '::1', '999.0.0.1']),
                          (1, ['0', '-1', '+1', '65536', ' 80', '80x', '']),
                          (8, ['0', '-1', '+1', '18446744073709551616', '1x', ''])]:
        for value in values:
            case = list(base)
            case[index] = value
            cases.append(case)
    for args in cases:
        result = subprocess.run([server, *args], capture_output=True, timeout=10)
        assert result.returncode == 1 and b'ready\n' not in result.stdout
    print('PASS auth_process CLI: help, strict positive decimal/IPv4, missing TLS, no admission')


def crc(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return value ^ 0xffffffff


def frame(login, sequence, wrong=False):
    def tlv(tag, data):
        return struct.pack('!HH', tag, len(data)) + data
    body = tlv(1, b'Alice_7') + tlv(2, b'Incorrect' if wrong else b'Correct!7')
    if login:
        body += tlv(3, bytes(16))
    header = struct.pack('!IBBHHHIIII', 0x56495245, 1, 32, 0x101 if login else 0x100,
                         0, 0, len(body), sequence, 0, 0)
    return header + struct.pack('!I', crc(header + body)) + body


def response(peer, login, sequence, wrong=False):
    def read(n):
        data = b''
        while len(data) < n:
            part = peer.recv(n - len(data))
            assert part, 'unexpected TLS EOF'
            data += part
        return data
    header = read(32)
    fields = struct.unpack('!IBBHHHIIIII', header)
    assert fields[:3] == (0x56495245, 1, 32)
    assert fields[3] == (0x101 if login else 0x100) and fields[7] == sequence
    assert fields[4] == 1 and fields[9] == 0
    assert fields[5] == (1104 if wrong else 0)
    body = read(fields[6])
    assert crc(header[:28] + body) == fields[-1]
    assert len(body) == (0 if wrong else 72 if login else 24)
    if login and not wrong:
        assert fields[8] != 0
        tags = {}
        offset = 0
        while offset < len(body):
            tag, length = struct.unpack_from('!HH', body, offset)
            offset += 4
            assert tag not in tags and offset + length <= len(body)
            tags[tag] = body[offset:offset + length]
            offset += length
        assert any(len(value) == 32 and any(value) for value in tags.values())


def session_frame(command, sequence, *, token=None, handle=0):
    body = struct.pack('!HH', 4, 32) + token if token is not None else b''
    header = struct.pack('!IBBHHHIIII', 0x56495245, 1, 32, command, 0, 0, len(body), sequence, handle, 0)
    return header + struct.pack('!I', crc(header + body)) + body


def session_response(peer, command, sequence, status=0):
    def read(n):
        data = b''
        while len(data) < n:
            part = peer.recv(n-len(data))
            assert part
            data += part
        return data
    header = read(32)
    h = struct.unpack('!IBBHHHIIIII', header)
    body = read(h[6])
    assert h[:3] == (0x56495245, 1, 32) and h[3] == command and h[7] == sequence
    assert h[4] == 1 and h[5] == status and h[9] == 0 and crc(header[:28] + body) == h[-1]
    if status or command == 0x102:
        assert not body and not h[8]
        return 0, {}
    tags = {}; offset = 0
    while offset < len(body):
        tag, n = struct.unpack_from('!HH', body, offset); offset += 4
        assert tag not in tags and offset + n <= len(body)
        tags[tag] = body[offset:offset+n]; offset += n
    assert h[8] and set(tags) == ({1, 3, 4, 5} if command == 0x101 else {1, 4, 5})
    assert all(len(tags[k]) == 8 for k in [1, 4, 5])
    assert len(body) == (72 if command == 0x101 else 36)
    return h[8], tags


def real(server, helper, endpoint, user, password_file, database):
    os.umask(0o077)
    root = Path(password_file).parent
    cert, key = root/'process-cert.pem', root/'process-key.pem'
    with (root/'process-openssl.log').open('xb') as log:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)], stdout=log, stderr=log, check=True, timeout=10)
    context = ssl.create_default_context(cafile=str(cert))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    children = []

    def port():
        with socket.socket() as bound:
            bound.bind(('127.0.0.1', 0))
            return bound.getsockname()[1]

    def start(name, *, checked=False, budget=4096, selected_port=None, socket_path=None, pw=None, cert_path=None, key_path=None):
        chosen = selected_port or port()
        args = ['127.0.0.1', str(chosen), str(cert_path or cert), str(key_path or key), socket_path or endpoint,
                user, str(pw or password_file), database, '60000']
        command = [helper, '--child', *args, str(budget)] if checked else [server, *args]
        log = (root/('process-'+name+'.log')).open('xb')
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log)
        children.append((child, log))
        return child, chosen, root/('process-'+name+'.log')

    def ready(child):
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            assert selector.select(15), 'process readiness timeout'
            assert child.stdout.readline() == b'vireo-auth-server ready\n', 'process failed before ready'

    def finish(child, path, expected, *, signum=None):
        if signum:
            child.send_signal(signum)
        output, _ = child.communicate(timeout=15)
        assert child.returncode == expected, 'unexpected process exit; private fixture log retained'
        data = path.read_text()
        assert 'AddressSanitizer' not in data and 'runtime error:' not in data
        fields = {name: int(value) for name, value in re.findall(r'(\w+)=(-?\d+)', data)}
        assert fields['clean'] == 1 and fields['cleanup'] == 0
        assert fields['created'] == fields['joined']
        if 'fd_before' in fields:
            assert fields['fd_before'] == fields['fd_after']
        if signum:
            assert fields['signal'] == signum and fields['ready'] == 1
        return fields, output

    def connect(chosen):
        raw = socket.create_connection(('127.0.0.1', chosen), timeout=10)
        return context.wrap_socket(raw, server_hostname='localhost')

    # Credentials only in the private fixture defaults file, never argv or printed SQL.
    config = root/'process-client.cnf'
    config.write_text('[client]\nuser='+user+'\npassword='+Path(password_file).read_text().strip()+'\n')

    def session_count():
        result = subprocess.run(['mysql', '--defaults-file='+str(config), '--protocol=SOCKET',
                                 '--socket='+endpoint, '--database='+database, '--batch', '--skip-column-names'],
                                input='SELECT COUNT(*) FROM sessions;', text=True, capture_output=True, timeout=5)
        assert result.returncode == 0, 'private fixture SELECT failed'
        return int(result.stdout.strip())

    def sql(text, *, admin=False):
        result = subprocess.run(['mysql', '--defaults-file='+str(root/'root.cnf' if admin else config), '--protocol=SOCKET',
                                 '--socket='+endpoint, '--database='+database, '--batch', '--skip-column-names'],
                                input=text, text=True, capture_output=True, timeout=5)
        assert result.returncode == 0, 'private fixture SQL failed'
        return result.stdout.strip()

    def wait_sql(text, expected):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = sql(text)
            if value == expected:
                return
        raise AssertionError('asynchronous audit condition timeout')

    try:
        child, chosen, path = start('normal')
        ready(child)
        with connect(chosen) as peer:
            peer.sendall(frame(False, 1)); response(peer, False, 1)
            peer.sendall(frame(True, 2)); first_handle, original = session_response(peer, 0x101, 2)
            peer.sendall(frame(True, 3, True)); response(peer, True, 3, True)
            wait_sql("SELECT COUNT(*) FROM operation_audits WHERE action=2 AND status=1104 AND detail='source=worker';", '1')
            assert child.poll() is None
        # Disconnect discards the connection handle, retaining the same persistent Session.
        with connect(chosen) as resumed:
            token = original[3]
            assert session_count() == 1
            partial = session_frame(0x103, 4, token=token)
            resumed.sendall(partial[:17])
            resumed.sendall(partial[17:])
            handle, restored = session_response(resumed, 0x103, 4)
            assert handle != first_handle and restored == {k: original[k] for k in [1, 4, 5]}
            assert session_count() == 1 and sql('SELECT COUNT(*) FROM operation_audits WHERE status=0;') == '2'
            resumed.sendall(session_frame(0x103, 5, token=bytes(32)))
            session_response(resumed, 0x103, 5, 1104)
            wait_sql("SELECT COUNT(*) FROM operation_audits WHERE action=4 AND status=1104 AND detail='source=worker';", '1')
            sql('UPDATE users SET status=2;')
            resumed.sendall(session_frame(0x103, 6, token=token)); session_response(resumed, 0x103, 6, 1104)
            sql('UPDATE users SET status=1;')
            # Same token on a second connection gets its own fresh handle.
            with connect(chosen) as second:
                second.sendall(session_frame(0x103, 7, token=token)); other_handle, other = session_response(second, 0x103, 7)
                assert other_handle != handle and other == restored
                resumed.sendall(session_frame(0x102, 8, handle=handle)); session_response(resumed, 0x102, 8)
                second.sendall(session_frame(0x102, 9, handle=other_handle)); session_response(second, 0x102, 9, 1104)
                second.sendall(session_frame(0x103, 10, token=token)); session_response(second, 0x103, 10, 1104)
            resumed.sendall(session_frame(0x102, 11) + session_frame(0x102, 12, handle=0x12345678))
            session_response(resumed, 0x102, 11, 1001); session_response(resumed, 0x102, 12, 1104)
            assert sql('SELECT COUNT(*) FROM operation_audits WHERE status=0;') == '3' and session_count() == 1
            # A new password login creates a different Session; expiry/presign both fail uniformly.
            resumed.sendall(frame(True, 13)); _, fresh = session_response(resumed, 0x101, 13)
            sql('UPDATE sessions SET issued_at_ms=0,last_seen_at_ms=0,expires_at_ms=1 WHERE status=1;')
            resumed.sendall(session_frame(0x103, 14, token=fresh[3])); session_response(resumed, 0x103, 14, 1104)
            future = int(time.time()*1000) + 3600000
            sql('UPDATE sessions SET issued_at_ms='+str(future)+',last_seen_at_ms='+str(future)+',expires_at_ms='+str(future+60000)+' WHERE status=1;')
            resumed.sendall(session_frame(0x103, 15, token=fresh[3])); session_response(resumed, 0x103, 15, 1104)
            # A bad CRC closes its own TLS connection; the authentication process survives.
            with connect(chosen) as malformed:
                broken = bytearray(session_frame(0x103, 16, token=fresh[3])); broken[-1] ^= 1
                malformed.sendall(broken)
                try:
                    assert malformed.recv(1) == b''
                except (ssl.SSLEOFError, ConnectionResetError):
                    pass
            assert child.poll() is None
            state, _ = finish(child, path, 0, signum=signal.SIGTERM)
        assert state['faults_at_stop'] == state['final_faults'] == 0 and state['created'] == 2
        assert state['worker'] != 0  # Ordinary business refusal survives as a pool first error.

        # Fresh quota and queue: five admitted bad LOGINs, then exactly one Reactor throttle.
        child, chosen, path = start('failure-rate', checked=True)
        ready(child)
        before_rate = int(sql("SELECT COUNT(*) FROM operation_audits WHERE status=1008 AND detail='source=reactor';"))
        with connect(chosen) as peer:
            for sequence in range(30, 35):
                peer.sendall(frame(True, sequence, True)); session_response(peer, 0x101, sequence, 1104)
            peer.sendall(frame(True, 35, True)); session_response(peer, 0x101, 35, 1008)
            wait_sql("SELECT COUNT(*) FROM operation_audits WHERE status=1008 AND detail='source=reactor';", str(before_rate+1))
        state, _ = finish(child, path, 0, signum=signal.SIGTERM)
        assert state['audit_disabled'] == 0 and state['audit_committed'] == 6
        assert state['audit_created'] == state['audit_joined'] == 1
        assert state['audit_queued'] == state['audit_taken'] + state['audit_discarded']

        # Only failure INSERTs fail. Observe DISABLED itself before the next valid login.
        sql("DELIMITER $$\nCREATE TRIGGER failure_audit_denied BEFORE INSERT ON operation_audits FOR EACH ROW BEGIN IF NEW.status<>0 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit denied'; END IF; END$$\nDELIMITER ;\n", admin=True)
        child, chosen, path = start('audit-disabled', checked=True)
        ready(child)
        baseline_success = int(sql('SELECT COUNT(*) FROM operation_audits WHERE status=0;'))
        baseline_sessions = session_count()
        with connect(chosen) as peer:
            peer.sendall(frame(True, 40, True)); session_response(peer, 0x101, 40, 1104)
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                assert selector.select(10), 'audit disable observation timeout'
                assert child.stdout.readline() == b'vireo-auth-test audit-disabled\n'
            peer.sendall(frame(True, 41)); session_response(peer, 0x101, 41)
            peer.sendall(frame(True, 42, True)); session_response(peer, 0x101, 42, 1104)
            assert child.poll() is None
        state, _ = finish(child, path, 0, signum=signal.SIGTERM)
        assert state['audit_disabled'] == 1 and state['audit_failed'] == 1 and state['audit_committed'] == 0
        assert state['audit_unknown'] == 0 and state['faults_at_stop'] == state['final_faults'] == 0
        assert session_count() == baseline_sessions + 1
        assert int(sql('SELECT COUNT(*) FROM operation_audits WHERE status=0;')) == baseline_success + 1
        sql('DROP TRIGGER failure_audit_denied;', admin=True)
        assert sql("SELECT COUNT(*) FROM operation_audits WHERE status<>0 AND (user_id IS NOT NULL OR session_id IS NOT NULL OR target_type<>0 OR target_id IS NOT NULL OR target_hash IS NOT NULL OR detail NOT IN ('source=worker','source=reactor'));") == '0'

        child, chosen, path = start('interrupt', checked=True)
        ready(child)
        with socket.create_connection(('127.0.0.1', chosen), timeout=5) as pending_tls:
            pending_tls.sendall(b'\x16')
            state, _ = finish(child, path, 0, signum=signal.SIGINT)
        assert state['created'] == 2 and state['faults_at_stop'] == 0

        child, _, path = start('database-failure', checked=True, socket_path=str(root/'absent.sock'))
        state, output = finish(child, path, 1)
        assert state['ready'] == 0 and state['created'] == 0 and not output
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0)); occupied.listen()
            child, _, path = start('listener-failure', checked=True, selected_port=occupied.getsockname()[1])
            state, output = finish(child, path, 1)
            assert state['ready'] == 0 and state['created'] == 2 and not output

        bad = root/'process-invalid-password'
        bad.write_bytes(b'not-a-valid\x00password\n')
        oversized = root/'process-oversized-key'
        oversized.write_bytes(bytes(65537))
        fifo = root/'process-key-fifo'
        os.mkfifo(fifo, 0o600)
        for name, kwargs in [('password', {'pw':bad}), ('key-size', {'key_path':oversized}),
                             ('key-fifo', {'key_path':fifo}), ('certificate', {'cert_path':bad})]:
            child, _, path = start('invalid-'+name, checked=True, **kwargs)
            state, output = finish(child, path, 1)
            assert state['ready'] == state['created'] == 0 and not output

        fifo.unlink()  # This test's own FIFO must be gone before regular-file archival.
        baseline = session_count()
        child, chosen, path = start('committed-missing-completion', checked=True, budget=1)
        ready(child)
        with connect(chosen) as peer:
            peer.sendall(frame(True, 9))
            state, _ = finish(child, path, 1)
        assert state['signal'] == 0 and state['faults_at_stop'] == state['final_faults'] == 8
        assert state['created'] == 2 and session_count() == baseline + 1
        print('PASS auth_process real: verified TLS login-disconnect-resume-logout, no reissue/renewal, disabled/expired/presign/revoked/invalid tokens, two connections, half/coalesced/bad CRC, REGISTER/LOGIN/refusal; TERM/INT; startup TLS/DB/listener rollback; FD restored before return; COMMITTED missing completion auto-stop without replay')
    finally:
        for child, log in children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
            log.close()


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--unit':
        unit(sys.argv[2])
    elif len(sys.argv) == 8 and sys.argv[1] == '--real':
        real(*sys.argv[2:])
    else:
        raise SystemExit('invalid auth_process test invocation')
