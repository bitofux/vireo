"""Verified TLS -> production mixed process -> real MySQL -> independent wire oracle.

All credentials and raw child diagnostics stay inside the owned 0700 fixture.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import os
import random
import re
import selectors
import signal
import socket
import ssl
import struct
import subprocess
import time
from test_auth_process import crc, frame, session_frame, session_response


def packet(command, sequence, body=b'', handle=0, flags=0, status=0, task=0):
    prefix = struct.pack('!IBBHHHIIII', 0x56495245, 1, 32, command,
                         flags, status, len(body), sequence, handle, task)
    return prefix + struct.pack('!I', crc(prefix + body)) + body


def tlv(tag, data):
    return struct.pack('!HH', tag, len(data)) + data


def stat_frame(sequence, node, handle=0):
    return packet(0x402, sequence, tlv(0x401, struct.pack('!Q', node)), handle)


def read_response(peer):
    def exact(n):
        chunks = bytearray()
        while len(chunks) < n:
            part = peer.recv(n - len(chunks))
            assert part, 'unexpected TLS EOF'
            chunks.extend(part)
        return bytes(chunks)
    header = exact(32)
    h = struct.unpack('!IBBHHHIIIII', header)
    assert h[:3] == (0x56495245, 1, 32) and h[4] == 1 and h[9] == 0
    assert h[6] <= 361
    body = exact(h[6])
    assert crc(header[:28] + body) == h[10]
    fields = {}
    offset = 0
    while offset < len(body):
        assert offset + 4 <= len(body)
        tag, n = struct.unpack_from('!HH', body, offset)
        offset += 4
        assert tag not in fields and offset + n <= len(body)
        fields[tag] = body[offset:offset+n]
        offset += n
    return h, fields


def stat_response(peer, sequence, status, *, handle=0, metadata=None):
    h, fields = read_response(peer)
    assert h[3] == 0x402 and h[7] == sequence and h[5] == status, (
        'STAT envelope', h[3], h[7], h[5], 'expected', sequence, status)
    assert h[8] == (handle if status == 0 else 0)
    if status:
        assert h[6] == 0 and fields == {}
    else:
        assert metadata is not None and fields == metadata
    return h


def real(server, helper, endpoint, user, password_file, database):
    os.umask(0o077)
    root = Path(password_file).parent
    cert, key = root/'directory-cert.pem', root/'directory-key.pem'
    with (root/'directory-openssl.log').open('xb') as log:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)], stdout=log, stderr=log,
                       check=True, timeout=10)
    context = ssl.create_default_context(cafile=str(cert))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    config = root/'directory-client.cnf'
    config.write_text('[client]\nuser='+user+'\npassword='+Path(password_file).read_text().strip()+'\n')
    children = []

    def mysql_args(admin=False):
        return ['mysql', '--defaults-file='+str(root/'root.cnf' if admin else config),
                '--protocol=SOCKET', '--socket='+endpoint, '--database='+database,
                '--batch', '--skip-column-names', '--unbuffered']

    def sql(statement, admin=False):
        result = subprocess.run(mysql_args(admin), input=statement, text=True,
                                capture_output=True, timeout=8)
        assert result.returncode == 0, 'owned directory fixture SQL failed'
        return result.stdout.strip()

    def start(name, checked=False, stat_budget=4096, lifetime=60000):
        with socket.socket() as bound:
            bound.bind(('127.0.0.1', 0))
            port = bound.getsockname()[1]
        args = ['127.0.0.1', str(port), str(cert), str(key), endpoint,
                user, password_file, database, str(lifetime)]
        command = [helper, '--child', *args, '4096', str(stat_budget)] if checked else [server, *args]
        path = root/('directory-'+name+'.log')
        log = path.open('xb')
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log)
        children.append((child, log))
        with selectors.DefaultSelector() as sel:
            sel.register(child.stdout, selectors.EVENT_READ)
            assert sel.select(15), 'directory process readiness timeout'
            assert child.stdout.readline() == b'vireo-auth-server ready\n'
        return child, port, path

    def connect(port):
        # Fixed-budget client cleanup spans multiple 100ms turns; 5s is below its observed 6.3s path.
        raw = socket.create_connection(('127.0.0.1', port), timeout=12)
        peer = context.wrap_socket(raw, server_hostname='localhost')
        assert peer.version() == 'TLSv1.3'
        return peer

    def finish(child, path, expected=0, signum=signal.SIGTERM):
        if signum:
            child.send_signal(signum)
        child.communicate(timeout=15)
        assert child.returncode == expected, 'directory child failed; private log retained'
        data = path.read_text()
        assert 'AddressSanitizer' not in data and 'runtime error:' not in data
        v = {k: int(n) for k, n in re.findall(r'(\w+)=(-?\d+)', data)}
        assert v['clean'] == 1 and v['cleanup'] == 0 and v['created'] == v['joined'] == 2
        assert v['queues_closed'] == 7 and v['queues_drained'] == 6 and v['final_drain_turns'] >= 1
        assert v['audit_created'] == v['audit_joined']
        if 'fd_before' in v:
            assert v['fd_before'] == v['fd_after']
        if signum:
            assert v['signal'] == signum
            assert v['faults_at_stop'] == v['stat_faults_at_stop'] == 0
            assert v['final_faults'] & ~8 == v['stat_final_faults'] & ~8 == 0
        return v

    def login(peer, sequence=1):
        peer.sendall(frame(True, sequence))
        return session_response(peer, 0x101, sequence)

    def metadata(node, name=b'', parent=None, *, file=False):
        values = {0x401: struct.pack('!Q', node), 0x403: name,
                  0x404: struct.pack('!H', 2 if file else 1),
                  0x405: struct.pack('!Q', (1 << 64)-1 if file else 0),
                  0x406: struct.pack('!Q', 42), 0x407: struct.pack('!Q', 99)}
        if parent is not None:
            values[0x402] = struct.pack('!Q', parent)
        if file:
            values[0x408] = bytes(range(32))
        return values

    def snapshot():
        return sql('SELECT id,owner_id,parent_id,HEX(name),node_type,state,HEX(object_hash),size,'
                   'created_at_ms,updated_at_ms,deleted_at_ms FROM file_nodes ORDER BY id;'
                   'SELECT HEX(object_hash),size,state,ref_count FROM objects ORDER BY object_hash;'
                   'SELECT id,status,last_login_at_ms,updated_at_ms FROM users ORDER BY id;'
                   'SELECT id,user_id,status,issued_at_ms,expires_at_ms,revoked_at_ms,last_seen_at_ms FROM sessions ORDER BY id;'
                   'SELECT COUNT(*) FROM operation_audits;')

    def closed(peer):
        try:
            assert peer.recv(1) == b'', 'invalid frame must close its client'
        except (ssl.SSLEOFError, ConnectionResetError):
            pass

    blocker = None
    try:
        child, port, path = start('normal')
        with connect(port) as peer:
            peer.sendall(frame(False, 1))
            h, registered = read_response(peer)
            assert h[3] == 0x100 and h[5] == 0 and h[7] == 1
            assert set(registered) == {1, 2} and all(len(v) == 8 for v in registered.values())
            root_id = int.from_bytes(registered[2], 'big')
            bob = tlv(1, b'Bob_7') + tlv(2, b'Correct!8')
            peer.sendall(packet(0x100, 2, bob))
            h, _ = read_response(peer)
            assert h[5] == 0 and h[7] == 2
            handle, identity = login(peer, 3)
            actor = int.from_bytes(identity[1], 'big')
            assert identity[1] == registered[1]
            # The wire carries issued_at_ms in tag4, never a persistent Session ID.
            sid = int(sql('SELECT id FROM sessions WHERE user_id='+str(actor)+' AND status=1;'))
            assert root_id == int(sql('SELECT id FROM file_nodes WHERE owner_id='+str(actor)+' AND parent_id IS NULL;'))
            bob_root = int(sql("SELECT n.id FROM file_nodes n JOIN users u ON n.owner_id=u.id WHERE u.username='Bob_7' AND n.parent_id IS NULL;"))
            # REGISTER already returns its root; LOGIN/RESUME root discovery remains a later contract.
            sql('UPDATE file_nodes SET created_at_ms=42,updated_at_ms=99 WHERE id='+str(root_id)+';')
            name = b'Q'*255
            binary_name = b'\xff'+b'F'*254
            object_hash = bytes(range(32)).hex()
            sql("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(X'"+object_hash+"',18446744073709551615,2,1,1,42,99,99);")
            sql("INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms) VALUES"
                "(1000,"+str(actor)+','+str(root_id)+",X'"+name.hex()+"',1,2,NULL,0,42,99),"
                "(18446744073709551613,"+str(actor)+",1000,X'"+binary_name.hex()+"',2,2,X'"+object_hash+"',18446744073709551615,42,99);")
            expected_root = metadata(root_id)
            expected_dir = metadata(1000, name, root_id)
            expected_file = metadata((1 << 64)-3, binary_name, 1000, file=True)
            before = snapshot()
            peer.sendall(stat_frame(4, root_id))
            stat_response(peer, 4, 1101)
            peer.sendall(stat_frame(5, root_id, handle ^ 0xffffffff))
            stat_response(peer, 5, 1101)
            with connect(port) as other:
                other.sendall(stat_frame(1, root_id, handle))
                stat_response(other, 1, 1101)
            # Deliberately split a valid TLS application frame into independent writes.
            partial = stat_frame(6, root_id, handle)
            peer.sendall(partial[:17]); peer.sendall(partial[17:35]); peer.sendall(partial[35:])
            stat_response(peer, 6, 0, handle=handle, metadata=expected_root)
            peer.sendall(stat_frame(7, 1000, handle))
            stat_response(peer, 7, 0, handle=handle, metadata=expected_dir)
            peer.sendall(stat_frame(8, (1 << 64)-3, handle))
            largest = stat_response(peer, 8, 0, handle=handle, metadata=expected_file)
            assert largest[6] + 32 == 393
            for sequence, node in [(9, bob_root), (10, (1 << 64)-2)]:
                peer.sendall(stat_frame(sequence, node, handle))
                stat_response(peer, sequence, 1201)
            peer.sendall(b''.join(stat_frame(n, root_id, handle) for n in range(11, 19)))
            seen = set()
            for _ in range(8):
                h, fields = read_response(peer)
                assert h[3] == 0x402 and h[5] == 0 and h[8] == handle and fields == expected_root
                assert h[7] in range(11, 19) and h[7] not in seen
                seen.add(h[7])
            assert snapshot() == before, 'STAT changed persistent business state'
            sql('UPDATE users SET status=2 WHERE id='+str(actor)+';')
            peer.sendall(stat_frame(19, root_id, handle)); stat_response(peer, 19, 1101)
            sql('UPDATE users SET status=1 WHERE id='+str(actor)+';')
            sql('UPDATE sessions SET issued_at_ms=0,last_seen_at_ms=0,expires_at_ms=1 WHERE id='+str(sid)+';')
            assert sql('SELECT COUNT(*) FROM sessions WHERE id='+str(sid)+' AND expires_at_ms=1;') == '1'
            peer.sendall(stat_frame(20, root_id, handle)); stat_response(peer, 20, 1101)
            expires = int.from_bytes(identity[5], 'big')
            issued = int.from_bytes(identity[4], 'big')
            sql('UPDATE sessions SET issued_at_ms='+str(issued)+',last_seen_at_ms='+str(issued)+',expires_at_ms='+str(expires)+' WHERE id='+str(sid)+';')
            sql('UPDATE sessions SET status=2,revoked_at_ms='+str(issued)+' WHERE id='+str(sid)+';')
            peer.sendall(stat_frame(21, root_id, handle)); stat_response(peer, 21, 1101)
            sql('UPDATE sessions SET status=1,revoked_at_ms=NULL WHERE id='+str(sid)+';')
            # The accepted STAT contract checks the selected active node, not ancestor reachability.
            sql('UPDATE file_nodes SET state=3,deleted_at_ms=99 WHERE id=1000;')
            peer.sendall(stat_frame(22, (1 << 64)-3, handle))
            stat_response(peer, 22, 0, handle=handle, metadata=expected_file)
            sql('UPDATE file_nodes SET state=2,deleted_at_ms=NULL WHERE id=1000;')
            # Same persistent Session on another connection; trusted LOGOUT revokes both local handles.
            with connect(port) as second:
                second.sendall(session_frame(0x103, 1, token=identity[3]))
                other_handle, _ = session_response(second, 0x103, 1)
                peer.sendall(session_frame(0x102, 23, handle=handle))
                session_response(peer, 0x102, 23)
                second.sendall(stat_frame(2, root_id, other_handle)); stat_response(second, 2, 1101)
                peer.sendall(stat_frame(24, root_id, handle)); stat_response(peer, 24, 1101)
            assert child.poll() is None

        # Independent schema oracle: valid body and no handle -> UNAUTHORIZED, malformed -> BAD_REQUEST.
        rng = random.Random(4305)
        body_cases = [b'', tlv(0x401, bytes(8)), tlv(0x401, bytes(7)),
                      tlv(0x401, bytes(9)), tlv(0x402, bytes(8)),
                      tlv(0x401, struct.pack('!Q', root_id))*2,
                      tlv(0x401, struct.pack('!Q', root_id))+tlv(0x499, b'x'),
                      tlv(0x401, struct.pack('!Q', root_id)), bytes(124)]
        body_cases += [rng.randbytes(rng.randrange(0, 125)) for _ in range(128)]
        before = snapshot()
        with connect(port) as malformed:
            for sequence, body in enumerate(body_cases, 1):
                valid = len(body) == 12 and body[:4] == b'\x04\x01\x00\x08' and any(body[4:])
                malformed.sendall(packet(0x402, sequence, body))
                stat_response(malformed, sequence, 1101 if valid else 1001)
        bad_frames = [bytearray(stat_frame(1, root_id)),
                      bytearray(packet(0x402, 1, bytes(125))),
                      bytearray(packet(0x401, 1)),
                      bytearray(packet(0x402, 0, tlv(0x401, struct.pack('!Q', root_id)))),
                      bytearray(packet(0x402, 1, flags=0x8000))]
        bad_frames[0][-1] ^= 1
        for broken in bad_frames:
            with connect(port) as malformed:
                malformed.sendall(broken); closed(malformed)
        for length in [1, 17, 31, 33, 43]:
            with connect(port) as partial:
                partial.sendall(stat_frame(1, root_id)[:length])
        assert snapshot() == before
        state = finish(child, path)
        assert state['final_faults'] == state['stat_final_faults'] == 0
        print('PASS directory production: verified TLS1.3, REGISTER root and real root/directory/file SQL, 393-byte binary-name/max-u64 response, owner isolation, handle binding, disabled/expired/revoked Session checks, explicit ancestor non-guarantee, cross-connection LOGOUT, split/coalesced frames, read-only snapshots, 137 schema inputs, 5 framing failures, partial disconnects')

        child, port, path = start('stat-publish-fault', checked=True, stat_budget=1)
        with connect(port) as peer:
            handle, _ = login(peer)
            peer.sendall(stat_frame(2, root_id, handle))
            state = finish(child, path, expected=1, signum=None)
        assert state['signal'] == 0 and state['faults_at_stop'] == state['final_faults'] == 0
        assert state['stat_faults_at_stop'] == state['stat_final_faults'] == 8
        print('PASS directory production: STAT missing completion auto-stop, independent fault domain, all three queues closed and both queues drained, joined workers and restored FDs before return')

        # Keep a real MySQL user row lock, observe actual LOCK WAIT, then stop with STAT in flight.
        child, port, path = start('inflight-stop', checked=True)
        with connect(port) as peer:
            handle, _ = login(peer)
            blocker = subprocess.Popen(mysql_args(True), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            blocker.stdin.write('START TRANSACTION; SELECT id FROM users WHERE id='+str(actor)+' FOR UPDATE;\n')
            blocker.stdin.flush()
            with selectors.DefaultSelector() as sel:
                sel.register(blocker.stdout, selectors.EVENT_READ)
                assert sel.select(5), 'row lock readiness timeout'
                assert blocker.stdout.readline().strip() == str(actor)
            peer.sendall(b''.join(stat_frame(n, root_id, handle) for n in range(2, 10)))
            deadline = time.monotonic() + 5
            while sql("SELECT COUNT(*) FROM information_schema.innodb_trx WHERE trx_state='LOCK WAIT';", True) == '0':
                assert time.monotonic() < deadline, 'STAT did not reach actual InnoDB lock wait'
            child.send_signal(signal.SIGINT)
            blocker.stdin.write('COMMIT;\n'); blocker.stdin.flush()
            blocker.communicate(timeout=5)
            assert blocker.returncode == 0
            blocker = None
            state = finish(child, path, signum=None)
            assert state['signal'] == signal.SIGINT and state['faults_at_stop'] == state['stat_faults_at_stop'] == 0
            assert state['final_faults'] & ~8 == state['stat_final_faults'] & ~8 == 0
        print('PASS directory production: actual InnoDB LOCK WAIT with multiple STAT requests, SIGINT/cancel/join/final dual drain, original worker cleanup and FD restoration')
    finally:
        if blocker is not None:
            blocker.kill(); blocker.communicate(timeout=5)
        for child, log in children:
            if child.poll() is None:
                child.kill(); child.communicate(timeout=10)
            log.close()


if __name__ == '__main__':
    if len(sys.argv) != 8 or sys.argv[1] != '--real':
        raise SystemExit('invalid directory process test invocation')
    real(*sys.argv[2:])
