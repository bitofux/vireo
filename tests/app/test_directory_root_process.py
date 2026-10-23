"""NODE_ROOT production TLS/MySQL tests with an independent wire oracle."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import os, random, re, selectors, signal, socket, ssl, struct, subprocess, time
from test_directory_stat_process import packet, tlv, read_response, stat_frame
from test_auth_process import frame, session_frame, session_response


def root_frame(seq, handle=0):
    return packet(0x406, seq, handle=handle)


def root_response(peer, seq, status=0, handle=0, root=0):
    h, values = read_response(peer)
    assert (h[3], h[5], h[7], h[8]) == (0x406, status, seq, handle if not status else 0)
    assert h[6] == (12 if not status else 0)
    assert values == ({0x401: struct.pack('!Q', root)} if not status else {})
    return h


def real(server, helper, endpoint, user, password_file, database):
    os.umask(0o077)
    base = Path(password_file).parent
    cert, key = base/'root-cert.pem', base/'root-key.pem'
    with (base/'root-openssl.log').open('xb') as log:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)], stdout=log, stderr=log, check=True, timeout=10)
    context = ssl.create_default_context(cafile=str(cert))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    config = base/'root-client.cnf'
    config.write_text('[client]\nuser='+user+'\npassword='+Path(password_file).read_text().strip()+'\n')
    children = []
    blocker = None

    def mysql_args(admin=False):
        return ['mysql', '--defaults-file='+str(base/'root.cnf' if admin else config),
                '--protocol=SOCKET', '--socket='+endpoint, '--database='+database,
                '--batch', '--skip-column-names', '--unbuffered']

    def sql(text, admin=False):
        p = subprocess.run(mysql_args(admin), input=text, text=True, capture_output=True, timeout=8)
        assert p.returncode == 0, 'owned ROOT fixture SQL failed'
        return p.stdout.strip()

    def snapshot():
        return sql('SELECT id,owner_id,parent_id,HEX(name),node_type,state,size,created_at_ms,updated_at_ms,deleted_at_ms FROM file_nodes ORDER BY id;'
                   'SELECT HEX(object_hash),size,state,ref_count FROM objects ORDER BY object_hash;'
                   'SELECT id,status,last_login_at_ms,updated_at_ms FROM users ORDER BY id;'
                   'SELECT id,user_id,status,issued_at_ms,expires_at_ms,revoked_at_ms,last_seen_at_ms FROM sessions ORDER BY id;'
                   'SELECT COUNT(*) FROM operation_audits;')

    def start(name, root_budget=4096, checked=True):
        with socket.socket() as bound:
            bound.bind(('127.0.0.1', 0)); port = bound.getsockname()[1]
        args = ['127.0.0.1', str(port), str(cert), str(key), endpoint, user, password_file, database, '60000']
        command = [helper, '--child', *args, '4096', '4096', str(root_budget)] if checked else [server, *args]
        path = base/('root-'+name+'.log'); log = path.open('xb')
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log); children.append((child, log))
        with selectors.DefaultSelector() as sel:
            sel.register(child.stdout, selectors.EVENT_READ)
            assert sel.select(15), 'ROOT process readiness timeout'
            assert child.stdout.readline() == b'vireo-auth-server ready\n'
        return child, port, path

    def connect(port):
        raw = socket.create_connection(('127.0.0.1', port), timeout=12)
        return context.wrap_socket(raw, server_hostname='localhost')

    def finish(child, path, expected=0, sig=signal.SIGTERM):
        if sig: child.send_signal(sig)
        child.communicate(timeout=15)
        assert child.returncode == expected, 'ROOT child failed; private diagnostics retained'
        text = path.read_text()
        assert 'AddressSanitizer' not in text and 'runtime error:' not in text
        v = {k: int(n) for k,n in re.findall(r'(\w+)=(-?\d+)', text)}
        assert v['clean'] == 1 and v['cleanup'] == 0 and v['created'] == v['joined'] == 2
        assert v['queues_closed'] == 15 and v['queues_drained'] == 14 and v['final_drain_turns'] > 0
        assert v['audit_created'] == v['audit_joined']
        if 'fd_before' in v: assert v['fd_before'] == v['fd_after']
        if sig:
            assert v['signal'] == sig and v['faults_at_stop'] == v['stat_faults_at_stop'] == v['root_faults_at_stop'] == 0
        return v

    def login(peer, seq=1, bob=False):
        wire = packet(0x101, seq, tlv(1,b'Bob_7')+tlv(2,b'Correct!8')+tlv(3,bytes(16))) if bob else frame(True,seq)
        peer.sendall(wire); return session_response(peer,0x101,seq)

    def closed(peer):
        try: assert peer.recv(1) == b''
        except (ssl.SSLEOFError, ConnectionResetError): pass

    try:
        child, port, path = start('normal', checked=False)
        with connect(port) as peer:
            roots = []
            for seq, body in [(1, None),(2,tlv(1,b'Bob_7')+tlv(2,b'Correct!8'))]:
                peer.sendall(frame(False,seq) if body is None else packet(0x100,seq,body))
                h, values = read_response(peer)
                assert h[3] == 0x100 and h[5] == 0
                roots.append(int.from_bytes(values[2], 'big'))
            assert roots[0] and roots[1] and roots[0] != roots[1]
            handle, identity = login(peer,3)
            actor = int.from_bytes(identity[1],'big')
            sid = int(sql('SELECT id FROM sessions WHERE user_id='+str(actor)+' AND status=1;'))
            assert roots[0] == int(sql('SELECT id FROM file_nodes WHERE owner_id='+str(actor)+' AND parent_id IS NULL;'))
            before = snapshot()
            peer.sendall(root_frame(4)); root_response(peer,4,1101)
            peer.sendall(root_frame(5,handle^0xffffffff)); root_response(peer,5,1101)
            with connect(port) as other:
                other.sendall(root_frame(1,handle)); root_response(other,1,1101)
            split = root_frame(6,handle)
            peer.sendall(split[:17]); peer.sendall(split[17:31]); peer.sendall(split[31:])
            root_response(peer,6,handle=handle,root=roots[0])
            peer.sendall(b''.join(root_frame(n,handle) for n in range(7,15)))
            seen = set()
            for _ in range(8):
                h, fields = read_response(peer)
                assert h[3] == 0x406 and h[5] == 0 and h[8] == handle and h[6] == 12
                assert fields == {0x401:struct.pack('!Q',roots[0])} and 7 <= h[7] < 15 and h[7] not in seen
                seen.add(h[7])
            peer.sendall(stat_frame(15,roots[0],handle)); h, values = read_response(peer)
            assert h[3] == 0x402 and h[5] == 0 and values[0x401] == struct.pack('!Q',roots[0])
            assert snapshot() == before, 'ROOT/STAT changed persistent business state'
            for seq, mutate, restore in [
                (16,'UPDATE users SET status=2 WHERE id='+str(actor),'UPDATE users SET status=1 WHERE id='+str(actor)),
                (17,'UPDATE sessions SET status=2,revoked_at_ms=issued_at_ms WHERE id='+str(sid),'UPDATE sessions SET status=1,revoked_at_ms=NULL WHERE id='+str(sid))]:
                sql(mutate); peer.sendall(root_frame(seq,handle)); root_response(peer,seq,1101); sql(restore)
            issued, expires = int.from_bytes(identity[4],'big'),int.from_bytes(identity[5],'big')
            sql('UPDATE sessions SET issued_at_ms=0,last_seen_at_ms=0,expires_at_ms=1 WHERE id='+str(sid))
            peer.sendall(root_frame(18,handle)); root_response(peer,18,1101)
            sql('UPDATE sessions SET issued_at_ms='+str(issued)+',last_seen_at_ms='+str(issued)+',expires_at_ms='+str(expires)+' WHERE id='+str(sid))
            bob_handle, _ = login(peer,19,True)
            peer.sendall(root_frame(20,handle)); root_response(peer,20,1101)
            peer.sendall(root_frame(21,bob_handle)); root_response(peer,21,handle=bob_handle,root=roots[1])
            with connect(port) as second:
                second.sendall(session_frame(0x103,1,token=identity[3]))
                resumed, _ = session_response(second,0x103,1)
                second.sendall(root_frame(2,resumed)); root_response(second,2,handle=resumed,root=roots[0])
                second.sendall(session_frame(0x102,3,handle=resumed)); session_response(second,0x102,3)
                second.sendall(root_frame(4,resumed)); root_response(second,4,1101)
            # Violate the root invariant only in the disposable fixture; reads must not repair it.
            sql('DELETE FROM file_nodes WHERE id='+str(roots[1]))
            before = snapshot()
            peer.sendall(root_frame(22,bob_handle)); root_response(peer,22,1902)
            assert snapshot() == before and sql('SELECT COUNT(*) FROM file_nodes WHERE id='+str(roots[1])) == '0'
            assert child.poll() is None
        # Independent root schema oracle: only empty body is valid.
        rng = random.Random(4404)
        bodies = [b'',tlv(0x401,struct.pack('!Q',roots[0])),bytes(124)]
        bodies += [rng.randbytes(rng.randrange(1,125)) for _ in range(64)]
        before = snapshot()
        with connect(port) as malformed:
            for seq,body in enumerate(bodies,1):
                malformed.sendall(packet(0x406,seq,body)); root_response(malformed,seq,1001 if body else 1101)
        bad = [bytearray(root_frame(1)),bytearray(packet(0x406,0)),bytearray(packet(0x406,1,flags=0x8000)),bytearray(packet(0x406,1,bytes(125)))]
        bad[0][28] ^= 1
        for wire in bad:
            with connect(port) as peer: peer.sendall(wire); closed(peer)
        for length in (1,17,31):
            with connect(port) as peer: peer.sendall(root_frame(1)[:length])
        assert snapshot() == before
        state = finish(child,path)
        assert state['final_faults'] == state['stat_final_faults'] == state['root_final_faults'] == 0
        print('PASS ROOT production: TLS1.3 LOGIN/RESUME -> ROOT -> STAT; Alice/Bob isolation, binding/disable/expiry/revoke/logout, missing root INTERNAL/no repair, five-table read-only snapshots, split/coalesced/schema/framing/partial disconnects')

        child,port,path = start('missing-completion',root_budget=1)
        with connect(port) as peer:
            handle,_ = login(peer)
            peer.sendall(root_frame(2,handle))
            state = finish(child,path,expected=1,sig=None)
        assert state['signal'] == 0 and state['root_faults_at_stop'] == state['root_final_faults'] == 8
        assert state['faults_at_stop'] == state['stat_faults_at_stop'] == state['final_faults'] == state['stat_final_faults'] == 0
        print('PASS ROOT production: missing ROOT completion auto-stops service; independent fault domain; all four queues closed, all three drained, joins and FD restoration before return')

        child,port,path = start('inflight-stop')
        with connect(port) as peer:
            handle,_ = login(peer)
            blocker = subprocess.Popen(mysql_args(True),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            blocker.stdin.write('START TRANSACTION; SELECT id FROM users WHERE id='+str(actor)+' FOR UPDATE;\n'); blocker.stdin.flush()
            with selectors.DefaultSelector() as sel:
                sel.register(blocker.stdout,selectors.EVENT_READ); assert sel.select(5)
                assert blocker.stdout.readline().strip() == str(actor)
            peer.sendall(b''.join(root_frame(n,handle) for n in range(2,10)))
            until = time.monotonic()+5
            while sql("SELECT COUNT(*) FROM information_schema.innodb_trx WHERE trx_state='LOCK WAIT';",True) == '0':
                assert time.monotonic() < until, 'ROOT did not reach InnoDB lock wait'
            child.send_signal(signal.SIGINT)
            blocker.stdin.write('COMMIT;\n'); blocker.stdin.flush(); blocker.communicate(timeout=5)
            assert blocker.returncode == 0; blocker = None
            state = finish(child,path,sig=None)
            assert state['signal'] == signal.SIGINT and state['root_faults_at_stop'] == 0
            assert (state['final_faults']|state['stat_final_faults']|state['root_final_faults']) & ~8 == 0
        print('PASS ROOT production: actual InnoDB LOCK WAIT, SIGINT with eight ROOT requests, cancel/close-before-join/final drain, restored FDs')
    finally:
        if blocker is not None: blocker.kill(); blocker.communicate(timeout=5)
        for child,log in children:
            if child.poll() is None: child.kill(); child.communicate(timeout=10)
            log.close()


if __name__ == '__main__':
    if len(sys.argv) != 8 or sys.argv[1] != '--real': raise SystemExit('invalid ROOT test invocation')
    real(*sys.argv[2:])
