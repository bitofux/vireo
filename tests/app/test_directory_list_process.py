"""LIST production TLS/MySQL integration; independent repeated-TLV and CRC oracle."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import os, re, selectors, signal, socket, ssl, struct, subprocess, time
from test_directory_stat_process import packet, tlv, read_response, stat_frame
from test_directory_root_process import root_frame, root_response
from test_auth_process import crc, frame, session_frame, session_response

def list_frame(seq, directory, handle=0, page=64, token=None):
    body=tlv(0x410,struct.pack('!Q',directory))+tlv(0x411,struct.pack('!H',page))
    if token is not None: body+=tlv(0x412,token)
    return packet(0x401,seq,body,handle)

def fields(body):
    values=[]; off=0
    while off<len(body):
        assert off+4<=len(body)
        tag,n=struct.unpack_from('!HH',body,off);off+=4
        assert off+n<=len(body);values.append((tag,body[off:off+n]));off+=n
    return values

def list_response(peer,seq,status=0,*,handle=0,directory=0,page=64):
    def exact(n):
        b=bytearray()
        while len(b)<n:
            part=peer.recv(n-len(b));assert part,'LIST unexpected EOF';b.extend(part)
        return bytes(b)
    wire=exact(32);h=struct.unpack('!IBBHHHIIIII',wire)
    assert h[:4]==(0x56495245,1,32,0x401) and h[5]==status and (h[7] in seq if isinstance(seq,set) else h[7]==seq) and h[9]==0, h[:10]
    if isinstance(seq,set):seq.remove(h[7])
    assert h[6]<=23478 and h[8]==(handle if status==0 else 0)
    body=exact(h[6]);assert crc(wire[:28]+body)==h[10]
    f=fields(body)
    if status:
        assert h[4]==1 and not body;return [],None,32
    assert h[4] in (1,33) and f[:2]==[(0x410,struct.pack('!Q',directory)),(0x411,struct.pack('!H',page))]
    more=bool(h[4]&32);token=None;entries=[]
    for tag,value in f[2:]:
        if tag==0x414:
            assert token is None and len(value)==96;token=value
        else:
            assert tag==0x413
            nested=fields(value);d=dict(nested);assert len(d)==len(nested)
            assert set(d) in ({0x401,0x402,0x403,0x404,0x405,0x406,0x407},{0x401,0x402,0x403,0x404,0x405,0x406,0x407,0x408})
            assert d[0x402]==struct.pack('!Q',directory) and 1<=len(d[0x403])<=255
            entries.append(d)
    ids=[int.from_bytes(d[0x401],'big') for d in entries]
    assert len(entries)<=page and ids==sorted(set(ids)) and more==(token is not None)
    if more:assert len(entries)==page
    return entries,token,32+len(body)

def real(server, helper, endpoint, user, password_file, database):
    os.umask(0o077)
    base = Path(password_file).parent
    cert, key = base/'list-cert.pem', base/'list-key.pem'
    with (base/'list-openssl.log').open('xb') as log:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)], stdout=log, stderr=log, check=True, timeout=10)
    context = ssl.create_default_context(cafile=str(cert))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    config = base/'list-client.cnf'
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

    def start(name, list_budget=32768, checked=True):
        with socket.socket() as bound:
            bound.bind(('127.0.0.1', 0)); port = bound.getsockname()[1]
        args = ['127.0.0.1', str(port), str(cert), str(key), endpoint, user, password_file, database, '60000']
        command = [helper, '--child', *args, '4096', '4096', '4096', str(list_budget)] if checked else [server, *args]
        path = base/('list-'+name+'.log'); log = path.open('xb')
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
        assert (v['queues_closed'], v['queues_drained']) == ((31,30) if 'fd_before' in v else (127,126)) and v['final_drain_turns'] > 0
        assert v['audit_created'] == v['audit_joined']
        if 'fd_before' in v: assert v['fd_before'] == v['fd_after']
        if sig:
            assert v['signal'] == sig and v['faults_at_stop'] == v['stat_faults_at_stop'] == v['root_faults_at_stop'] == v['list_faults_at_stop'] == 0
        return v

    def login(peer, seq=1, bob=False):
        wire = packet(0x101, seq, tlv(1,b'Bob_7')+tlv(2,b'Correct!8')+tlv(3,bytes(16))) if bob else frame(True,seq)
        peer.sendall(wire); return session_response(peer,0x101,seq)

    def closed(peer):
        try: assert peer.recv(1) == b''
        except (ssl.SSLEOFError, ConnectionResetError): pass

    try:
        child,port,path=start('normal',checked=False)
        with connect(port) as peer:
            roots=[]
            for seq,body in [(1,None),(2,tlv(1,b'Bob_7')+tlv(2,b'Correct!8'))]:
                peer.sendall(frame(False,seq) if body is None else packet(0x100,seq,body))
                h,v=read_response(peer);assert h[5]==0;roots.append(int.from_bytes(v[2],'big'))
            handle,identity=login(peer,3);actor=int.from_bytes(identity[1],'big')
            sid=int(sql('SELECT id FROM sessions WHERE user_id='+str(actor)+' AND status=1;'))
            peer.sendall(root_frame(4,handle));root_response(peer,4,handle=handle,root=roots[0])
            # 130 visible max-name hashed files, plus an empty subdirectory and Bob's own child.
            object_hash=bytes(range(32))
            sql("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(X'"+object_hash.hex()+"',18446744073709551615,2,130,1,42,99,99);")
            rows=[]
            for i in range(130):
                name=(b'\xff'+str(i).encode().rjust(3,b'0')+b'Q'*251)
                rows.append('('+str(1000+i)+','+str(actor)+','+str(roots[0])+",X'"+name.hex()+"',2,2,X'"+object_hash.hex()+"',18446744073709551615,42,99)")
            rows.append('(2000,'+str(actor)+','+str(roots[0])+",X'656d707479',1,2,NULL,0,42,99)")
            sql('INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms) VALUES'+','.join(rows)+';')
            before=snapshot()
            peer.sendall(list_frame(5,roots[0]));list_response(peer,5,1101)
            peer.sendall(list_frame(6,roots[1],handle));list_response(peer,6,1201)
            peer.sendall(list_frame(7,999999,handle));list_response(peer,7,1201)
            peer.sendall(list_frame(8,1000,handle));list_response(peer,8,1201)
            split=list_frame(9,roots[0],handle);peer.sendall(split[:17]);peer.sendall(split[17:39]);peer.sendall(split[39:])
            first,token,n=list_response(peer,9,handle=handle,directory=roots[0]);assert n==23510 and len(first)==64 and token
            for i,v in enumerate(first):
                assert int.from_bytes(v[0x401],'big')==1000+i and len(v[0x403])==255 and v[0x408]==object_hash
            peer.sendall(list_frame(10,roots[0],handle,token=token));second,token2,n=list_response(peer,10,handle=handle,directory=roots[0]);assert len(second)==64 and token2 and n==23510
            peer.sendall(list_frame(11,roots[0],handle,token=token2));last,none,_=list_response(peer,11,handle=handle,directory=roots[0]);assert len(last)==3 and none is None
            assert [int.from_bytes(v[0x401],'big') for v in first+second+last]==list(range(1000,1130))+[2000]
            peer.sendall(list_frame(12,2000,handle));assert list_response(peer,12,handle=handle,directory=2000)==([],None,50)
            peer.sendall(stat_frame(13,1000,handle));h,v=read_response(peer);assert h[5]==0 and v[0x408]==object_hash
            # Bad MAC, wrong directory/page size, and original authentication precedence.
            broken=bytes([token[0]^1])+token[1:]
            for seq,directory,page,t in [(14,roots[0],64,broken),(15,2000,64,token),(16,roots[0],63,token)]:
                peer.sendall(list_frame(seq,directory,handle,page,t));list_response(peer,seq,1001)
            sql('UPDATE users SET status=2 WHERE id='+str(actor))
            peer.sendall(list_frame(17,roots[0],handle,token=broken));list_response(peer,17,1101)
            sql('UPDATE users SET status=1 WHERE id='+str(actor))
            assert snapshot()==before,'LIST/ROOT/STAT altered five-table business state'
            # Same persistent session may resume the complete chain on a different TLS connection.
            with connect(port) as other:
                other.sendall(session_frame(0x103,1,token=identity[3]));resumed,_=session_response(other,0x103,1)
                other.sendall(list_frame(2,roots[0],resumed,token=token));page,_,_=list_response(other,2,handle=resumed,directory=roots[0]);assert len(page)==64
            # A new LOGIN yields a different persistent session, invalidating old pagination context.
            fresh,_=login(peer,18)
            peer.sendall(list_frame(19,roots[0],fresh,token=token));list_response(peer,19,1001)
            # ID keyset has no cross-page snapshot: an inserted higher ID appears, deleted IDs disappear.
            sql('UPDATE file_nodes SET state=3,deleted_at_ms=100,updated_at_ms=100 WHERE id=1064;')
            sql('INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms) VALUES(3000,'+str(actor)+','+str(roots[0])+",X'6e6577',1,2,NULL,0,42,99);")
            # Original session can still resume and use its original token.
            with connect(port) as other:
                other.sendall(session_frame(0x103,1,token=identity[3]));resumed,_=session_response(other,0x103,1)
                other.sendall(list_frame(2,roots[0],resumed,token=token));page,next_token,_=list_response(other,2,handle=resumed,directory=roots[0]);assert int.from_bytes(page[0][0x401],'big')==1065
                other.sendall(list_frame(3,roots[0],resumed,token=next_token));page,_,_=list_response(other,3,handle=resumed,directory=roots[0]);assert int.from_bytes(page[-1][0x401],'big')==3000
            # Coalesced requests use independent sequences; complete large pages may arrive out of order.
            peer.sendall(b''.join(list_frame(seq,2000,fresh) for seq in range(20,28)))
            sequences=set(range(20,28))
            for _ in range(8):list_response(peer,sequences,handle=fresh,directory=2000)
            assert not sequences
            # Well-framed schema errors are bounded local refusals; malformed framing closes.
            before=snapshot()
            valid=tlv(0x410,struct.pack('!Q',roots[0]))+tlv(0x411,struct.pack('!H',64))
            bad_bodies=[b'',valid+tlv(0x411,struct.pack('!H',64)),valid+tlv(0x999,b'x'),
                        tlv(0x410,bytes(8))+tlv(0x411,struct.pack('!H',64))]
            bad_bodies += [tlv(0x410,struct.pack('!Q',roots[0]))+tlv(0x411,struct.pack('!H',n)) for n in [0,65,65535]]
            bad_bodies += [valid+tlv(0x412,bytes(n)) for n in [0,1,95,97]]
            for seq,body in enumerate(bad_bodies,100):
                peer.sendall(packet(0x401,seq,body,fresh));list_response(peer,seq,1001)
            bad_crc=bytearray(list_frame(1,roots[0]));bad_crc[-1]^=1
            for wire in [bad_crc,packet(0x401,0,valid),packet(0x401,1,valid,flags=0x8000),packet(0x401,1,bytes(125))]:
                with connect(port) as other:other.sendall(wire);closed(other)
            for length in [1,31,49,149]:
                with connect(port) as other:other.sendall(list_frame(1,roots[0],token=bytes(96))[:length])
            assert snapshot()==before
            assert child.poll() is None
        state=finish(child,path);assert state['list_final_faults']==0
        print('PASS LIST production: maximum23510 pages, TLS splits/coalescing, ID keyset, empty page, ROOT/STAT, Alice/Bob, bad MAC/context, auth priority, RESUME/new LOGIN, five-table read-only snapshot')
        child,port,path=start('restart')
        with connect(port) as peer:
            peer.sendall(session_frame(0x103,1,token=identity[3]));h,_=session_response(peer,0x103,1)
            peer.sendall(list_frame(2,roots[0],h,token=token));list_response(peer,2,1001)
        finish(child,path)
        print('PASS LIST production: process key restart invalidates old token with the same persistent session')
        child,port,path=start('missing-completion',list_budget=1)
        with connect(port) as peer:
            h,_=login(peer);peer.sendall(list_frame(2,roots[0],h));closed(peer)
        state=finish(child,path,expected=1,sig=None)
        assert state['list_faults_at_stop']==state['list_final_faults']==8 and state['signal']==0
        assert state['faults_at_stop']==state['stat_faults_at_stop']==state['root_faults_at_stop']==0
        print('PASS LIST production: missing completion auto-stops service, independent LIST fault domain, five queues close, four drain, workers joined and FDs restored')
        child,port,path=start('inflight-stop')
        with connect(port) as peer:
            h,_=login(peer)
            blocker=subprocess.Popen(mysql_args(True),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            blocker.stdin.write('START TRANSACTION; SELECT id FROM users WHERE id='+str(actor)+' FOR UPDATE;\n');blocker.stdin.flush()
            with selectors.DefaultSelector() as sel:
                sel.register(blocker.stdout,selectors.EVENT_READ);assert sel.select(5);assert blocker.stdout.readline().strip()==str(actor)
            peer.sendall(b''.join(list_frame(seq,roots[0],h) for seq in range(2,10)))
            until=time.monotonic()+5
            while sql("SELECT COUNT(*) FROM information_schema.innodb_trx WHERE trx_state='LOCK WAIT';",True)=='0':assert time.monotonic()<until
            child.send_signal(signal.SIGINT);blocker.stdin.write('COMMIT;\n');blocker.stdin.flush();blocker.communicate(timeout=5);assert blocker.returncode==0;blocker=None
            state=finish(child,path,sig=None);assert state['signal']==signal.SIGINT and state['list_faults_at_stop']==0
            assert (state['final_faults']|state['stat_final_faults']|state['root_final_faults']|state['list_final_faults']) & ~8 == 0
        print('PASS LIST production: actual InnoDB LOCK WAIT + SIGINT, close-before-join/final drain and clean owner/FD teardown')
    finally:
        if blocker is not None:blocker.kill();blocker.communicate(timeout=5)
        for child,log in children:
            if child.poll() is None:child.kill();child.communicate(timeout=10)
            log.close()

if __name__=='__main__':
    if len(sys.argv)!=8 or sys.argv[1]!='--real':raise SystemExit('invalid LIST invocation')
    real(*sys.argv[2:])
