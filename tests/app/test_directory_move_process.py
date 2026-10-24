"""Nine-command production TLS + native MySQL; independent wire and database observations."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import concurrent.futures, os, re, selectors, signal, socket, ssl, struct, subprocess, time
from test_directory_stat_process import packet, tlv, read_response, stat_frame
from test_directory_root_process import root_frame, root_response
from test_directory_list_process import list_frame, list_response
from test_auth_process import frame, session_frame, session_response


def mkdir_frame(sequence, parent, name, key, handle=0):
    return packet(0x403, sequence, tlv(0x402,struct.pack('!Q',parent))+tlv(0x403,name)+tlv(0x420,key), handle)


def mkdir_response(peer, sequence, key, handle, status=0):
    h, values=read_response(peer)
    assert h[3]==0x403 and h[7]==sequence and h[5]==status
    assert h[8]==(handle if status==0 else 0)
    if status:
        assert not values and h[6]==0
        return 0
    assert h[6]==32 and set(values)=={0x401,0x420} and values[0x420]==key
    node=int.from_bytes(values[0x401],'big');assert node>0
    return node


def move_frame(sequence,source,parent,name,key,handle=0):
    return packet(0x405,sequence,tlv(0x401,struct.pack('!Q',source))+tlv(0x430,struct.pack('!Q',parent))+tlv(0x431,name)+tlv(0x420,key),handle)


def move_response(peer,sequence,source,key,handle,status=0):
    head,values=read_response(peer)
    assert head[3]==0x405 and head[7]==sequence and head[5]==status,(sequence,head[5],status)
    assert head[8]==(handle if status==0 else 0)
    if status:
        assert not values and head[6]==0;return 0
    assert head[6]==32 and set(values)=={0x401,0x420} and values[0x420]==key
    assert int.from_bytes(values[0x401],'big')==source;return source


def real(server, helper, endpoint, user, password_file, database):
    os.umask(0o077)
    base=Path(password_file).parent;cert=base/'move-cert.pem';pem=base/'move-key.pem'
    with (base/'move-openssl.log').open('xb') as log:
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
                        '-addext','subjectAltName=DNS:localhost','-keyout',str(pem),'-out',str(cert)],stdout=log,stderr=log,check=True,timeout=10)
    context=ssl.create_default_context(cafile=str(cert));context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
    config=base/'move-client.cnf';config.write_text('[client]\nuser='+user+'\npassword='+Path(password_file).read_text().strip()+'\n')
    children=[];blocker=None
    def mysql_args(admin=False):
        return ['mysql','--defaults-file='+str(base/'root.cnf' if admin else config),'--protocol=SOCKET','--socket='+endpoint,'--database='+database,'--batch','--skip-column-names','--unbuffered']
    def sql(query,admin=False):
        p=subprocess.run(mysql_args(admin),input=query,text=True,capture_output=True,timeout=10)
        assert p.returncode==0,'owned MOVE fixture SQL failed; diagnostics kept private'
        return p.stdout.strip()
    def start(name, budget=4096, production=False, barrier=None):
        with socket.socket() as bound:bound.bind(('127.0.0.1',0));port=bound.getsockname()[1]
        args=['127.0.0.1',str(port),str(cert),str(pem),endpoint,user,password_file,database,'600000']
        command=[server,*args] if production else [helper,'--child',*args,'4096','4096','4096','32768','4096',str(budget)]
        path=base/('move-'+name+'.log');log=path.open('xb');child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=log,env={**os.environ,**({'VIREO_MOVE_TEST_BARRIER':str(barrier)} if barrier else {})});children.append((child,log))
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout,selectors.EVENT_READ);assert selector.select(15),'MOVE readiness timeout'
            assert child.stdout.readline()==b'vireo-auth-server ready\n'
        return child,port,path
    def connect(port):return context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=15),server_hostname='localhost')
    def finish(child,path,expected=0,sig=signal.SIGTERM):
        if sig:child.send_signal(sig)
        child.communicate(timeout=20);assert child.returncode==expected,'MOVE process failed; private log retained'
        text=path.read_text();assert 'AddressSanitizer' not in text and 'runtime error:' not in text
        v={k:int(n) for k,n in re.findall(r'(\w+)=(-?\d+)',text)}
        assert v['clean']==1 and v['cleanup']==0 and v['created']==v['joined']==2
        assert (v['queues_closed'],v['queues_drained'])==(127,126) and v['final_drain_turns']>0
        assert v['audit_created']==v['audit_joined']
        if 'fd_before' in v:assert v['fd_before']==v['fd_after']
        if sig:assert v['signal']==sig
        return v
    def login(peer,seq=1,bob=False):
        wire=packet(0x101,seq,tlv(1,b'Bob_7')+tlv(2,b'Correct!8')+tlv(3,bytes(16))) if bob else frame(True,seq)
        peer.sendall(wire);return session_response(peer,0x101,seq)
    def closed(peer):
        try:assert peer.recv(1)==b''
        except (ssl.SSLEOFError,ConnectionResetError):pass
    def receipt(actor,key):
        return sql("SELECT result_node_id FROM directory_write_receipts WHERE user_id="+str(actor)+" AND command=1029 AND idempotency_key=X'"+key.hex()+"';")
    def write_snapshot():
        return sql('SELECT id,owner_id,parent_id,HEX(name),node_type,state,size,HEX(object_hash),created_at_ms,updated_at_ms FROM file_nodes ORDER BY id;'
                   'SELECT * FROM directory_write_receipts ORDER BY user_id,command,idempotency_key;'
                   'SELECT id,HEX(request_id),user_id,session_id,action,target_id FROM operation_audits WHERE action IN (5,6) ORDER BY id;'
                   'SELECT HEX(object_hash),size,state,ref_count FROM objects ORDER BY object_hash;')
    def integrity():
        assert sql('SELECT COUNT(*) FROM directory_write_receipts r LEFT JOIN operation_audits a ON a.id=r.audit_id '
                   'LEFT JOIN file_nodes n ON n.id=r.result_node_id WHERE a.id IS NULL OR a.action<>IF(r.command=1029,6,5) OR a.status<>0 OR a.user_id<>r.user_id OR a.target_id<>r.result_node_id OR n.id IS NULL;')=='0'
        assert sql('SELECT COUNT(*) FROM directory_write_receipts;')==sql('SELECT COUNT(*) FROM operation_audits WHERE action IN (5,6) AND status=0;')
    serial=0
    def key():
        nonlocal serial
        serial+=1;return serial.to_bytes(16,'big')
    def mkdir(peer,seq,parent,name,h):
        k=key();peer.sendall(mkdir_frame(seq,parent,name,k,h));return mkdir_response(peer,seq,k,h)
    def move(peer,seq,source,parent,name,k,h,status=0):
        peer.sendall(move_frame(seq,source,parent,name,k,h));return move_response(peer,seq,source,k,h,status)
    def assert_stat(peer,seq,node,parent,name,h):
        peer.sendall(stat_frame(seq,node,h));head,v=read_response(peer)
        assert head[5]==0 and head[7]==seq and int.from_bytes(v[0x401],'big')==node
        assert int.from_bytes(v[0x402],'big')==parent and v[0x403]==name
    def wait_receipt(actor,k):
        until=time.monotonic()+8
        while not receipt(actor,k):assert time.monotonic()<until
    try:
        child,port,path=start('normal',production=True)
        with connect(port) as peer:
            roots=[]
            for seq,body in [(1,None),(2,tlv(1,b'Bob_7')+tlv(2,b'Correct!8'))]:
                peer.sendall(frame(False,seq) if body is None else packet(0x100,seq,body));head,v=read_response(peer);assert head[5]==0;roots.append(int.from_bytes(v[2],'big'))
            h,identity=login(peer,3);actor=int.from_bytes(identity[1],'big')
            peer.sendall(root_frame(4,h));root_response(peer,4,handle=h,root=roots[0])
            source=mkdir(peer,5,roots[0],b'source',h);target=mkdir(peer,6,roots[0],b'target',h);desc=mkdir(peer,7,source,b'descendant',h)
            file=mkdir(peer,8,roots[0],b'file',h)
            sql("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(UNHEX(REPEAT('a5',32)),91,2,1,1,1000,1000,1000);")
            sql("UPDATE file_nodes SET node_type=2,object_hash=UNHEX(REPEAT('a5',32)),size=91 WHERE id="+str(file))
            payload=sql('SELECT node_type,HEX(object_hash),size,created_at_ms FROM file_nodes WHERE id='+str(file))
            k1,k2,k3=key(),key(),key()
            move(peer,9,source,roots[0],b'renamed',k1,h);assert_stat(peer,10,source,roots[0],b'renamed',h)
            move(peer,11,source,target,b'renamed',k2,h);assert_stat(peer,12,source,target,b'renamed',h)
            move(peer,13,source,roots[0],b'both-changed',k3,h);assert_stat(peer,14,source,roots[0],b'both-changed',h)
            assert sql('SELECT parent_id FROM file_nodes WHERE id='+str(desc))==str(source)
            move(peer,15,file,target,b'moved-file',key(),h)
            assert sql('SELECT node_type,HEX(object_hash),size,created_at_ms FROM file_nodes WHERE id='+str(file))==payload
            assert sql('SELECT ref_count FROM objects;')=='1'
            # Historical recovery returns the source without repeating the old mutation.
            before=write_snapshot();move(peer,16,source,roots[0],b'renamed',k1,h);assert write_snapshot()==before
            for seq,src,dst,name in [(17,desc,roots[0],b'renamed'),(18,source,target,b'renamed'),(19,source,roots[0],b'other')]:
                move(peer,seq,src,dst,name,k1,h,1206);assert write_snapshot()==before
            # First no-op creates one receipt; repeats create none.
            kn=key();move(peer,20,source,roots[0],b'both-changed',kn,h);before=write_snapshot();move(peer,21,source,roots[0],b'both-changed',kn,h);assert write_snapshot()==before
            occupied=mkdir(peer,22,target,b'occupied',h)
            rejected=[(roots[0],target,b'root',1102),(source,source,b'self',1206),(source,desc,b'cycle',1206),
                      (source,target,b'occupied',1206),(source,roots[1],b'foreign',1201),(roots[1],target,b'foreign-source',1201),
                      (source,file,b'non-directory',1201),(2**64-1,target,b'missing',1201),(source,target,b'e\xcc\x81',1203)]
            before=write_snapshot()
            for seq,(src,dst,name,status) in enumerate(rejected,23):
                move(peer,seq,src,dst,name,key(),h,status);assert write_snapshot()==before
            move(peer,33,source,target,b'\xc3\xa9',key(),h)
            long_key=key();long_name=b'L'*255;wire=move_frame(34,source,roots[0],long_name,long_key,h);assert len(wire)==335
            peer.sendall(wire[:17]);peer.sendall(wire[17:334]);peer.sendall(wire[334:]);move_response(peer,34,source,long_key,h)
            ka,kb=key(),key();peer.sendall(move_frame(35,source,target,b'coalesced',ka,h)+move_frame(36,file,roots[0],b'coalesced-file',kb,h))
            seen=set()
            for _ in range(2):
                head,v=read_response(peer);assert head[3]==0x405 and head[5]==0 and head[7] in {35,36} and head[7] not in seen
                assert v[0x420]==(ka if head[7]==35 else kb) and int.from_bytes(v[0x401],'big')==(source if head[7]==35 else file);seen.add(head[7])
            peer.sendall(list_frame(37,target,h));entries,token,_=list_response(peer,37,handle=h,directory=target);assert token is None and any(int.from_bytes(v[0x401],'big')==source for v in entries)
            move(peer,38,source,target,b'unauthorized',key(),0,1101)
            with connect(port) as other:
                oh,_=login(other);before=write_snapshot();move(other,2,source,roots[0],b'renamed',k1,oh);assert write_snapshot()==before
                concurrent_key=key()
                def exchange(p,seq,handle):return move(p,seq,source,roots[0],b'parallel',concurrent_key,handle)
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    a=pool.submit(exchange,peer,39,h);b=pool.submit(exchange,other,3,oh);assert a.result()==b.result()==source
                other.sendall(session_frame(0x102,4,handle=oh));session_response(other,0x102,4)
                move(other,5,source,target,b'after-logout',key(),oh,1101)
            with connect(port) as resumed:
                resumed.sendall(session_frame(0x103,1,token=identity[3]));rh,_=session_response(resumed,0x103,1)
                before=write_snapshot();move(resumed,2,source,roots[0],b'renamed',k1,rh);assert write_snapshot()==before
            with connect(port) as bob:
                bh,_=login(bob,bob=True);bob_source=mkdir(bob,2,roots[1],b'bob-source',bh)
                move(bob,3,bob_source,roots[1],b'bob-renamed',k1,bh)
                move(bob,4,source,roots[1],b'hidden',key(),bh,1201)
            # A native fixture chain reaches the 257-node ancestry limit.
            sql('SET @p='+str(roots[0])+';'+''.join("INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,size,created_at_ms,updated_at_ms) VALUES("+str(actor)+",@p,'depth',1,2,0,1000,1000);SET @p=LAST_INSERT_ID();" for _ in range(256))+'SELECT @p;')
            deepest=int(sql("SELECT MAX(id) FROM file_nodes WHERE owner_id="+str(actor)))
            before=write_snapshot();move(peer,40,source,deepest,b'bounded',key(),h,1206);assert write_snapshot()==before
            lost_key=key()
            with connect(port) as lost:
                lh,_=login(lost);lost.sendall(move_frame(2,source,target,b'unread',lost_key,lh));wait_receipt(actor,lost_key)
            integrity()
        state=finish(child,path);assert state['move_final_faults']==0
        print('PASS MOVE production: nine commands, three move forms, descendant/file/hash/refcount invariance, historic/noop recovery, payload conflicts, roots/cycles/name/NFC/isolation/ancestry limit, 335-byte split/coalesced TLS, concurrent/new Session/RESUME/logout')
        child,port,path=start('restart')
        with connect(port) as peer:
            h,_=login(peer);before=write_snapshot();move(peer,2,source,target,b'unread',lost_key,h);assert write_snapshot()==before
        finish(child,path)
        print('PASS MOVE restart: durable unread receipt recovers without a second mutation or success audit; no precise COMMIT reply-loss claim')
        failed_key=key();child,port,path=start('missing-completion',budget=1)
        with connect(port) as peer:
            h,_=login(peer);peer.sendall(move_frame(2,source,roots[0],b'committed-unpublished',failed_key,h));closed(peer)
        state=finish(child,path,expected=1,sig=None)
        assert state['move_faults_at_stop']==state['move_final_faults']==8 and state['signal']==0
        assert not(state['faults_at_stop']|state['stat_faults_at_stop']|state['root_faults_at_stop']|state['list_faults_at_stop']|state['mkdir_faults_at_stop'])
        assert receipt(actor,failed_key);integrity()
        child,port,path=start('recover-publication-failure')
        with connect(port) as peer:
            h,_=login(peer);before=write_snapshot();move(peer,2,source,roots[0],b'committed-unpublished',failed_key,h);assert write_snapshot()==before
        finish(child,path)
        print('PASS MOVE actual commit with missing completion: isolated PUBLISH=8, seven closes, six drains and recovery')
        # Test-only publication barrier after actual SQL; independently observe COMMITTED,
        # then advance the helper monotonic sample by 11s without pausing native threads.
        barrier=base/'move-clock-advance';child,port,path=start('soft-deadline',barrier=barrier)
        with connect(port) as peer:
            h,_=login(peer);timeout_key=key()
            peer.sendall(move_frame(2,source,target,b'soft-deadline',timeout_key,h));wait_receipt(actor,timeout_key)
            barrier.touch();move_response(peer,2,source,timeout_key,h,1906)
            before=write_snapshot();move(peer,3,source,target,b'soft-deadline',timeout_key,h);assert write_snapshot()==before
        finish(child,path)
        print('PASS MOVE soft deadline: real SQL commit observed independently, test-only publication barrier/monotonic +11s, TIMEOUT then original-key recovery')
        child,port,path=start('inflight-stop')
        with connect(port) as peer:
            h,_=login(peer)
            blocker=subprocess.Popen(mysql_args(True),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            blocker.stdin.write('START TRANSACTION; SELECT id FROM users WHERE id='+str(actor)+' FOR UPDATE;\n');blocker.stdin.flush()
            with selectors.DefaultSelector() as selector:
                selector.register(blocker.stdout,selectors.EVENT_READ);assert selector.select(5);assert blocker.stdout.readline().strip()==str(actor)
            peer.sendall(move_frame(2,source,roots[0],b'stopping',key(),h)+root_frame(3,h)+stat_frame(4,file,h)+list_frame(5,roots[0],h)+mkdir_frame(6,roots[0],b'stop-mkdir',key(),h))
            until=time.monotonic()+8
            while sql("SELECT COUNT(*) FROM information_schema.innodb_trx WHERE trx_state='LOCK WAIT';",True)=='0':assert time.monotonic()<until
            child.send_signal(signal.SIGINT);blocker.stdin.write('COMMIT;\n');blocker.stdin.flush();blocker.communicate(timeout=5);assert blocker.returncode==0;blocker=None
            state=finish(child,path,sig=None);assert state['signal']==signal.SIGINT
            assert not((state['final_faults']|state['stat_final_faults']|state['root_final_faults']|state['list_final_faults']|state['mkdir_final_faults']|state['move_final_faults'])&~8)
        integrity()
        print('PASS MOVE native lock wait plus SIGINT: mixed queues, seven closes before join and six final drains, FD restored')
    finally:
        if blocker is not None:blocker.kill();blocker.communicate(timeout=5)
        for child,log in children:
            if child.poll() is None:child.kill();child.communicate(timeout=10)
            log.close()

if __name__=='__main__':
    if len(sys.argv)!=8 or sys.argv[1]!='--real':raise SystemExit('invalid MOVE invocation')
    real(*sys.argv[2:])
