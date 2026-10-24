"""Eight-command production TLS + native MySQL; independent wire and database observations."""
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


def real(server, helper, endpoint, user, password_file, database):
    os.umask(0o077)
    base=Path(password_file).parent;cert=base/'mkdir-cert.pem';pem=base/'mkdir-key.pem'
    with (base/'mkdir-openssl.log').open('xb') as log:
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
                        '-addext','subjectAltName=DNS:localhost','-keyout',str(pem),'-out',str(cert)],stdout=log,stderr=log,check=True,timeout=10)
    context=ssl.create_default_context(cafile=str(cert));context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
    config=base/'mkdir-client.cnf';config.write_text('[client]\nuser='+user+'\npassword='+Path(password_file).read_text().strip()+'\n')
    children=[];blocker=None
    def mysql_args(admin=False):
        return ['mysql','--defaults-file='+str(base/'root.cnf' if admin else config),'--protocol=SOCKET','--socket='+endpoint,'--database='+database,'--batch','--skip-column-names','--unbuffered']
    def sql(query,admin=False):
        p=subprocess.run(mysql_args(admin),input=query,text=True,capture_output=True,timeout=10)
        assert p.returncode==0,'owned MKDIR fixture SQL failed; diagnostics kept private'
        return p.stdout.strip()
    def start(name, budget=4096, production=False):
        with socket.socket() as bound:bound.bind(('127.0.0.1',0));port=bound.getsockname()[1]
        args=['127.0.0.1',str(port),str(cert),str(pem),endpoint,user,password_file,database,'600000']
        command=[server,*args] if production else [helper,'--child',*args,'4096','4096','4096','32768',str(budget)]
        path=base/('mkdir-'+name+'.log');log=path.open('xb');child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=log);children.append((child,log))
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout,selectors.EVENT_READ);assert selector.select(15),'MKDIR readiness timeout'
            assert child.stdout.readline()==b'vireo-auth-server ready\n'
        return child,port,path
    def connect(port):return context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=15),server_hostname='localhost')
    def finish(child,path,expected=0,sig=signal.SIGTERM):
        if sig:child.send_signal(sig)
        child.communicate(timeout=20);assert child.returncode==expected,'MKDIR process failed; private log retained'
        text=path.read_text();assert 'AddressSanitizer' not in text and 'runtime error:' not in text
        v={k:int(n) for k,n in re.findall(r'(\w+)=(-?\d+)',text)}
        assert v['clean']==1 and v['cleanup']==0 and v['created']==v['joined']==2
        assert (v['queues_closed'],v['queues_drained'])==((63,62) if 'fd_before' in v else (127,126)) and v['final_drain_turns']>0
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
        return sql("SELECT result_node_id FROM directory_write_receipts WHERE user_id="+str(actor)+" AND command=1027 AND idempotency_key=X'"+key.hex()+"';")
    def write_snapshot():
        return sql('SELECT id,owner_id,parent_id,HEX(name),node_type,state FROM file_nodes ORDER BY id;'
                   'SELECT user_id,command,HEX(idempotency_key),request_parent_id,HEX(request_name),result_node_id,audit_id FROM directory_write_receipts ORDER BY user_id,command,idempotency_key;'
                   'SELECT id,HEX(request_id),user_id,session_id,action,target_id FROM operation_audits WHERE action=5 ORDER BY id;')
    def integrity():
        assert sql('SELECT COUNT(*) FROM directory_write_receipts r LEFT JOIN operation_audits a ON a.id=r.audit_id '
                   'LEFT JOIN file_nodes n ON n.id=r.result_node_id WHERE a.id IS NULL OR a.action<>5 OR a.status<>0 OR a.user_id<>r.user_id OR a.target_id<>r.result_node_id OR n.id IS NULL;')=='0'
        assert sql('SELECT COUNT(*) FROM directory_write_receipts;')==sql('SELECT COUNT(*) FROM operation_audits WHERE action=5 AND status=0;')
    keys=[i.to_bytes(16,'big') for i in range(1,20)]
    try:
        child,port,path=start('normal',production=True)
        with connect(port) as peer:
            roots=[]
            for seq,body in [(1,None),(2,tlv(1,b'Bob_7')+tlv(2,b'Correct!8'))]:
                peer.sendall(frame(False,seq) if body is None else packet(0x100,seq,body));h,v=read_response(peer);assert h[5]==0;roots.append(int.from_bytes(v[2],'big'))
            handle,identity=login(peer,3);actor=int.from_bytes(identity[1],'big')
            peer.sendall(root_frame(4,handle));root_response(peer,4,handle=handle,root=roots[0])
            peer.sendall(mkdir_frame(5,roots[0],b'docs',keys[0],handle));original=mkdir_response(peer,5,keys[0],handle)
            before=write_snapshot();peer.sendall(mkdir_frame(6,roots[0],b'docs',keys[0],handle));assert mkdir_response(peer,6,keys[0],handle)==original
            peer.sendall(mkdir_frame(7,roots[0],b'changed',keys[0],handle));mkdir_response(peer,7,keys[0],handle,1206)
            peer.sendall(mkdir_frame(8,roots[0],b'docs',keys[1],handle));mkdir_response(peer,8,keys[1],handle,1206)
            assert write_snapshot()==before
            peer.sendall(stat_frame(9,original,handle));h,v=read_response(peer);assert h[5]==0 and v[0x403]==b'docs' and int.from_bytes(v[0x402],'big')==roots[0]
            peer.sendall(list_frame(10,roots[0],handle));entries,token,_=list_response(peer,10,handle=handle,directory=roots[0]);assert token is None and any(int.from_bytes(v[0x401],'big')==original for v in entries)
            peer.sendall(mkdir_frame(11,roots[0],b'e\xcc\x81',keys[2],handle));mkdir_response(peer,11,keys[2],handle,1203)
            peer.sendall(mkdir_frame(12,roots[0],b'\xc3\xa9',keys[2],handle));mkdir_response(peer,12,keys[2],handle)
            long_name=b'M'*255;wire=mkdir_frame(13,roots[0],long_name,keys[3],handle);assert len(wire)==323
            peer.sendall(wire[:17]);peer.sendall(wire[17:322]);peer.sendall(wire[322:]);long_node=mkdir_response(peer,13,keys[3],handle)
            assert sql('SELECT OCTET_LENGTH(name) FROM file_nodes WHERE id='+str(long_node))=='255'
            peer.sendall(mkdir_frame(14,roots[0],b'coalesce-a',keys[4],handle)+mkdir_frame(15,roots[0],b'coalesce-b',keys[5],handle))
            seen=set()
            for _ in range(2):
                h,v=read_response(peer);assert h[3]==0x403 and h[5]==0 and h[7] in {14,15} and h[7] not in seen and v[0x420]==keys[h[7]-10];seen.add(h[7])
            before=write_snapshot()
            peer.sendall(mkdir_frame(16,roots[0],b'unauthorized',keys[6]));mkdir_response(peer,16,keys[6],0,1101)
            peer.sendall(mkdir_frame(17,roots[1],b'other-root',keys[6],handle));mkdir_response(peer,17,keys[6],handle,1201)
            sql('UPDATE users SET status=2 WHERE id='+str(actor));peer.sendall(mkdir_frame(18,roots[0],b'disabled',keys[6],handle));mkdir_response(peer,18,keys[6],handle,1101);sql('UPDATE users SET status=1 WHERE id='+str(actor))
            assert write_snapshot()==before
            with connect(port) as bob:
                bob_handle,bob_identity=login(bob,1,True);bob_actor=int.from_bytes(bob_identity[1],'big');assert bob_actor!=actor
                bob.sendall(mkdir_frame(2,roots[1],b'docs',keys[0],bob_handle));assert mkdir_response(bob,2,keys[0],bob_handle)!=original
            with connect(port) as other:
                other_handle,_=login(other)
                wire_a=mkdir_frame(19,roots[0],b'parallel',keys[7],handle);wire_b=mkdir_frame(2,roots[0],b'parallel',keys[7],other_handle)
                def exchange(p,wire,seq,h):p.sendall(wire);return mkdir_response(p,seq,keys[7],h)
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    a=pool.submit(exchange,peer,wire_a,19,handle);b=pool.submit(exchange,other,wire_b,2,other_handle);assert a.result()==b.result()
                assert receipt(actor,keys[7])
                other.sendall(mkdir_frame(3,roots[0],b'docs',keys[0],other_handle));assert mkdir_response(other,3,keys[0],other_handle)==original
                other.sendall(session_frame(0x102,4,handle=other_handle));session_response(other,0x102,4)
                other.sendall(mkdir_frame(5,roots[0],b'logout',keys[8],other_handle));mkdir_response(other,5,keys[8],other_handle,1101)
            # Auth RESUME is the eighth command route exercised together with directory writes.
            with connect(port) as resumed:
                resumed.sendall(session_frame(0x103,1,token=identity[3]));rh,_=session_response(resumed,0x103,1)
                resumed.sendall(mkdir_frame(2,roots[0],b'docs',keys[0],rh));assert mkdir_response(resumed,2,keys[0],rh)==original
            # Setup-only SQL changes: recovering the original ID does not depend on the current node path/state.
            sql("UPDATE file_nodes SET parent_id="+str(long_node)+",name=X'6d6f766564',updated_at_ms=created_at_ms WHERE id="+str(original))
            peer.sendall(mkdir_frame(20,roots[0],b'docs',keys[0],handle));assert mkdir_response(peer,20,keys[0],handle)==original
            sql('UPDATE file_nodes SET state=3,deleted_at_ms=created_at_ms,updated_at_ms=created_at_ms WHERE id='+str(original))
            peer.sendall(mkdir_frame(21,roots[0],b'docs',keys[0],handle));assert mkdir_response(peer,21,keys[0],handle)==original
            # No-read disconnect: wait on an independent durable receipt, intentionally never read the response.
            with connect(port) as lost:
                lh,_=login(lost);lost.sendall(mkdir_frame(2,roots[0],b'no-read',keys[9],lh))
                until=time.monotonic()+8
                while not receipt(actor,keys[9]):assert time.monotonic()<until
            integrity()
        state=finish(child,path);assert state['mkdir_final_faults']==0
        print('PASS MKDIR production: eight commands, create/STAT/LIST, same-key recovery/conflict, isolation/NFC/255-byte split/coalesced TLS, two Session concurrency, new Session/RESUME/logout, moved/deleted original-ID recovery, independent three-write integrity')
        child,port,path=start('restart')
        with connect(port) as peer:
            h,_=login(peer);before=write_snapshot();peer.sendall(mkdir_frame(2,roots[0],b'no-read',keys[9],h));assert mkdir_response(peer,2,keys[9],h)==int(receipt(actor,keys[9]));assert write_snapshot()==before
        finish(child,path)
        print('PASS MKDIR production: client did not read, disconnected, fresh process same database recovers durable ID without new success audit; no claim of precise COMMIT reply-loss injection')
        child,port,path=start('missing-completion',budget=1)
        with connect(port) as peer:
            h,_=login(peer);peer.sendall(mkdir_frame(2,roots[0],b'committed-no-completion',keys[10],h));closed(peer)
        state=finish(child,path,expected=1,sig=None)
        assert state['mkdir_faults_at_stop']==state['mkdir_final_faults']==8 and state['signal']==0
        assert not(state['faults_at_stop']|state['stat_faults_at_stop']|state['root_faults_at_stop']|state['list_faults_at_stop'])
        assert receipt(actor,keys[10]);integrity()
        child,port,path=start('recover-publication-failure')
        with connect(port) as peer:
            h,_=login(peer);before=write_snapshot();peer.sendall(mkdir_frame(2,roots[0],b'committed-no-completion',keys[10],h));assert mkdir_response(peer,2,keys[10],h)==int(receipt(actor,keys[10]));assert write_snapshot()==before
        finish(child,path)
        print('PASS MKDIR production: actual COMMITTED with completion budget failure, independent PUBLISH=8 stops all six queues, five drain, workers/FDs restored, subsequent same-key recovery')
        child,port,path=start('inflight-stop')
        with connect(port) as peer:
            h,_=login(peer)
            blocker=subprocess.Popen(mysql_args(True),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            blocker.stdin.write('START TRANSACTION; SELECT id FROM users WHERE id='+str(actor)+' FOR UPDATE;\n');blocker.stdin.flush()
            with selectors.DefaultSelector() as selector:
                selector.register(blocker.stdout,selectors.EVENT_READ);assert selector.select(5);assert blocker.stdout.readline().strip()==str(actor)
            peer.sendall(mkdir_frame(2,roots[0],b'stopping',keys[11],h)+root_frame(3,h)+stat_frame(4,long_node,h)+list_frame(5,roots[0],h))
            until=time.monotonic()+8
            while sql("SELECT COUNT(*) FROM information_schema.innodb_trx WHERE trx_state='LOCK WAIT';",True)=='0':assert time.monotonic()<until
            child.send_signal(signal.SIGINT);blocker.stdin.write('COMMIT;\n');blocker.stdin.flush();blocker.communicate(timeout=5);assert blocker.returncode==0;blocker=None
            state=finish(child,path,sig=None);assert state['signal']==signal.SIGINT
            assert not((state['final_faults']|state['stat_final_faults']|state['root_final_faults']|state['list_final_faults']|state['mkdir_final_faults'])&~8)
        integrity()
        print('PASS MKDIR production: native InnoDB LOCK WAIT plus SIGINT, mixed directory requests, six independent closes before join and unconditional final five drains')
    finally:
        if blocker is not None:blocker.kill();blocker.communicate(timeout=5)
        for child,log in children:
            if child.poll() is None:child.kill();child.communicate(timeout=10)
            log.close()

if __name__=='__main__':
    if len(sys.argv)!=8 or sys.argv[1]!='--real':raise SystemExit('invalid MKDIR invocation')
    real(*sys.argv[2:])
