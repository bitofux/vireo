"""Ten-command production TLS + MySQL NODE_REMOVE lifecycle."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import os, re, selectors, signal, socket, ssl, struct, subprocess, time
from test_directory_stat_process import packet, tlv, read_response, stat_frame
from test_directory_root_process import root_frame, root_response
from test_directory_list_process import list_frame, list_response
from test_directory_mkdir_process import mkdir_frame, mkdir_response
from test_auth_process import frame, session_response


def remove_frame(sequence, node, key, handle):
    return packet(0x404,sequence,tlv(0x401,struct.pack('!Q',node))+tlv(0x420,key),handle)


def remove_response(peer, sequence, node, key, handle, status=0):
    head,values=read_response(peer)
    assert head[3]==0x404 and head[7]==sequence and head[5]==status,(sequence,head[5],status)
    assert head[8]==(handle if status==0 else 0)
    if status:
        assert not values and head[6]==0
        return
    assert head[6]==32 and set(values)=={0x401,0x420}
    assert int.from_bytes(values[0x401],'big')==node and values[0x420]==key


def real(server, helper, endpoint, user, password_file, database):
    os.umask(0o077)
    base=Path(password_file).parent;cert=base/'remove-cert.pem';pem=base/'remove-key.pem'
    with (base/'remove-openssl.log').open('xb') as log:
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
            '-addext','subjectAltName=DNS:localhost','-keyout',str(pem),'-out',str(cert)],stdout=log,stderr=log,check=True,timeout=10)
    context=ssl.create_default_context(cafile=str(cert));context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
    config=base/'remove-client.cnf';config.write_text('[client]\nuser='+user+'\npassword='+Path(password_file).read_text().strip()+'\n')
    def sql(query):
        p=subprocess.run(['mysql','--defaults-file='+str(config),'--protocol=SOCKET','--socket='+endpoint,
            '--database='+database,'--batch','--skip-column-names'],input=query,text=True,capture_output=True,timeout=10)
        assert p.returncode==0,'owned REMOVE fixture SQL failed; diagnostics kept private'
        return p.stdout.strip()
    with socket.socket() as bound:bound.bind(('127.0.0.1',0));port=bound.getsockname()[1]
    args=[server,'127.0.0.1',str(port),str(cert),str(pem),endpoint,user,password_file,database,'600000']
    path=base/'remove-process.log'
    with path.open('xb') as log:
        process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=log)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ);assert selector.select(15),'REMOVE readiness timeout'
                assert process.stdout.readline()==b'vireo-auth-server ready\n'
            tls=ssl.create_default_context(cafile=str(cert));tls.minimum_version=tls.maximum_version=ssl.TLSVersion.TLSv1_3
            peer=tls.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=15),server_hostname='localhost')
            roots=[]
            for seq,name,password in [(1,b'Alice_7',b'Correct!7'),(2,b'Bob_7',b'Correct!8')]:
                body=tlv(1,name)+tlv(2,password)
                peer.sendall(packet(0x100,seq,body));head,values=read_response(peer)
                assert head[3]==0x100 and head[7]==seq and head[5]==0
                roots.append(int.from_bytes(values[2],'big'))
            peer.sendall(frame(True,3));handle,identity=session_response(peer,0x101,3);actor=int.from_bytes(identity[1],'big')
            root=roots[0];peer.sendall(root_frame(4,handle));root_response(peer,4,handle=handle,root=root)
            key1=(1).to_bytes(16,'big');key2=(2).to_bytes(16,'big')
            peer.sendall(mkdir_frame(5,root,b'to-remove',key1,handle));node=mkdir_response(peer,5,key1,handle)
            peer.sendall(remove_frame(6,node,key2,handle));remove_response(peer,6,node,key2,handle)
            receipt="SELECT COUNT(*) FROM node_remove_receipts WHERE user_id="+str(actor)+" AND command=1028 AND idempotency_key=X'"+key2.hex()+"';"
            audit="SELECT COUNT(*) FROM operation_audits WHERE user_id="+str(actor)+" AND action=7 AND target_id="+str(node)+";"
            deadline=time.monotonic()+8
            before=(sql(receipt),sql(audit))
            while before!=('1','1') and time.monotonic()<deadline:
                time.sleep(.05);before=(sql(receipt),sql(audit))
            assert before==('1','1')
            peer.sendall(remove_frame(7,node,key2,handle));remove_response(peer,7,node,key2,handle)
            assert (sql(receipt),sql(audit))==before
            conflict_key=(6).to_bytes(16,'big');peer.sendall(mkdir_frame(8,root,b'conflict',conflict_key,handle));other=mkdir_response(peer,8,conflict_key,handle)
            peer.sendall(remove_frame(9,other,key2,handle));remove_response(peer,9,other,key2,handle,1206)
            peer.sendall(remove_frame(10,root,key1,handle));remove_response(peer,10,root,key1,handle,1102)
            parent_key=(3).to_bytes(16,'big');child_key=(4).to_bytes(16,'big')
            peer.sendall(mkdir_frame(11,root,b'parent',parent_key,handle));parent=mkdir_response(peer,11,parent_key,handle)
            peer.sendall(mkdir_frame(12,parent,b'child',child_key,handle));child_node=mkdir_response(peer,12,child_key,handle)
            nonempty_key=(5).to_bytes(16,'big');peer.sendall(remove_frame(13,parent,nonempty_key,handle));remove_response(peer,13,parent,nonempty_key,handle,1205)
            peer.sendall(remove_frame(14,child_node,nonempty_key,0));remove_response(peer,14,child_node,nonempty_key,0,1101)
            peer.sendall(remove_frame(15,child_node,nonempty_key,handle));remove_response(peer,15,child_node,nonempty_key,handle)
            peer.sendall(stat_frame(16,node,handle));stat_head,_=read_response(peer);assert stat_head[5]==1201
            peer.sendall(list_frame(17,root,handle));entries,token,_=list_response(peer,17,handle=handle,directory=root)
            assert token is None and all(int.from_bytes(entry[0x401],'big')!=node for entry in entries)
            peer.close()
        finally:
            if process.poll() is None:process.send_signal(signal.SIGTERM)
            process.communicate(timeout=20)
        assert process.returncode==0,'REMOVE server failed; private log retained'
    log_text=path.read_text();assert 'AddressSanitizer' not in log_text and 'runtime error:' not in log_text
    values={k:int(n) for k,n in re.findall(r'(\w+)=(-?\d+)',log_text)}
    assert values['clean']==1 and values['cleanup']==0 and values['created']==values['joined']==2
    assert (values['queues_closed'],values['queues_drained'])==(255,254) and values['final_drain_turns']>0
    assert values['remove_faults_at_stop']==values['remove_final_faults']==0
    print('PASS REMOVE production: TLS APPLIED/RECOVERED, idempotency conflict boundary, root/non-empty/unauthorized, STAT/LIST hiding, seven completion queues')


if __name__=='__main__':
    if len(sys.argv)!=8 or sys.argv[1]!='--real':raise SystemExit('invalid REMOVE invocation')
    real(*sys.argv[2:])
