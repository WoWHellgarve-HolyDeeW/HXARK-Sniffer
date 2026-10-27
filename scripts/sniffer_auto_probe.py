"""Test automatic capture through Npcap with synthetic localhost traffic."""
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import threading
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from iara.sniffer.automatic import run_session
from iara.sniffer.windows_inventory import tcp_rows
from iara.sniffer.windows_session import IMAGE_SHA256
from iara.sniffer.local_secrets import protect
from iara.sniffer.session_keys import derive_encryption
from iara.capture_inspector import inspect_file


def run(root, *, initial_auth=False, changed_address=False):
    root=Path(root);root.mkdir(parents=True,exist_ok=False)
    wow=root/'synthetic-client.bin';wow.write_bytes(b'fictional client; never executed')
    session=bytes(range(40));cc=b'c'*32;sc=b's'*32
    key=derive_encryption(session,cc,sc)
    initial={
        'client':[struct.pack('<I',0x440003)+bytes(8)+cc+bytes(40),struct.pack('<I',0x440005)],
        'server':[struct.pack('<I',0x4c0000)+bytes(32)+sc+b'\0',struct.pack('<I',0x4c0004)+bytes(68)+b'\x80'],
    }
    if initial_auth:
        ticket=b'fictional realm ticket; no account data'
        initial['client'][0]=(struct.pack('<IQIII',0x440001,0,1,2,3)+cc+bytes(24)+
                              b'\0'+struct.pack('<I',len(ticket))+ticket)
    def wire(direction):
        label='CLIENT TO SERVER' if direction=='client' else 'SERVER TO CLIENT'
        data=('WORLD OF WARCRAFT CONNECTION - '+label+' - V2\n').encode()
        for value in initial[direction]:data+=struct.pack('<I',len(value))+bytes(12)+value
        nonce=struct.pack('<Q',2)+(b'CLNT' if direction=='client' else b'SRVR')
        enc=Cipher(algorithms.AES(key),modes.GCM(nonce)).encryptor()
        # Orgrimmar fixture checks location-based filenames.
        message=(struct.pack('<IiiiI',0x4501f0,1,1637,0,0) if direction=='server'
                 else struct.pack('<I',42)+b'fictional automatic capture')
        value=enc.update(message)+enc.finalize()
        return data+struct.pack('<I',len(value))+enc.tag[:12]+value
    def receive(peer,length):
        result=b''
        while len(result)<length:
            part=peer.recv(length-len(result))
            if not part:raise ValueError('synthetic_early_eof')
            result+=part
        return result
    ended=threading.Event();started=threading.Event();errors=[];workers=[];events=[]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',3724));listener.listen(1);listener.settimeout(8)
        def exchange():
            try:
                with socket.socket() as client:
                    if changed_address:client.bind(('127.0.0.3',0))
                    client.settimeout(6);client.connect(('127.0.0.1',3724))
                    with listener.accept()[0] as server:
                        server.settimeout(6);started.set()
                        sent=wire('client');client.sendall(sent)
                        if receive(server,len(sent))!=sent:raise ValueError('wrong_client_data')
                        reply=wire('server');server.sendall(reply)
                        if receive(client,len(reply))!=reply:raise ValueError('wrong_server_data')
                        time.sleep(2)
            except Exception as exc:errors.append(type(exc).__name__)
            finally:ended.set()
        class Owner:
            pid=None;rows=();exited=False
            def poll(self):
                if started.is_set():self.pid=os.getpid()
                self.exited=ended.is_set()
                self.rows=tuple((tuple(r['client']),tuple(r['server'])) for r in tcp_rows(os.getpid(),connecting=True)
                                if r['server']==['127.0.0.1',3724]) if started.is_set() and not self.exited else ()
            def close(self):pass
        class Archive:
            def __init__(self,_,output,__):self.output=output;self.paths=[]
            def sample(self,pid):
                if self.paths:return
                path=self.output/'private-session-01.dpapi'
                path.write_bytes(protect(json.dumps({'build':70575,'image_sha256':IMAGE_SHA256,'session':session.hex()}).encode()))
                self.paths.append(path)
        def notify(value):
            events.append(value)
            if value['state']=='waiting' and not workers:
                worker=threading.Thread(target=exchange,daemon=True);workers.append(worker);worker.start()
        result=run_session(wow,root/'captures',threading.Event(),notify,
            owner_factory=lambda _:Owner(),archive_factory=Archive,
            adapters_factory=lambda:[('127.0.0.1',r'\Device\NPF_Loopback'),('127.0.0.2',r'\Device\NPF_Loopback')],
            inspect=lambda _:{'capture_allowed':True,'build':70575,'image_sha256':hashlib.sha256(wow.read_bytes()).hexdigest()},
            seconds=12,dumps=root/'dumps')
        for worker in workers:worker.join(8)
    if errors or any(w.is_alive() for w in workers) or not result['complete']:
        raise ValueError('automatic_loopback_failed')
    pkts=list((root/'dumps').glob('*.pkt'))
    if len(pkts)!=1:raise ValueError('unexpected_capture_count')
    proof=inspect_file(pkts[0])
    if not proof['complete'] or proof['records']!=6:raise ValueError('synthetic_pkt_mismatch')
    if not pkts[0].name.startswith('Orgrimmar_b70575_'):raise ValueError('capture_location_name_mismatch')
    if list((root/'captures').glob('*/*.pkt')) or any(p.suffix!='.pkt' for p in (root/'dumps').iterdir()):
        raise ValueError('capture_library_not_separated')
    proof={'automatic_supervisor':True,'source':'synthetic_loopback','no_prepare_or_stop_click':True,
           'authentication_path':'initial' if initial_auth else 'continued',
           'adapter_address_count':2,'capture_interface_count':result['adapter_count'],
           'duplicate_interface_not_started':not any((root/'captures').glob('*/private-adapter-02')),
           'client_address_differs_from_armed_addresses':changed_address,
           'process_exit_simulated':True,'native_process_exit_test_separate':True,
           'pkt_records':proof['records'],'public_dumps_only_pkt':True,'verified_area_label':'Orgrimmar',
           'live_game_capture':False,'result':result,'events':events}
    (root/'proof.json').write_text(json.dumps(proof,indent=2))
    return proof
