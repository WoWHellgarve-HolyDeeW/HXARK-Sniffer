"""Test pre-login capture and PKT decoding with localhost traffic."""
from pathlib import Path
import json
import os
import socket
import struct
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.sniffer_capture_start import run_capture
from iara.sniffer.windows_inventory import tcp_rows
from iara.sniffer.session_keys import derive_session,derive_encryption
from iara.sniffer.profiles import BuildProfile
from iara.sniffer.replay import replay
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes


def run(output):
    key=derive_encryption(derive_session(bytes(range(64)),b'c'*32,b's'*32),b'c'*32,b's'*32)
    expected={7:b'fictional client auth',8:b'fictional client message',9:b'fictional server auth',10:b'fictional server message'}
    def wire(direction,ops):
        side='CLIENT TO SERVER' if direction=='client' else 'SERVER TO CLIENT'
        result=('WORLD OF WARCRAFT CONNECTION - '+side+' - V2\n').encode()
        for count,op in enumerate(ops):
            value=struct.pack('<I',op)+expected[op];tag=bytes(12)
            if count:
                nonce=struct.pack('<Q',count)+(b'CLNT' if direction=='client' else b'SRVR')
                c=Cipher(algorithms.AES(key),modes.GCM(nonce)).encryptor()
                value=c.update(value)+c.finalize();tag=c.tag[:12]
            result+=struct.pack('<I',len(value))+tag+value
        return result
    sent,reply=wire('client',[7,8]),wire('server',[9,10])
    def recv(c,n):
        data=b''
        while len(data)<n:
            x=c.recv(n-len(data))
            if not x:raise ValueError('early_eof')
            data+=x
        return data
    errors=[];workers=[];connected=threading.Event();first_at=[None]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(5)
        port=listener.getsockname()[1]
        def exchange():
            try:
                with socket.socket() as client:
                    client.settimeout(4);client.connect(('127.0.0.1',port))
                    with listener.accept()[0] as server:
                        server.settimeout(4)
                        first_at[0]=time.monotonic();connected.set()
                        client.sendall(sent)
                        if recv(server,len(sent))!=sent:raise ValueError('wrong_client')
                        server.sendall(reply)
                        if recv(client,len(reply))!=reply:raise ValueError('wrong_server')
                        # Leave the connection visible to the native PID table,
                        # but deliberately withhold its owner for 250 ms.
                        time.sleep(.7)
            except Exception as exc:errors.append(type(exc).__name__)
        def ready():
            t=threading.Thread(target=exchange,daemon=True);workers.append(t);t.start()
        def owner():
            if not connected.is_set() or time.monotonic()-first_at[0]<.25:return []
            return [(tuple(r['client']),tuple(r['server'])) for r in tcp_rows(os.getpid()) if r['server']==['127.0.0.1',port]]
        receipt=run_capture(output,interface=r'\Device\NPF_Loopback',local='127.0.0.1',servers=[('127.0.0.1',port)],owner=owner,seconds=4,on_ready=ready)
        for t in workers:t.join(5)
        if errors or any(t.is_alive() for t in workers):raise ValueError('synthetic_exchange_failed')
    flows=json.loads((output/'private-flows.json').read_text())
    if len(flows)!=1:raise ValueError('synthetic_owner_not_captured')
    flow=flows[0];pkt=output/'synthetic.pkt'
    profile=BuildProfile(0,'synthetic',None,0x4c000e,0x4c000d,'synthetic_only')
    with (output/flow['file']).open('rb') as f:
        decoded=replay(f,pkt,profile=profile,client=flow['client'],server=flow['server'],keys={'client':key,'server':key},encrypted_from={'client':1,'server':1})
    raw=pkt.read_bytes();pos=66;actual={}
    while pos<len(raw):
        _,_,_,extra,length,op=struct.unpack_from('<IiIiiI',raw,pos)
        if extra or op in actual:raise ValueError('unexpected_pkt_record')
        actual[op]=raw[pos+24:pos+20+length];pos+=20+length
    if actual!=expected or pos!=len(raw):raise ValueError('decoded_payload_mismatch')
    receipt.update({'source':'synthetic_loopback','deferred_owner_ms':250,'initial_syn_preserved':True,
                    'pkt_records_verified':len(actual),'live_70575_verified':False,'decode':decoded})
    (output/'proof.json').write_text(json.dumps(receipt,indent=2));return receipt


if __name__=='__main__':
    print(json.dumps(run(Path(sys.argv[1])),indent=2))
