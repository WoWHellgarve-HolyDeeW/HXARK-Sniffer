"""Sign a compatibility catalog after checking its validation record."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from iara.sniffer.catalog import SCHEMA,validate_profile,integer,sign,verify
from iara.sniffer.local_secrets import unprotect
from iara.sniffer.trust import PUBLIC_KEY
from iara.sniffer.updates import read_bounded


def release(profile,receipt_raw,key,*,revision,issued_at,days=30,previous_raw=None):
    validate_profile(profile);integer(days,1,90)
    receipt=json.loads(receipt_raw)
    if (hashlib.sha256(receipt_raw).hexdigest()!=profile['proof']['receipt_sha256']
            or receipt.get('build')!=profile['build']
            or receipt.get('authenticated_frames')!=profile['proof']['authenticated_frames']
            or receipt.get('records')!=profile['proof']['pkt_records']
            or any(receipt.get(k) is not True for k in ('live_capture_verified','transport_complete',
                'container_complete','build_compatibility_verified','handshake_validated'))
            or receipt.get('session_uploaded') is not False
            or receipt.get('scope')!='one_complete_continued_session_connection'):
        raise ValueError('release_evidence_mismatch')
    check=receipt.get('independent_container_check',{})
    if check.get('complete') is not True or check.get('records')!=receipt['records'] or check.get('build')!=receipt['build']:
        raise ValueError('independent_check_required')
    profiles={}
    if previous_raw is not None:
        previous=verify(previous_raw,key.public_key().public_bytes_raw(),now=issued_at,allow_expired=True)
        if revision<=previous['revision']:raise ValueError('revision_must_increase')
        profiles={p['build']:p for p in previous['profiles']}
    profiles[profile['build']]=profile
    return sign({'schema':SCHEMA,'channel':'staff','revision':revision,'engine_abi':1,
        'issued_at':issued_at,'expires_at':issued_at+days*86400,'profiles':[profiles[b] for b in sorted(profiles)]},key)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('profile',type=Path);p.add_argument('receipt',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--key',required=True,type=Path);p.add_argument('--revision',required=True,type=int)
    p.add_argument('--previous',type=Path,help='Verified prior catalog; retained profiles are not dropped.')
    p.add_argument('--reviewed-receipt-sha256',required=True)
    a=p.parse_args()
    raw=read_bounded(a.receipt)
    if hashlib.sha256(raw).hexdigest()!=a.reviewed_receipt_sha256:raise ValueError('reviewed_receipt_changed')
    profile=json.loads(read_bounded(a.profile));key=Ed25519PrivateKey.from_private_bytes(unprotect(read_bounded(a.key)))
    if key.public_key().public_bytes_raw()!=PUBLIC_KEY:raise ValueError('wrong_release_key')
    catalog=release(profile,raw,key,revision=a.revision,issued_at=int(time.time()),
        previous_raw=read_bounded(a.previous) if a.previous else None)
    with a.output.open('xb') as f:f.write(catalog)
    print(json.dumps({'written':True,'revision':a.revision,'build':profile['build'],
        'catalog_sha256':hashlib.sha256(catalog).hexdigest(),'private_content_included':False}))


if __name__=='__main__':main()
