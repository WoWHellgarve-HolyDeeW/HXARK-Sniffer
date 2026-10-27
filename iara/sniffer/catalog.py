"""Signed compatibility-profile schema and validation."""
import json
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA='hxark-sniffer-compatibility-v1'
ENGINE_ABI=1
MAX_CATALOG=262144
HASH=re.compile(r'[0-9a-f]{64}')
PROFILE_FIELDS={'build','version','image_sha256','protocol','root_rva','vtable_rva',
                'session_offset','slots_offset','slot_stride','slot_count','compressed_opcode',
                'bundle_opcode','proof'}


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate_catalog_field')
        result[key]=value
    return result


def integer(value,minimum,maximum):
    if type(value) is not int or not minimum<=value<=maximum:raise ValueError('invalid_catalog_number')


def validate_profile(p):
    if type(p) is not dict or set(p)!=PROFILE_FIELDS:raise ValueError('invalid_profile_fields')
    integer(p['build'],1,2**31-1)
    if type(p['version']) is not str or not re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.'+str(p['build']),p['version']):
        raise ValueError('invalid_profile_version')
    if type(p['image_sha256']) is not str or not HASH.fullmatch(p['image_sha256']):raise ValueError('invalid_profile_hash')
    if p['protocol']!='continued-v1':raise ValueError('engine_update_required')
    for field in ('root_rva','vtable_rva'):integer(p[field],4096,2**30)
    for field in ('session_offset','slots_offset'):integer(p[field],8,4096)
    integer(p['slot_stride'],96,8192);integer(p['slot_count'],1,8)
    for field in ('compressed_opcode','bundle_opcode'):integer(p[field],1,2**32-1)
    if p['compressed_opcode']==p['bundle_opcode']:raise ValueError('invalid_control_opcodes')
    proof=p['proof']
    if type(proof) is not dict or set(proof)!={'receipt_sha256','authenticated_frames','pkt_records','reviewed'}:
        raise ValueError('invalid_profile_proof')
    if proof['reviewed'] is not True or type(proof['receipt_sha256']) is not str or not HASH.fullmatch(proof['receipt_sha256']):
        raise ValueError('profile_not_reviewed')
    integer(proof['authenticated_frames'],1,1000000);integer(proof['pkt_records'],1,10000000)
    return p


def verify(raw,public_key,*,now,allow_expired=False):
    if type(raw) is not bytes or not 1<=len(raw)<=MAX_CATALOG:raise ValueError('catalog_size_limit')
    try:
        envelope=json.loads(raw,object_pairs_hook=unique)
        if type(envelope) is not dict or set(envelope)!={'signed','signature'}:raise ValueError('invalid_catalog_envelope')
        signature=envelope['signature']
        if type(signature) is not str or not re.fullmatch('[0-9a-f]{128}',signature):raise ValueError('invalid_catalog_signature')
        Ed25519PublicKey.from_public_bytes(public_key).verify(bytes.fromhex(signature),canonical(envelope['signed']))
    except InvalidSignature:raise ValueError('invalid_catalog_signature') from None
    value=envelope['signed']
    if type(value) is not dict or set(value)!={'schema','channel','revision','engine_abi','issued_at','expires_at','profiles'}:
        raise ValueError('invalid_catalog_fields')
    if value['schema']!=SCHEMA or value['channel']!='staff':raise ValueError('invalid_catalog_channel')
    if type(value['engine_abi']) is not int or value['engine_abi']!=ENGINE_ABI:raise ValueError('engine_update_required')
    integer(value['revision'],1,2**31-1)
    integer(value['issued_at'],1,2**40);integer(value['expires_at'],1,2**40)
    if not 0<value['expires_at']-value['issued_at']<=90*86400:raise ValueError('invalid_catalog_lifetime')
    if value['issued_at']>now+300:raise ValueError('catalog_from_future')
    if not allow_expired and value['expires_at']<=now:raise ValueError('catalog_expired')
    profiles=value['profiles']
    if type(profiles) is not list or not 1<=len(profiles)<=128:raise ValueError('invalid_catalog_profiles')
    builds=set()
    for profile in profiles:
        validate_profile(profile)
        if profile['build'] in builds:raise ValueError('duplicate_profile_build')
        builds.add(profile['build'])
    return value


def sign(value,private_key):
    # Publisher validates the exact signed representation before releasing it.
    envelope={'signed':value,'signature':private_key.sign(canonical(value)).hex()}
    raw=canonical(envelope)
    verify(raw,private_key.public_key().public_bytes_raw(),now=value['issued_at'])
    return raw
