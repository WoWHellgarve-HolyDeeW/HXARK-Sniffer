"""Decode PCAP using a local key manifest.

Fields: build, client/server [IPv4, port], encrypted_from {client: n, server: n},
keys {client: hex32, server: hex32}. Unvalidated profiles require --experimental.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from iara.sniffer.profiles import select_profile
from iara.sniffer.replay import replay

SAFE_CODES=frozenset('''unsupported_build build_requires_validation client_fingerprint_mismatch
manifest_limit invalid_endpoint invalid_key encryption_boundary_required session_key_required
authentication_failed encryption_key_required counter_exhausted invalid_crypto_frame
missing_tcp_handshake connection_reused conflicting_fin connection_reset missing_direction
connection_not_fully_captured selected_connection_not_found timestamp_out_of_range
incomplete_stream conflicting_overlap history_unavailable packet_limit byte_limit
unsupported_capture_format unsupported_link_type fragmented_ipv4 truncated_pcap
truncated_or_invalid_record invalid_timestamp incomplete greeting body_length body_size
chunk_limit depth_limit output_limit decoded_size flush_marker compressed_checksum
decoded_checksum inflate_state inflate_error bundle_header bundle_length message_limit
decoded_batch_limit capture_size_limit'''.split())

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('pcap',type=Path);p.add_argument('manifest',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--experimental',action='store_true');a=p.parse_args()
    # Bound manifest reads and keep key values out of errors.
    try:
        with a.manifest.open('rb') as f:raw=f.read(4097)
        if len(raw)>4096:raise ValueError('manifest_limit')
        v=json.loads(raw)
        profile=select_profile(v['build'],experimental=a.experimental,image_sha256=v.get('image_sha256'))
        keys={d:bytes.fromhex(v['keys'][d]) for d in ('client','server')}
        with a.pcap.open('rb') as f:
            result=replay(f,a.output,profile=profile,client=v['client'],server=v['server'],
                          keys=keys,encrypted_from=v['encrypted_from'])
        print(json.dumps(result));return 0
    except (OSError,ValueError,KeyError,TypeError,OverflowError,ModuleNotFoundError) as exc:
        code='decode_failed'
        if isinstance(exc,FileExistsError):code='destination_exists'
        elif isinstance(exc,PermissionError):code='local_file_access_denied'
        elif isinstance(exc,OSError):code='local_io_error'
        elif isinstance(exc,ModuleNotFoundError):code='dependency_missing'
        elif type(exc) is ValueError and str(exc) in SAFE_CODES:code=str(exc)
        print(json.dumps({'ok':False,'code':code,'finalized':False,
                          'hint':'Check the build, capture completeness, keys and encryption boundaries.'}))
        return 1


if __name__=='__main__':raise SystemExit(main())
