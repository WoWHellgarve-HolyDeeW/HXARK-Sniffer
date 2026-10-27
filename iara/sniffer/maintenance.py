"""Build compatibility checks and maintenance records."""
import hashlib
import json
from pathlib import Path
from .profiles import active_profiles
from .windows_inventory import fixed_version


NEXT_ACTION={'needs_build_analysis':'create_isolated_candidate',
             'fingerprint_changed':'inspect_changed_image',
             'ready':'record_authorized_session',
             'needs_live_validation':'validate_candidate_locally'}


def triage(build,digest):
    from .catalog import HASH,integer
    integer(build,1,2**31-1)
    if type(digest) is not str or not HASH.fullmatch(digest):raise ValueError('invalid_profile_hash')
    profile=active_profiles().get(build)
    state=('needs_build_analysis' if profile is None else
           'fingerprint_changed' if digest!=profile.image_sha256 else
           'ready' if profile.live_verified and profile.layout is not None else 'needs_live_validation')
    return {'schema':'hxark-build-observation-v1','build':build,'image_sha256':digest,
            'state':state,'capture_allowed':state=='ready','private_data_included':False,
            'next_action':NEXT_ACTION[state]}


def inspect_build(wow):
    wow=Path(wow).resolve(strict=True)
    build,_=fixed_version(wow)
    with wow.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
    return triage(build,digest)


def prepare_job(observation,output):
    allowed={'schema','build','image_sha256','state','capture_allowed','private_data_included','next_action'}
    if type(observation) is not dict or set(observation)!=allowed or observation['private_data_included'] is not False:
        raise ValueError('invalid_build_observation')
    from .catalog import HASH,integer
    integer(observation['build'],1,2**31-1)
    if type(observation['image_sha256']) is not str or not HASH.fullmatch(observation['image_sha256']):raise ValueError('invalid_profile_hash')
    if observation['state'] not in ('needs_build_analysis','fingerprint_changed','needs_live_validation'):
        raise ValueError('maintenance_not_needed')
    if (observation['schema']!='hxark-build-observation-v1' or observation['capture_allowed'] is not False
            or observation['next_action']!=NEXT_ACTION[observation['state']]):
        raise ValueError('invalid_build_observation')
    job={'schema':'hxark-engineering-job-v1','kind':'sniffer_build_compatibility','observation':observation,
         'network_capture_uploaded':False,
         'phases':['inspect_local_build','propose_data_profile_or_code_change','run_synthetic_regressions',
                   'validate_authorized_live_capture','review_receipts','sign_staff_catalog'],
         'release_gate':{'independent_tests':True,'live_authenticated_capture':True,'supervisor_review':True},
         'forbidden':['publish_unverified_profile','upload_session_keys','upload_private_capture','modify_game']}
    Path(output).mkdir(parents=True,exist_ok=False)
    (Path(output)/'job.json').write_text(json.dumps(job,indent=2),encoding='utf-8')
    return job
