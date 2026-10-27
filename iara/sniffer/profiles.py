"""Client fingerprints, session layouts and validated build profiles."""
from dataclasses import dataclass


@dataclass(frozen=True)
class SessionLayout:
    root_rva: int
    vtable_rva: int
    session_offset: int = 0x48
    slots_offset: int = 0x231
    slot_stride: int = 0x148
    slot_count: int = 4


DEFAULT_LAYOUT=SessionLayout(0x4a50750,0x40f8d00)


@dataclass(frozen=True)
class BuildProfile:
    build: int
    version: str
    image_sha256: str | None
    compressed_opcode: int
    bundle_opcode: int
    evidence: str
    live_verified: bool = False
    key_locator_verified: bool = False
    control_opcodes_verified: bool = False
    layout: SessionLayout | None = None


# 69875 control opcodes: static analysis only.
# 70575: complete continued-session capture validated on 2026-10-24.
PROFILES = {
    69875: BuildProfile(69875, '12.1.0.69875', None, 0x4c000e, 0x4c000d,
                        'reference_ymir_static'),
    70575: BuildProfile(70575, '12.1.5.70575',
                        '14b70997cf6c7971a4fcd533b7f421316b6a3da0c8da3710425a8dd20e356a29',
                        0x4c000e, 0x4c000d, 'live_70575_continued_session_20261024',
                        live_verified=True, key_locator_verified=True, control_opcodes_verified=True,
                        layout=DEFAULT_LAYOUT),
}


def active_profiles():
    from .updates import installed,default_store
    from .trust import PUBLIC_KEY
    profiles=dict(PROFILES)
    for value in installed(default_store(),PUBLIC_KEY):
        layout=SessionLayout(**{k:value[k] for k in ('root_rva','vtable_rva','session_offset','slots_offset','slot_stride','slot_count')})
        profiles[value['build']]=BuildProfile(value['build'],value['version'],value['image_sha256'],
            value['compressed_opcode'],value['bundle_opcode'],'signed_continued_session_profile',True,True,True,layout)
    return profiles


def select_profile(build, *, experimental=False, image_sha256=None):
    profiles=active_profiles()
    if type(build) is not int or build not in profiles:
        raise ValueError('unsupported_build')
    if type(experimental) is not bool:
        raise ValueError('invalid_experimental_flag')
    profile=profiles[build]
    if not profile.live_verified and not experimental:
        raise ValueError('build_requires_validation')
    if image_sha256 is not None and image_sha256 != profile.image_sha256:
        raise ValueError('client_fingerprint_mismatch')
    return profile
