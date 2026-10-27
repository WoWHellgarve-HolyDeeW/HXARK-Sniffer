"""Read session fields from the pinned NetClient layout.

Snapshots use read-only process access. GCM validation checks the resulting key.
"""
import ctypes as C
import hashlib
import hmac
import os
from pathlib import Path
import struct
from .session_keys import derive_encryption
from .profiles import DEFAULT_LAYOUT,select_profile
from .windows_inventory import _apis, find_process, process_path, fixed_version, U32, PTR

IMAGE_SHA256 = '14b70997cf6c7971a4fcd533b7f421316b6a3da0c8da3710425a8dd20e356a29'
ROOT_RVA = 0x4a50750
VTABLE_RVA = 0x40f8d00


def read_session(read, base, layout=DEFAULT_LAYOUT):
    """The injected reader must reject partial, guarded or inaccessible reads."""
    def block(address, count):
        value = read(address, count)
        if type(value) is not bytes or len(value) != count:
            raise ValueError('session_memory_unavailable')
        return value
    root_raw = block(base+layout.root_rva,8)
    root = struct.unpack('<Q',root_raw)[0]
    if not 0x10000 <= root < 0x7fff00000000 or root & 7:
        raise ValueError('session_root_unavailable')
    table = struct.pack('<Q',base+layout.vtable_rva)
    if block(root,8) != table:
        raise ValueError('session_type_mismatch')
    session = block(root+layout.session_offset,40)
    if session == bytes(40):
        raise ValueError('session_not_initialized')
    raw_slots = [block(root+n*layout.slot_stride+layout.slots_offset,96) for n in range(layout.slot_count)]
    result = []
    for slot, value in enumerate(raw_slots):
        client,server,key = value[:32],value[32:64],value[64:]
        if client == bytes(32) or server == bytes(32) or key == bytes(32):
            continue
        expected = derive_encryption(session,client,server)
        if not hmac.compare_digest(expected,key):
            raise ValueError('session_key_mismatch')
        result.append({'slot':slot,'client_challenge':client.hex(),
                       'server_challenge':server.hex(),'key':key.hex()})
    # Do not combine fields from a login/realm transition occurring during read.
    if block(base+layout.root_rva,8) != root_raw or block(root,8) != table or block(root+layout.session_offset,40) != session:
        raise ValueError('session_changed_during_read')
    if any(block(root+n*layout.slot_stride+layout.slots_offset,96) != value for n,value in enumerate(raw_slots)):
        raise ValueError('session_changed_during_read')
    if not result:
        raise ValueError('session_not_initialized')
    return {'session':session.hex(),'keys':result}


class _MemoryInfo(C.Structure):
    _fields_=[('base',PTR),('allocation',PTR),('allocation_protect',U32),
              ('size',C.c_size_t),('state',U32),('protect',U32),('type',U32)]


def snapshot(wow, *, expected_pid=None, verified_image=None):
    wow=Path(wow).resolve(strict=True)
    if verified_image is None:
        with wow.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
        build,_=fixed_version(wow)
    else:
        stat=wow.stat()
        if (stat.st_size,stat.st_mtime_ns)!=verified_image['stat']:
            raise ValueError('client_changed_during_capture')
        digest=verified_image['sha256'];build=verified_image['build']
    profile=select_profile(build,image_sha256=digest)
    if profile.layout is None:raise ValueError('session_profile_mismatch')
    pid=find_process(wow);k=_apis();h=k.OpenProcess(0x410,False,pid)
    if not h:raise ValueError('readonly_process_access_denied')
    try:
        if expected_pid is not None and pid!=expected_pid:raise ValueError('process_identity_changed')
        if os.path.normcase(process_path(k,h)) != os.path.normcase(str(wow)):
            raise ValueError('process_identity_changed')
        ps=C.WinDLL('psapi',use_last_error=True)
        ps.EnumProcessModulesEx.argtypes=[PTR,PTR,U32,C.POINTER(U32),U32];ps.EnumProcessModulesEx.restype=C.c_int
        ps.GetModuleFileNameExW.argtypes=[PTR,PTR,C.c_wchar_p,U32];ps.GetModuleFileNameExW.restype=U32
        modules=(PTR*4096)();used=U32()
        if not ps.EnumProcessModulesEx(h,modules,C.sizeof(modules),C.byref(used),3) or used.value>C.sizeof(modules):
            raise ValueError('module_inventory_unavailable')
        bases=[]
        for base in modules[:used.value//C.sizeof(PTR)]:
            name=C.create_unicode_buffer(32768)
            if ps.GetModuleFileNameExW(h,base,name,len(name)) and os.path.normcase(name.value)==os.path.normcase(str(wow)):
                bases.append(base)
        if len(bases)!=1:raise ValueError('module_identity_unavailable')
        k.VirtualQueryEx.argtypes=[PTR,PTR,C.POINTER(_MemoryInfo),C.c_size_t];k.VirtualQueryEx.restype=C.c_size_t
        k.ReadProcessMemory.argtypes=[PTR,PTR,PTR,C.c_size_t,C.POINTER(C.c_size_t)];k.ReadProcessMemory.restype=C.c_int
        def read(address,count):
            if not 1 <= count <= 96:raise ValueError('session_read_limit')
            data=bytearray()
            while len(data)<count:
                a=address+len(data);region=_MemoryInfo()
                if k.VirtualQueryEx(h,a,C.byref(region),C.sizeof(region))!=C.sizeof(region):
                    raise ValueError('session_memory_unavailable')
                if (region.state!=0x1000 or region.protect&0x100 or
                    region.protect&255 not in (2,4,8,0x20,0x40,0x80) or
                    region.base is None or not region.base<=a<region.base+region.size):
                    raise ValueError('session_memory_unavailable')
                size=min(count-len(data),region.base+region.size-a)
                b=C.create_string_buffer(size);n=C.c_size_t()
                if not k.ReadProcessMemory(h,a,b,size,C.byref(n)) or n.value!=size:
                    raise ValueError('session_memory_unavailable')
                data.extend(b.raw)
            return bytes(data)
        result=read_session(read,bases[0],profile.layout)
        result.update({'pid':pid,'build':build,'image_sha256':digest})
        return result
    finally:k.CloseHandle(h)
