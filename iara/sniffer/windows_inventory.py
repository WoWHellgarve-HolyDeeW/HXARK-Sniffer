"""Windows process, IPv4 connection and adapter inventory."""
import ctypes as C
import hashlib
import ipaddress
import os
from pathlib import Path

U32=C.c_uint32
PTR=C.c_void_p


def _apis():
    if os.name!='nt':raise ValueError('windows_required')
    k=C.WinDLL('kernel32',use_last_error=True)
    k.OpenProcess.argtypes=[U32,C.c_int,U32];k.OpenProcess.restype=PTR
    k.CloseHandle.argtypes=[PTR];k.CloseHandle.restype=C.c_int
    k.QueryFullProcessImageNameW.argtypes=[PTR,U32,C.c_wchar_p,C.POINTER(U32)]
    k.QueryFullProcessImageNameW.restype=C.c_int
    return k


def process_path(k,handle):
    count=U32(32768);value=C.create_unicode_buffer(count.value)
    if not k.QueryFullProcessImageNameW(handle,0,value,C.byref(count)):
        raise ValueError('process_identity_unavailable')
    return value.value


def find_process(path):
    """Returns one exact path match; inaccessible unrelated processes are skipped."""
    target=os.path.normcase(str(Path(path).resolve(strict=True)))
    k=_apis();p=C.WinDLL('psapi',use_last_error=True)
    p.EnumProcesses.argtypes=[PTR,U32,C.POINTER(U32)];p.EnumProcesses.restype=C.c_int
    ids=(U32*32768)();used=U32()
    if not p.EnumProcesses(ids,C.sizeof(ids),C.byref(used)) or used.value>=C.sizeof(ids):
        raise ValueError('process_inventory_unavailable')
    matches=[]
    for pid in ids[:used.value//4]:
        handle=k.OpenProcess(0x1000,False,pid)
        if not handle:continue
        try:
            try:actual=process_path(k,handle)
            except ValueError:continue
            if os.path.normcase(actual)==target:matches.append(pid)
        finally:k.CloseHandle(handle)
    if len(matches)!=1:raise ValueError('wow_process_not_unique_or_not_running')
    return matches[0]


def fixed_version(path):
    from .windows_tables import build_from_fixed_version
    _apis();v=C.WinDLL('version',use_last_error=True)
    v.GetFileVersionInfoSizeW.argtypes=[C.c_wchar_p,C.POINTER(U32)];v.GetFileVersionInfoSizeW.restype=U32
    v.GetFileVersionInfoW.argtypes=[C.c_wchar_p,U32,U32,PTR];v.GetFileVersionInfoW.restype=C.c_int
    v.VerQueryValueW.argtypes=[PTR,C.c_wchar_p,C.POINTER(PTR),C.POINTER(U32)];v.VerQueryValueW.restype=C.c_int
    dummy=U32();size=v.GetFileVersionInfoSizeW(str(path),C.byref(dummy))
    if not 52<=size<=1048576:raise ValueError('file_version_unavailable')
    buffer=C.create_string_buffer(size)
    if not v.GetFileVersionInfoW(str(path),0,size,buffer):raise ValueError('file_version_unavailable')
    data=PTR();length=U32()
    if not v.VerQueryValueW(buffer,'\\',C.byref(data),C.byref(length)) or length.value<52:
        raise ValueError('file_version_unavailable')
    start=C.addressof(buffer)
    if not start<=data.value<=start+size-52:raise ValueError('file_version_unavailable')
    words=(U32*13).from_address(data.value)
    if words[0]!=0xfeef04bd:raise ValueError('file_version_unavailable')
    ms,ls=words[2],words[3]
    return build_from_fixed_version(ms,ls),[ms>>16,ms&65535,ls>>16,ls&65535]


def tcp_rows(pid, *, connecting=False):
    from .windows_tables import parse_tcp_table
    _apis();ip=C.WinDLL('iphlpapi',use_last_error=True)
    fn=ip.GetExtendedTcpTable
    fn.argtypes=[PTR,C.POINTER(U32),C.c_int,U32,U32,U32];fn.restype=U32
    size=U32(0);code=fn(None,C.byref(size),False,2,5,0)
    for _ in range(4):
        if code not in (0,122) or not 4<=size.value<=16*1024*1024:
            raise ValueError('tcp_inventory_unavailable')
        buffer=C.create_string_buffer(size.value)
        code=fn(buffer,C.byref(size),False,2,5,0)
        if code==0:return parse_tcp_table(buffer.raw[:size.value],pid,connecting=connecting)
    raise ValueError('tcp_inventory_unstable')


class _IPAddress(C.Structure):
    _fields_=[('next',PTR),('address',C.c_char*16),('mask',C.c_char*16),('context',U32)]


class _AdapterPrefix(C.Structure):
    _fields_=[('next',PTR),('combo',U32),('name',C.c_char*260),('description',C.c_char*132),
              ('address_length',U32),('address',C.c_ubyte*8),('index',U32),('type',U32),
              ('dhcp',U32),('current_ip',PTR),('ip_list',_IPAddress)]


def adapter_addresses():
    """IPv4 adapter GUIDs with bounded native pointer traversal."""
    import ipaddress
    import uuid
    _apis();ip=C.WinDLL('iphlpapi',use_last_error=True)
    fn=ip.GetAdaptersInfo;fn.argtypes=[PTR,C.POINTER(U32)];fn.restype=U32
    size=U32();code=fn(None,C.byref(size))
    for _ in range(4):
        if code not in (0,111) or not C.sizeof(_AdapterPrefix)<=size.value<=16*1024*1024:
            raise ValueError('adapter_inventory_unavailable')
        buffer=C.create_string_buffer(size.value)
        code=fn(buffer,C.byref(size))
        if code==0:break
    else:raise ValueError('adapter_inventory_unstable')
    start=C.addressof(buffer);end=start+C.sizeof(buffer);cursor=start;seen=set();result={}
    while cursor:
        if cursor in seen or len(seen)>=1024 or not start<=cursor<=end-C.sizeof(_AdapterPrefix):
            raise ValueError('invalid_adapter_inventory')
        seen.add(cursor);row=_AdapterPrefix.from_address(cursor)
        try:guid=str(uuid.UUID(row.name.decode('ascii').strip('{}')))
        except (ValueError,UnicodeError):raise ValueError('invalid_adapter_identity') from None
        ipcursor=cursor+_AdapterPrefix.ip_list.offset;ipseens=set()
        while ipcursor:
            if ipcursor in ipseens or len(ipseens)>=1024 or not start<=ipcursor<=end-C.sizeof(_IPAddress):
                raise ValueError('invalid_adapter_inventory')
            ipseens.add(ipcursor);address=_IPAddress.from_address(ipcursor)
            value=str(ipaddress.IPv4Address(address.address.decode('ascii')))
            if value!='0.0.0.0':
                interface='\\Device\\NPF_{'+guid+'}'
                if value in result and result[value]!=interface:raise ValueError('ambiguous_adapter')
                result[value]=interface
            ipcursor=address.next
        cursor=row.next
    return result


def inventory(wow):
    path=Path(wow).resolve(strict=True)
    pid=find_process(path);build,parts=fixed_version(path)
    with path.open('rb') as source:digest=hashlib.file_digest(source,'sha256').hexdigest()
    all_rows=tcp_rows(pid);adapters=adapter_addresses();rows=[];loopback_count=0
    for row in all_rows:
        if (ipaddress.IPv4Address(row['client'][0]).is_loopback or
                ipaddress.IPv4Address(row['server'][0]).is_loopback):
            loopback_count+=1
            continue
        interface=adapters.get(row['client'][0])
        if interface is None:raise ValueError('game_adapter_unavailable')
        row['interface']=interface
        rows.append(row)
    # A changed process identity during inventory cannot widen capture scope.
    if find_process(path)!=pid:raise ValueError('game_process_changed')
    return {'pid':pid,'path':str(path),'build':build,'version_parts':parts,
            'sha256':digest,'connections':rows,'inventory':'win32_read_only',
            'scope':'established_non_loopback_ipv4','excluded_loopback_connections':loopback_count}
