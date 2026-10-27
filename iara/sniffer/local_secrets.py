"""Current-user Windows DPAPI storage for session material."""
import ctypes as C
import os


class _Blob(C.Structure):
    _fields_=[('size',C.c_uint32),('data',C.c_void_p)]


def _transform(value,unprotect):
    if os.name!='nt':raise ValueError('windows_required')
    if type(value) is not bytes or not 1<=len(value)<=65536:
        raise ValueError('invalid_secret_size')
    crypt=C.WinDLL('crypt32',use_last_error=True);kernel=C.WinDLL('kernel32',use_last_error=True)
    kernel.LocalFree.argtypes=[C.c_void_p];kernel.LocalFree.restype=C.c_void_p
    src=C.create_string_buffer(value);input_blob=_Blob(len(value),C.cast(src,C.c_void_p));out=_Blob()
    name='CryptUnprotectData' if unprotect else 'CryptProtectData';fn=getattr(crypt,name)
    fn.argtypes=[C.POINTER(_Blob),C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,C.c_uint32,C.POINTER(_Blob)]
    fn.restype=C.c_int
    try:
        # CRYPTPROTECT_UI_FORBIDDEN; protection stays scoped to the current user.
        if not fn(C.byref(input_blob),None,None,None,None,1,C.byref(out)):
            raise ValueError('local_secret_protection_failed')
        if not out.data or not 1<=out.size<=65536:
            raise ValueError('invalid_protected_result')
        return C.string_at(out.data,out.size)
    finally:
        C.memset(src,0,C.sizeof(src))
        if out.data:
            if unprotect:C.memset(out.data,0,out.size)
            kernel.LocalFree(out.data)


def protect(value):return _transform(value,False)
def unprotect(value):return _transform(value,True)
