"""macOS Security.framework Keychain backend. Darwin only."""

from __future__ import annotations

import sys

from .identity import IdentityError


class SecurityKeychain:
    """Live macOS Keychain via Security.framework (no extra Python package)."""

    def put(self, service: str, account: str, secret: bytes) -> None:
        self._require()
        status = self._add(service, account, secret)
        if status == -25299:  # errSecDuplicateItem
            status = self._update(service, account, secret)
        if status != 0:
            raise IdentityError("identity_protect_failed")

    def get(self, service: str, account: str) -> bytes:
        self._require()
        data, status = self._copy(service, account)
        if status != 0 or data is None:
            raise IdentityError("identity_unprotect_failed")
        return data

    def _require(self) -> None:
        if sys.platform != "darwin":
            raise IdentityError("keychain_unavailable")

    def _libs(self):
        import ctypes
        import ctypes.util

        sec_name = ctypes.util.find_library("Security")
        cf_name = ctypes.util.find_library("CoreFoundation")
        if not sec_name or not cf_name:
            raise IdentityError("keychain_unavailable")
        return ctypes, ctypes.CDLL(sec_name), ctypes.CDLL(cf_name)

    def _add(self, service: str, account: str, secret: bytes) -> int:
        ctypes, sec, cf = self._libs()
        attrs = self._attrs(ctypes, cf, service, account, secret, for_query=False)
        try:
            sec.SecItemAdd.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            sec.SecItemAdd.restype = ctypes.c_int32
            return int(sec.SecItemAdd(attrs, None))
        finally:
            cf.CFRelease(attrs)

    def _update(self, service: str, account: str, secret: bytes) -> int:
        ctypes, sec, cf = self._libs()
        query = self._attrs(ctypes, cf, service, account, None, for_query=True)
        update = self._value_dict(ctypes, cf, secret)
        try:
            sec.SecItemUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            sec.SecItemUpdate.restype = ctypes.c_int32
            return int(sec.SecItemUpdate(query, update))
        finally:
            cf.CFRelease(query)
            cf.CFRelease(update)

    def _copy(self, service: str, account: str):
        ctypes, sec, cf = self._libs()
        query = self._attrs(ctypes, cf, service, account, None, for_query=True, return_data=True)
        result = ctypes.c_void_p()
        try:
            sec.SecItemCopyMatching.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
            sec.SecItemCopyMatching.restype = ctypes.c_int32
            status = int(sec.SecItemCopyMatching(query, ctypes.byref(result)))
            if status != 0 or not result.value:
                return None, status
            cf.CFDataGetLength.argtypes = [ctypes.c_void_p]
            cf.CFDataGetLength.restype = ctypes.c_long
            cf.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
            cf.CFDataGetBytePtr.restype = ctypes.c_void_p
            length = int(cf.CFDataGetLength(result))
            ptr = cf.CFDataGetBytePtr(result)
            return ctypes.string_at(ptr, length), 0
        finally:
            cf.CFRelease(query)
            if result.value:
                cf.CFRelease(result)

    def _cfstr(self, ctypes, cf, text: str):
        cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        cf.CFStringCreateWithCString.restype = ctypes.c_void_p
        return cf.CFStringCreateWithCString(None, text.encode("utf-8"), 0x08000100)

    def _cfdata(self, ctypes, cf, blob: bytes):
        cf.CFDataCreate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]
        cf.CFDataCreate.restype = ctypes.c_void_p
        buf = ctypes.create_string_buffer(blob, len(blob))
        return cf.CFDataCreate(None, buf, len(blob))

    def _bool_true(self, ctypes, cf):
        return ctypes.c_void_p.in_dll(cf, "kCFBooleanTrue")

    def _dict(self, ctypes, cf, mapping: dict):
        n = len(mapping)
        keys = (ctypes.c_void_p * n)()
        vals = (ctypes.c_void_p * n)()
        owned = []
        for i, (k, v) in enumerate(mapping.items()):
            ks = self._cfstr(ctypes, cf, k)
            keys[i] = ks
            owned.append(ks)
            if isinstance(v, bytes):
                ds = self._cfdata(ctypes, cf, v)
                vals[i] = ds
                owned.append(ds)
            elif isinstance(v, str):
                vs = self._cfstr(ctypes, cf, v)
                vals[i] = vs
                owned.append(vs)
            else:
                vals[i] = v
        cf.CFDictionaryCreate.restype = ctypes.c_void_p
        d = cf.CFDictionaryCreate(None, keys, vals, n, None, None)
        for item in owned:
            if item:
                cf.CFRelease(item)
        if not d:
            raise IdentityError("keychain_unavailable")
        return d

    def _attrs(
        self,
        ctypes,
        cf,
        service: str,
        account: str,
        secret: bytes | None,
        *,
        for_query: bool,
        return_data: bool = False,
    ):
        mapping: dict = {
            "class": "genp",
            "svce": service,
            "acct": account,
        }
        if secret is not None:
            mapping["v_Data"] = secret
        if return_data:
            mapping["r_Data"] = self._bool_true(ctypes, cf)
            mapping["m_Limit"] = "m_LimitOne"
        if not for_query:
            mapping["pdmn"] = "akpu"
        return self._dict(ctypes, cf, mapping)

    def _value_dict(self, ctypes, cf, secret: bytes):
        return self._dict(ctypes, cf, {"v_Data": secret})
