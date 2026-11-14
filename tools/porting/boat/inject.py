"""inject.py pid dll_path : LoadLibraryW the DLL in the target process (CreateRemoteThread)."""
import ctypes, ctypes.wintypes as W, sys
k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = W.HANDLE; k.VirtualAllocEx.restype = ctypes.c_void_p
k.VirtualAllocEx.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_size_t, W.DWORD, W.DWORD]
k.WriteProcessMemory.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k.GetProcAddress.restype = ctypes.c_void_p; k.GetProcAddress.argtypes = [W.HMODULE, ctypes.c_char_p]
k.GetModuleHandleW.restype = W.HMODULE
k.CreateRemoteThread.restype = W.HANDLE
k.CreateRemoteThread.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, W.DWORD, ctypes.c_void_p]
pid = int(sys.argv[1]); path = sys.argv[2]
h = k.OpenProcess(0x1F0FFF, False, pid)
buf = (path + '\0').encode('utf-16-le')
mem = k.VirtualAllocEx(h, None, len(buf), 0x3000, 0x04)
n = ctypes.c_size_t(); k.WriteProcessMemory(h, mem, buf, len(buf), ctypes.byref(n))
lla = k.GetProcAddress(k.GetModuleHandleW('kernel32.dll'), b'LoadLibraryW')
t = k.CreateRemoteThread(h, None, 0, lla, mem, 0, None)
print('thread', t, 'err', ctypes.get_last_error())
k.WaitForSingleObject(t, 10000)
code = W.DWORD(); k.GetExitCodeThread(t, ctypes.byref(code)); print('LoadLibrary returned (low 32 bits)', hex(code.value))
