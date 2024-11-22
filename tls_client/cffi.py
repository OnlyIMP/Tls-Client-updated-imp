from sys import platform
from platform import machine
import ctypes
import os

# Determinação da extensão do arquivo compartilhado com base na plataforma
if platform == 'darwin':
    file_ext = '-arm64.dylib' if machine() == "arm64" else '-x86.dylib'
elif platform in ('win32', 'cygwin'):
    file_ext = '-64.dll' if ctypes.sizeof(ctypes.c_voidp) == 8 else '-32.dll'
else:
    if machine() == "aarch64":
        file_ext = '-arm64.so'
    elif "x86" in machine():
        file_ext = '-x86.so'
    else:
        file_ext = '-amd64.so'

# Carregamento da biblioteca compartilhada
root_dir = os.path.abspath(os.path.dirname(__file__))
library_path = os.path.join(root_dir, 'dependencies', f'tls-client{file_ext}')
library = ctypes.CDLL(library_path)

# Definição das funções expostas pela biblioteca Go

# Função request
request = library.request
request.argtypes = [ctypes.c_char_p]
request.restype = ctypes.c_char_p

# Função freeMemory
freeMemory = library.freeMemory
freeMemory.argtypes = [ctypes.c_char_p]
freeMemory.restype = ctypes.c_char_p

# Função destroySession
destroySession = library.destroySession
destroySession.argtypes = [ctypes.c_char_p]
destroySession.restype = ctypes.c_char_p

# Função destroyAll
destroyAll = library.destroyAll
destroyAll.argtypes = []
destroyAll.restype = ctypes.c_char_p

# Função getCookiesFromSession
getCookiesFromSession = library.getCookiesFromSession
getCookiesFromSession.argtypes = [ctypes.c_char_p]
getCookiesFromSession.restype = ctypes.c_char_p

# Função addCookiesToSession
addCookiesToSession = library.addCookiesToSession
addCookiesToSession.argtypes = [ctypes.c_char_p]
addCookiesToSession.restype = ctypes.c_char_p
