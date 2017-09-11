import os
import shlex
from lib.common.abstracts import Package
import ctypes
from ctypes import wintypes
import subprocess
import logging
import time
import sys


def create_mutex(mutex_name):
    """Creating mutex_name on the machine"""
    try:
        _CreateMutex = ctypes.windll.kernel32.CreateMutexA
        _CreateMutex.argtypes = [wintypes.LPCVOID, wintypes.BOOL, wintypes.LPCSTR]
        _CreateMutex.restype = wintypes.HANDLE
        ret = _CreateMutex(None, False, mutex_name)
        print mutex_name
    except Exception as e:
        print "Mutex creation failed."


class Mutex(Package):
    """Package that creates a mutex on the guest machine. Receives mutex name in arguments."""
    def start(self, path):
        args = self.options.get("arguments", "")
        # Getting the mutex name from the arguments sent to the package
        mutexes = self.options.get("mutexes", "")
        create_mutex(mutexes)
        print "mutex created: " + mutexes
        name, ext = os.path.splitext(path)
        if not ext:
            # running the executable
            new_path = name + ".exe"
            os.rename(path, new_path)
            path = new_path
        return self.execute(path, args=shlex.split(args))
