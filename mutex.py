import os
import shlex
try:
  from lib.common.abstracts import Package
except ImportError:
  print "Can't import libs.common.abstract, got Cuckoo installed? ¯\_(ツ)_/¯ "
import ctypes
import logging




class Mutex(Package):

  def __init__(self):
    logger = logging.getLogger("mystique")
    hdlr = logging.FileHandler('mystique.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)

  """Package that creates a mutex on the guest machine. Receives mutex name
  in arguments."""
  def start(self, path):
    args = self.options.get("arguments", "")
    # Getting the mutex name from the arguments sent to the package
    mutexes = self.options.get("mutexes", "")
    self.create_mutex(mutexes)
    self.logger.info("mutex created: ", mutexes)
    name, ext = os.path.splitext(path)

    if not ext:
      # running the executable
      new_path = name + ".exe"
      os.rename(path, new_path)
      path = new_path
    return self.execute(path, args=shlex.split(args))

  def create_mutex(self,mutex_name):
    """Creating mutex_name on the machine"""
    try:
      _CreateMutex = ctypes.windll.kernel32.CreateMutexA
      _CreateMutex.argtypes = [ctypes.wintypes.LPCVOID, ctypes.wintypes.BOOL,
                               ctypes.wintypes.LPCSTR]
      _CreateMutex.restype = ctypes.wintypes.HANDLE
      ret = _CreateMutex(None, False, mutex_name)
      self.logger.info("mutex name %s" % (mutex_name))
    except Exception as e:
      self.logger.error("Mutex creation failed!")
