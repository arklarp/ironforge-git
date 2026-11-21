import os
import shutil

BIN = "/bot/bin/forge" if os.path.exists("/bot/bin/forge") else os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "forge")

try:
    os.execv(BIN, [BIN])
except PermissionError:
    tmp = "/tmp/forge"
    shutil.copyfile(BIN, tmp)
    os.chmod(tmp, 0o755)
    os.execv(tmp, [tmp])
