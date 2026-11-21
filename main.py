import os
import shutil


def resolve_server_binary() -> str:
    deployed_bin = "/bot/bin/forge"
    if os.path.exists(deployed_bin):
        return deployed_bin
    repo_root = os.path.dirname(os.path.abspath(__file__))
    local_bin = os.path.join(repo_root, "bin", "forge")
    return local_bin


def launch_forge_daemon() -> None:
    executable_path = resolve_server_binary()
    try:
        os.execv(executable_path, [executable_path])
    except PermissionError:
        staged_bin = "/tmp/ironforge-server-bin"
        shutil.copyfile(executable_path, staged_bin)
        os.chmod(staged_bin, 0o755)
        os.execv(staged_bin, [staged_bin])


if __name__ == "__main__":
    launch_forge_daemon()
