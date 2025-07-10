import sys
import ctypes
from RatFinder.classes.utils.GUI.GUI import GUI
from RatFinder.classes.utils.Shared import Shared
from RatFinder.classes.utils.Tools.Logger import Logger


def is_admin():
    """
    Check if the script is running with admin privileges on Windows.
    Returns:
        bool: True if running as admin, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def is_frozen():
    """
    Check if the script is running as a frozen executable (e.g., PyInstaller).
    Returns:
        bool: True if running as a frozen executable, False otherwise.
    """
    return getattr(sys, 'frozen', False)

def is_running_as_exe():
    """
    Check if the script is running as an executable (e.g., .exe) on Windows.
    Returns:
        bool: True if running as an executable, False otherwise.
    """
    return is_frozen() and sys.executable.endswith('.exe')

def require_admin():
    """
    Check if the script is running with admin privileges. If not, and it is running as an Executable (.exe) relaunch it with admin rights.
    """
    if not is_admin() and is_running_as_exe():
        # Relaunch the script with admin rights
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, ' '.join(sys.argv), None, 1
        )
        sys.exit()

def main():
    """
    Main function to initialize the application.
    It sets up the shared instance, logger, and GUI, and then calls the parse function to process RATs.
    """
    require_admin()
    shared = Shared()
    shared.logger_instance = Logger(shared)
    GUI(shared)


if __name__ == "__main__":
    main()