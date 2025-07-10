import sys
import ctypes
import platform
from datetime import datetime
from os.path import join as pjoin
from RatFinder.classes.utils.GUI.GUI import GUI
from RatFinder.classes.utils.Shared import Shared
from RatFinder.classes.rats.anydesk import Anydesk
from RatFinder.classes.utils.Tools.Logger import Logger
from RatFinder.classes.rats.teamviewer import Teamviewer
from RatFinder.classes.utils.Tools.Directory_Listing import DirectoryListing

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

def parse(shared, logger):
    """
    Parse the RATs and generate logs.
    Args:
        shared (Shared): Shared instance containing configuration and state.
        logger (Logger): Logger instance for logging.
    """
    if not shared.no_logging:
        shared.logger.bind(category="general").info('Producing directory listing...')
    DirectoryListing(shared).directory_list()

    if 'AnyDesk' in shared.rats:
        if not shared.no_logging:
            logger.generate_anydesk_logger()
            shared.logger.bind(category="anydesk").info("Log initiated. Anydesk log created")
        anydesk = Anydesk(shared)
        anydesk.parse()
        del shared.trace_files
        del anydesk

    if 'TeamViewer' in shared.rats:
        if not shared.no_logging:
            logger.generate_teamviewer_logger()
            shared.logger.bind(category="teamviewer").info("Log initiated. Teamviewer log created")
        teamviewer = Teamviewer(shared)
        teamviewer.parse()
        del teamviewer

def main():
    """
    Main function to initialize the application.
    It sets up the shared instance, logger, and GUI, and then calls the parse function to process RATs.
    """
    ended_gracefully = True

    require_admin()
    shared = Shared()
    logger = Logger(shared)
    gui = GUI(shared)

    shared.output = pjoin(shared.output, "RatFinder_Results", platform.uname()[1],datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

    if not shared.no_logging:
        logger.generate_general_logger()
        shared.logger.bind(category="general").info("Log initiated. General log created")
    try:
        parse(shared, logger)
    except Exception as e:
        gui.window_pop("Error",f"Uncaught exception: {str(e)}")
        ended_gracefully = False

    if ended_gracefully:
        gui.window_pop("Success",f"Program finished with no error.")



if __name__ == "__main__":
    main()