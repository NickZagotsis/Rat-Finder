import os
import sys
from pathlib import Path
class DirectoryListing:
    """
    DirectoryListing class to handle directory listing and file population for RATs.
    This class is responsible for scanning directories for specific RAT-related files and populating the shared instance with the found files, relevant for each RAT.
    """
    def __init__(self, shared):
        self.shared = shared

    @staticmethod
    def is_teamviewer(path):
        """
        Check if the given path is a TeamViewer log file or teamviewer connection file.
        """
        actual = path.split(os.sep)[-1]
        c1 = 'teamviewer' in actual.lower() and 'log' in actual.lower()  # Condition for logs
        c2 = 'connections' in actual.lower() and '.txt' in path and 'teamviewer' in path.lower()  # Condition for connections.txt file
        c3 = 'rolloutfile' in actual.lower()
        return any([c1, c2, c3])

    def populate_with_default(self):
        """
        Populate the shared instance with default RAT-related files (only known locations will be parsed).
        This method scans specific directories for AnyDesk and TeamViewer files and adds them to the shared instance.
        """


        self.shared.trace_files = []
        self.shared.teamviewer_logfiles = []

        #-----------List for PC data-----------------
        if 'AnyDesk' in self.shared.rats:
            ad_svc_trace_path = r"C:\\ProgramData\\AnyDesk"
            for subdir, _, files in os.walk(ad_svc_trace_path):
                for file in files:
                    if file.endswith("ad_svc.trace") or ("ad_" in file and "svc" in file and file.endswith(".trace")):
                        self.shared.trace_files.append(os.path.join(subdir, file))
                    if 'trace' in file and ("connection" in file or "file_transfer" in file):
                        self.shared.trace_files.append(os.path.join(subdir, file))


        if 'TeamViewer' in self.shared.rats:
            logs_incoming_connections_path = r"C:\Program Files\TeamViewer"
            for subdir, _, files in os.walk(logs_incoming_connections_path):
                for file in files:
                    path = os.path.join(subdir, file)
                    if DirectoryListing.is_teamviewer(path):
                        self.shared.teamviewer_logfiles.append(path)


        #-----------List for per user data-----------------
        for user in self.shared.system_users.keys():
            if 'AnyDesk' in self.shared.rats:
                ad_trace_path = f"C:\\Users\\{user}\\AppData\\Roaming\\AnyDesk"
                for subdir,_,files in os.walk(ad_trace_path):
                    for file in files:
                        if file.endswith('.trace') and 'ad' in file.lower():
                            self.shared.trace_files.append(os.path.join(subdir, file))

            if 'TeamViewer' in self.shared.rats:
                outgoing_conn_folder = f"C:\\Users\\{user}\\AppData\\Roaming\\TeamViewer"
                for subdir,_,files in os.walk(outgoing_conn_folder):
                    for file in files:
                        if file.endswith('txt') and "connection" in file and not "trace" in file:
                            self.shared.teamviewer_logfiles.append(os.path.join(subdir, file))

    def populate_with_full(self):
        """
        Populate the shared instance with all RAT-related files (all files in the input directory will be searched and parsed).
        """
        for file_path in DirectoryListing.list_all_files(self.shared.input):
            if 'AnyDesk' in self.shared.rats:
                if 'trace' in file_path.split(os.sep)[-1].lower():
                    self.shared.trace_files.append(file_path)

            if 'TeamViewer' in self.shared.rats:
                    if DirectoryListing.is_teamviewer(file_path):
                        self.shared.teamviewer_logfiles.append(file_path)

    @staticmethod
    def get_local_users():
        """
        Get a list of local users on the system.
        Returns:
            list: List of local user directories.
        """
        users_dir = "C:\\Users"
        try:
            return [
                name for name in os.listdir(users_dir)
                if os.path.isdir(os.path.join(users_dir, name))
                   and name.lower() not in ("public", "default", "default user", "all users")
            ]
        except Exception as e:
            print(f"Error reading user directories: {e}")
            return []

    @staticmethod
    def list_all_files(root_dir):
        """
        Recursively list all files in a directory and its subdirectories.
        Args:
            root_dir (str): The root directory to start the search.
        """
        try:
            with os.scandir(root_dir) as entries:
                for entry in entries:
                    try:
                        full_path = os.path.join(root_dir, entry.name)
                        if entry.is_dir():
                            yield from DirectoryListing.list_all_files(full_path)
                        elif entry.is_file():
                            yield full_path
                    except PermissionError:
                        # Skip files/directories we don't have permission to access
                        continue
                    except WindowsError:
                        # Skip files/directories with Windows-specific errors
                        continue
                    except KeyboardInterrupt:
                        sys.exit()
        except KeyboardInterrupt:
            sys.exit()
        except WindowsError:
            # Skip directories with Windows-specific errors
            pass
        except Exception as e:
            print(f"Error scanning {root_dir}: {str(e)}")

    def populate_users(self):
        """
        Populate the shared instance with local users.
        This method retrieves the list of local users and initializes their data structures in the shared instance.
        """
        users = DirectoryListing.get_local_users()
        for user in users:
            if user not in self.shared.system_users:
                self.shared.system_users[user] = {}

        for key in self.shared.system_users:
            for rat in self.shared.rats:
                self.shared.system_users[key][rat] = {}

    def directory_list(self):
        """
        Main method to populate the shared instance with RAT-related files.
        """
        self.populate_users()
        if self.shared.full:
            self.populate_with_full()
        else:
            self.populate_with_default()