import re
from os.path import isfile
from datetime import datetime


class Anydesk:
    """
    This class is responsible for parsing AnyDesk.

    This class is responsible for the parsing of anydesk, which includes every type of log parsing, description adding
    to each message, and session attribution.

    Attributes
    ----------
        ad_svc_trace_results : dict[int,list[dict[str, str]]]
            A dictionary containing parsed results from `ad_svc.trace` files.

            Each key in the dictionary represents a unique session identifier (e.g., 1, 2, 3, ...).
            The corresponding value is a list of dictionaries, where each dictionary represents a single log entry (i.e., a row)
            with the following keys:

            - LogLevel: The severity level of the log message.
            - Timestamp: The timestamp of when the log entry was recorded.
            - Service: The name of the service associated with the log.
            - LogService: The specific log source or subcomponent.
            - Message: The raw log message content.
            - Explanation: A parsed or interpreted version of the message, if available.
            - File: The filename or path of the log file from which the entry was parsed.

        ad_trace_results : dict[int,list[dict[str, str]]]
            A dictionary containing parsed results from `ad.trace` files.

            Each key in the dictionary represents a unique session identifier (e.g., 1, 2, 3, ...).
            The corresponding value is a list of dictionaries, where each dictionary represents a single log entry (i.e., a row)
            with the following keys:

            - LogLevel (str): The severity level of the log message.
            - Timestamp (str): The timestamp of when the log entry was recorded.
            - Service (str): The name of the service associated with the log.
            - LogService (str): The specific log source or subcomponent.
            - Message (str): The raw log message content.
            - Explanation (str): A parsed or interpreted version of the message, if available.
            - File (str): The filename or path of the log file from which the entry was parsed.


        connection_trace_results : List[str]
            Each entry in the list represents a parsed line from the `connection_trace.txt` file, fields are separated with `#`.

        shared : Shared
            Stored reference to the shared object passed in the constructor.

        ips : dict[str, list[str]]
            Dictionary to store detected IP addresses with the relative file(s) found.

        ips_timestamps : dict[str, list[str]]
            Dictionary to store detected IP addresses with the relative timestamps it was found.

        clients_timestamps : dict[str, list[str]]
            Client identifiers with corresponding timestamps.

        IP_REGEX : str
            Regular expression pattern to match IPv4 addresses.

        CLIENT_ID_REGEX : str
            Regular expression pattern to match 9–10 digit client IDs.

        logger : Logger
            `Logger` instance retrieved from the shared object.

        anydesk_keys : list[str]
            `List` of AnyDesk-related configuration keys used during parsing.

        attribution_ad_svc : dict[int, dict[str, list]]
            Tracks attribution results from service-level traces. The initial dictionary's keys
            refer to each session (1,2,3...) each of which have a dictionary of alias(es), ip(s), ID(s) found
            in the session. So it matches Session X with the respective information.

        attribution_ad_trace : dict[int, dict[str, list]]
            Tracks attribution results from general trace logs. The initial dictionary's keys
            refer to each session (1,2,3...) each of which have a dictionary of alias(es), ip(s), ID(s) found
            in the session. So it matches Session X with the respective information.

        anydesk_log_dict : dict[str,str]
            Dictionary of AnyDesk log line patterns and their descriptions,
            used for detecting and interpreting log events.

        patterns : list[str]
            List of regex/string patterns derived from the keys of `anydesk_log_dict`.

        ids_w_aliases : dict
            Mapping of detected client IDs to their corresponding aliases.

        files_uploaded : dict
            Dictionary to store uploaded files with the relative session(s) found.
            It contains the following structure:

            {"file_path": {session_id: {"sum_files": int,"files": {"RootFolder": int,}}}}

            files_downloaded : dict
            Dictionary to store downloaded files with the relative session(s) found.
            It contains the following structure:

            {"file_path": {session_id: {"sum_files": int}}}
    """

    def __init__(self, shared):
        """
        Initialize the log parser with shared resources and prepare internal structures.

        Parameters
        ---------
        shared : Shared
            This is the commonly passed shared instance that contains all the shared information between scripts.
        """
        self.files_uploaded = {}
        self.files_downloaded = {}
        self.ad_svc_trace_results = None
        self.ad_trace_results = None
        self.file_trace_results = None #THIS IS THE NEWEST FILE THAT WAS SHADOW DROPPED
        self.connection_trace_results = None
        self.shared = shared
        self.ips = {}  # IP addresses
        self.ips_timestamps = {}  # IP addresses with timestamps
        self.clients_timestamps = {}  # clients with timestamps
        self.IP_REGEX = r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
        self.CLIENT_ID_REGEX = r'\b\d{9,10}\b'
        self.logger = self.shared.logger
        self.anydesk_keys = ['ad.anynet.id',
                             "ad.anynet.alias",
                             'ad.roster.favorites',
                             'ad.roster.items',
                             "ad.anynet.cur_version"
                             ]
        self.file_trace_keys = ["Method","Timestamp","Start/Finish","Download/Upload","FileTransferred","SizeTransferred","LogFile"]

        self.attribution_ad_svc = {}
        self.attribution_ad_trace = {}
        self.anydesk_log_dict = {
            # Connection Events
            r"[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}": "An IPv4 address was detected, indicating a connection attempt, authentication, or remote session.",
            "Accepting from|Accept request from": "An incoming remote connection was detected",
            "Incoming session request": "A remote session request was received from a remote user, listing user alias and connection ID.",
            "Logged in from": "A remote user logged in, and their IP address and relay server were recorded.",
            "Making a new connection to client": "A new remote connection attempt was initiated to a client device.",
            "Session started": "A new remote session was successfully established.",
            "connection quit": "A remote connection was closed, either by user action or network interruption.",

            # Authentication Events
            "Authenticated with correct passphrase": "Authentication was successful using the correct passphrase.",
            "Passphrase not accepted": "Authentication failed due to an incorrect passphrase entry.",
            r"(password|2FA)": "An event related to password authentication or two-factor authentication occurred.",

            # Session Termination Events
            "Received quit": "A termination signal was received, indicating session closure or application shutdown.",
            r"(Stopping session|session - Destroyed|Invalid session id)": "The session was stopped, destroyed, or reported an invalid session ID.",
            "Terminated": "A session or application process was forcefully terminated.",

            # File Transfer Events
            ## Machine -> Actor (exfil)
            "Preparing files in": "Files were prepared for transfer to a remote device.",
            r"Preparation of * completed": "File transfer was completed successfully to the remote device.",
            r"clipbrd.capture*found* | clipbrd.capture*offers*":"File transfer found via clipboard",
            
            ## Actor -> Machine
            "ole*Finished file paste operation*": "File paste from remote machine detected, using the clipboard.",
            "app.local_file_transfer*Download started*" : "A file download from the remote machine started.",
            "app.local_file_transfer*Download finished*": "A file download from the remote machine finished.",




            # Administrative Actions (UAC, Commands)
            "Opening UAC dialog": "The User Account Control (UAC) dialog was triggered to request elevated permissions.",
            "os_win.start_uac - line": "A Windows UAC prompt was initiated by AnyDesk for administrative access.",

            # GUI/Configuration Events
            "winapp.gui.permissions_panel": "The permissions configuration panel within the GUI was accessed.",
            "Selecting Profile": "A user selected a profile within the AnyDesk application settings.",
            "Profile was used": "A previously configured profile was used during the session.",

            # System/Client Information
            "Client-ID": "A Client-ID was referenced, identifying a specific device or session.",
            "Remote OS": "The operating system of the connecting remote machine was identified.",
            "OS is": "The operating system of the local device was identified and logged.",
            "Client": "An AnyDesk client instance or session was referenced.",
            "Version": "The version of the AnyDesk software in use was logged.",
            "Startup": "The AnyDesk application was launched manually or during system boot.",

            # Other Events
            "The user has requested": "A user-initiated action, such as a session start or file transfer, was recorded.",
        }
        self.patterns = list(self.anydesk_log_dict.keys())
        self.ids_w_aliases = {}

    @staticmethod
    def split_alias_id(message):
        """
            Splits the message to extract the AnyDesk ID and alias.

            Parameters
            ----------
            message : str
                The message to split.

            Returns
            -------
            tuple of str, str
                A tuple containing:

                - anydesk_id: The AnyDesk ID extracted from the message.
                - alias: The alias extracted from the message.
        """
        temp = message.split(":")[-1].split('(')
        alias = temp[0].rstrip().lstrip()
        anydesk_id = temp[1].rstrip().lstrip().rstrip(')')
        return anydesk_id, alias

    @staticmethod
    def clean_file_dict(data:dict):
        cleaned = {}
        for path, entries in data.items():
            filtered_entries = {
                key: val for key, val in entries.items()
                if val.get("sum_files", 0) != 0
            }
            if filtered_entries:
                cleaned[path] = filtered_entries
        return cleaned

    def get_sessions_attribution(self, dic):
        """
        This function attributes all the activity made per session ID.

        Parameters
        ----------
        dic: dict[int,list[dict[str, str]]]
            This is basically ad_trace and ad_svc_trace results, which are dictionaries containing the session ID as key
        Returns
        -------
            dict[int, dict[str, list]]
                A dictionary where each session ID (1,2,3...) is a key, and the value is another dictionary containing the following info:

                - Alias: Alias(es) found in the session
                - Ip: IP(s) found in the session
                - AnyDesk_ID: AnyDesk ID(s) found in the session
        """
        session_attr_dict = {}
        last_file = None
        if not dic:
            self.files_uploaded = None
            self.files_downloaded = None
            return {}
        for key in dic:
            session_attr_dict[key] = {
                "Alias": [],
                "IP": [],
                "AnyDesk_id": [],
                "EarliestTimestamp": None,
                "LatestTimestamp": None
            }
            timestamps = []
            for row in dic[key]:
                timestamps.append(datetime.strptime(row["Timestamp"], "%Y-%m-%d %H:%M:%S.%f"))
                if 'relay' in row["LogService"] or 'multicast' in row["Message"] or 'Using' in row[
                    'Message'] or 'External address' in row["Message"]:
                    continue
                if search := re.search(self.IP_REGEX, row["Message"]):
                    ip = search.group()
                    session_attr_dict[key]["IP"].append(ip)
                    session_attr_dict[key]["IP"] = list(set(session_attr_dict[key]["IP"]))

                if "Incoming session request" in row["Message"]:
                    self.match_id_to_alias(row["Message"])
                    anydesk_id, alias = Anydesk.split_alias_id(row["Message"])

                    session_attr_dict[key]["AnyDesk_id"].append(anydesk_id)
                    session_attr_dict[key]["AnyDesk_id"] = list(set(session_attr_dict[key]["AnyDesk_id"]))
                    session_attr_dict[key]["Alias"].append(alias)
                    session_attr_dict[key]["Alias"] = list(set(session_attr_dict[key]["Alias"]))

                if client := re.search(self.CLIENT_ID_REGEX, row["Message"]):
                    client_id = client.group()
                    if self.ids_w_aliases.get(client_id, None):
                        session_attr_dict[key]["Alias"].extend(self.ids_w_aliases.get(client_id))
                        session_attr_dict[key]["Alias"] = list(set(session_attr_dict[key]["Alias"]))

                    session_attr_dict[key]["AnyDesk_id"].append(client_id)
                    session_attr_dict[key]["AnyDesk_id"] = list(set(session_attr_dict[key]["AnyDesk_id"]))

                if not self.files_uploaded.get(row['File'], None):
                    self.files_uploaded[row['File']] = {}
                if not key in self.files_uploaded[row['File']]:
                    self.files_uploaded[row['File']][key] = {"sum_files": 0, "files": {}}

                if "clipbrd.capture" in row["LogService"] and "found" in row["Message"].lower():
                    if search := re.search(r"\d+", row["Message"]):
                        num_files = search.group()
                        try:
                            self.files_uploaded[row["File"]][key]["sum_files"] += int(num_files)
                            if not self.files_uploaded[row["File"]][key]["files"].get("clipboard", None):
                                self.files_uploaded[row['File']][key]["files"]["clipboard"] = 0
                            self.files_uploaded[row['File']][key]["files"]["clipboard"] += int(num_files)
                        except ValueError:
                            pass

                if "app.prepare_task" in row["LogService"] and "Preparing files in" in row["Message"]:
                    last_file = row["Message"].partition("'")[-1].replace("'.",'')


                if "app.local_file_transfer" in row["LogService"] and "Preparation of" in row["Message"]:
                    if search := re.search(r"\d+", row["Message"]):
                        num_files = search.group()
                        if not last_file:
                            last_file = "unknown"

                        if last_file not in self.files_uploaded[row['File']][key]["files"]:
                            self.files_uploaded[row['File']][key]["files"][last_file] = 0

                        try:
                            self.files_uploaded[row['File']][key]["sum_files"] += int(num_files)
                            try:
                                self.files_uploaded['File'][key]["files"][last_file] += int(num_files)
                            except KeyError:
                                pass
                        except ValueError:
                            pass
                        last_file = None

                if not self.files_downloaded.get(row['File'], None):
                    self.files_downloaded[row['File']] = {}
                if not self.files_downloaded[row['File']].get(key, None):
                    self.files_downloaded[row['File']][key] = {"sum_files":0}

                if "ole" in row["LogService"] and "Finished file paste operation" in row["Message"]\
                        or "app.local_file_transfer" in row["LogService"] and "Download started" in row["Message"]:
                    self.files_downloaded[row['File']][key]["sum_files"] += 1

            session_attr_dict[key]["EarliestTimestamp"] = min(timestamps)
            session_attr_dict[key]["LatestTimestamp"] = max(timestamps)

            session_attr_dict[key]["EarliestTimestamp"] = session_attr_dict[key]["EarliestTimestamp"].replace(tzinfo=self.shared.utc)
            session_attr_dict[key]["LatestTimestamp"] = session_attr_dict[key]["LatestTimestamp"].replace(tzinfo=self.shared.utc)

            if not session_attr_dict[key]["AnyDesk_id"] and not session_attr_dict[key]["IP"] and not \
                    session_attr_dict[key]["Alias"]:
                del session_attr_dict[key]

        self.files_uploaded = Anydesk.clean_file_dict(self.files_uploaded)
        self.files_downloaded = Anydesk.clean_file_dict(self.files_downloaded)

        return session_attr_dict

    def update_users(self):
        """
        It creates the AnyDesk key in the system_users dictionary for each user.

        This function is used when the program runs in Triage mode, where it needs to find specific user activity, so it appends
        AnyDesk key in the dictionary for each user.
        It directly modifies the system_users dictionary by adding the AnyDesk key to each user.
        """
        for user in self.shared.system_users.keys():
            self.shared.system_users[user]["AnyDesk"] = dict.fromkeys(self.anydesk_keys)

    def pattern_match(self, message):
        """
        This function is used to match the message with the patterns in the dictionary.

        This function is used to match the message with the patterns stored in anydesk_log_dict and return the
        description of the pattern if found.
        Parameters
        ----------
        message: str
            The message to check patterns against

        Returns
        -------
            str
                The description of the pattern if found, otherwise an empty string.

        """
        for pattern in self.anydesk_log_dict.keys():
            if re.search(pattern=pattern, string=message):
                return self.anydesk_log_dict.get(pattern, "")
        return ""

    def all_conf(self):
        """
        This function is responsible to parse each known configuration file.

        This function is responsible to parse each known configuration file and extract relevant information and append it
        to the equivalent user in the users' dictionary.
        It directly modifies the system_users dictionary by adding the relevant information to the AnyDesk key.
        """
        for user in self.shared.system_users.keys():
            flist = []
            file_names = [f"C:\\Users\\{user}\\AppData\\Roaming\\AnyDesk\\service.conf",
                          f"C:\\Users\\{user}\\AppData\\Roaming\\AnyDesk\\user.conf",
                          f"C:\\Users\\{user}\\AppData\\Roaming\\AnyDesk\\system.conf"]

            for file_name in file_names:
                if isfile(file_name):
                    with open(file_name, 'r') as f:
                        flist.append(f.read().split("\n"))

            for f in flist:
                for line in f:
                    if len(line.split("=")) > 1:
                        key, value = line.split('=')[0], line.split('=')[1]
                    else:
                        key, value = line.split('=')[0], None
                    if key in self.anydesk_keys:
                        self.shared.system_users[user]["AnyDesk"][key] = value

    def log(self, message, mtype="info"):
        """
        This function is used to log messages with different types.
        Parameters
        ----------
        message: str
            Message you want to log

        mtype: str
            Type of message severity you want to log. It can be one of the following:

            - "error"
            - "info"
            - "success"
            - "warning"

            Default is "info".
        """
        match mtype:
            case "error":
                self.shared.logger.bind(category="anydesk").error(message)
            case "info":
                self.shared.logger.bind(category="anydesk").info(message)
            case "success":
                self.shared.logger.bind(category="anydesk").success(message)
            case "warning":
                self.shared.logger.bind(category="anydesk").warning(message)
            case _:
                self.shared.logger.bind(category="anydesk").info(message)

    def read_file(self, file_path):
        """
        This function is used to read the file and return the lines read.
        Parameters
        ----------
        file_path: str
            File path

        Returns
        -------
            list[str]
                the list of lines read from the file
        """
        try:
            with open(file_path, 'r', encoding='UTF-8', errors="replace") as log:
                return log.readlines()
        except Exception as E:
            self.log(f"Exception occurred: {E}. {file_path} had an error!", "error")
            return []

    @staticmethod
    def convert_to_datetime(timestamp):
        """
        This function is used to convert the timestamp to a datetime object with a specific format (YY-MM-DD HH:MM:SS.ss).
        Parameters
        ----------
        timestamp: str
            Timestamp string.

        Returns
        -------
            datetime
                The formatted datetime object.
        """
        return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f").strftime("%Y-%m-%d %H:%M:%S.%f")

    def match_id_to_alias(self, message):
        """
        This function is used to match the AnyDesk ID to an alias found in specific anydesk messages.

        It does so by splitting the file and extracting the ID and alias from the message.
        Parameters
        It modifies the ids_w_aliases dictionary by adding the ID and alias to the dictionary.
        ----------
        message: str
            Message to extract the ID and alias from.
        """
        anydesk_id, alias = Anydesk.split_alias_id(message)
        if not self.ids_w_aliases.get(anydesk_id, None):
            self.ids_w_aliases[anydesk_id] = []
        self.ids_w_aliases[anydesk_id].append(alias)
        self.ids_w_aliases[anydesk_id] = list(set(self.ids_w_aliases[anydesk_id]))

    def trace_parser(self, loglist):
        """
        This function is used to parse the ad_svc.trace and ad.trace files.

        Both of these file have the same type of logs so they are parsed in the same way.
        Parameters
        ----------
        loglist: list[str]
            List of log files' locations to parse.

        Returns
        -------
            dict[int,list[dict[str, str]]]
                a dictionary where the keys are the sessions and the values are lists of dictionaries containing the log data per session.
        """
        index = 0
        sessions = {}

        for file in loglist:
            try:
                with open(file, 'r', errors='replace') as f:
                    index += 1
                    sessions[index] = []

                    for line in f:
                        if "* * * * *" in line:
                            if sessions[index]:
                                index += 1
                                sessions[index] = []
                                continue

                        line_dict = dict.fromkeys(
                            ["LogLevel", "Timestamp", "Service", "LogService", "Message", "Explanation", "File"])
                        split = line.split()
                        if not split:
                            continue
                        line_dict["LogLevel"] = split[0]
                        try:
                            line_dict["Timestamp"] = Anydesk.convert_to_datetime(' '.join(split[1:3]))
                        except ValueError:
                            line_dict["Timestamp"] = ""
                        line_dict["Service"] = split[3]
                        log = split[6:]
                        if log[0].isdigit():
                            log = log[1:]
                        log = ' '.join(log).split('-')
                        if len(log) < 2:
                            continue
                        line_dict["LogService"] = log[0]
                        line_dict["Message"] = ''.join(log[1:])
                        if "Incoming session request" in line_dict["Message"]:
                            self.match_id_to_alias(line_dict["Message"])
                        line_dict["File"] = file
                        line_dict["Explanation"] = self.pattern_match(
                            line_dict["LogService"] + " " + line_dict["Message"]
                        )
                        sessions.get(index).append(line_dict)
            except Exception as e:
                self.log(f"Exception occurred: {e}. {file} had an error!", "error")
        return sessions

    def connection_trace_parser(self, loglist):
        """
        This function is used to parse the connection_trace.txt files.
        Parameters
        ----------
        loglist: list[str]
            List of log files' locations to parse.

        Returns
        -------
            list[str]
                a list of strings containing the log data, separated by `#` character.
        #TODO: change it so it is already split?
        """
        results = []

        for file in loglist:
            lines = self.read_file(file)

            for data in lines:
                # Skip empty lines
                if not data.strip() or data.encode() == b"\x00":
                    continue

                # Format the data
                formatted_line = re.sub(r'\s{2,}', '#', data.replace('\x00', '').rstrip("\n"))
                if formatted_line:
                    results.append(formatted_line)

        return results

    def get_each_type(self):
        """
        This function is used to get each type of log file into separate lists, ad_svc_trace, ad_trace and connection_trace, all of which
        contain the file paths of the respective log files.
        Returns
        -------
            tuple[list[str], list[str], list[str]]
                a tuple containing 3 lists with the file paths of the respective log files.
        """
        ad_svc_trace = []
        ad_trace = []
        connection_trace = []
        file_trace = []
        for file in self.shared.trace_files:
            if file.endswith("ad_svc.trace") or ("ad_" in file and "svc" in file and file.endswith(".trace")):
                ad_svc_trace.append(file)
            elif file.endswith("ad.trace") or ("ad_" in file and file.endswith(".trace")):
                ad_trace.append(file)
            elif file.endswith("connection_trace.txt"):
                connection_trace.append(file)
            elif file.endswith("trace.txt") and "file_transfer" in file.split('\\')[-1]:
                file_trace.append(file)

        return ad_svc_trace, ad_trace, connection_trace, file_trace

    def file_type_count_log(self, ad_svc_trace, ad_trace, connection_trace):
        """
        Secondary function to log the number of files found for each type of log file.
        Parameters
        ----------
        ad_svc_trace: list[str]
        ad_trace: list[str]
        connection_trace: list[str]
        """
        log_file_types = [
            (ad_svc_trace, "ad_svc.trace"),
            (ad_trace, "ad.trace"),
            (connection_trace, "connection_trace.txt")
        ]
        for file_list, file_type in log_file_types:
            if file_list:
                self.log(f"Found {len(file_list)} {file_type} files", "success")
            else:
                self.log(f"No {file_type} files found in the system", "warning")

    def file_trace_parser(self, file_trace):
        results = []
        for file in file_trace:
            try:
                with open(file, 'r', encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        lines[i] = line.replace('\0', '')
            except Exception as e:
                self.log(f"Exception occurred: {e}", "error")
            for line in lines:
                temp = line.split('\t')
                if len(temp) < 5 or len(temp) > 6:
                    continue
                if not temp[1]:
                    temp.pop(1)
                temp.append('('+temp[-1].partition('\' (')[-1])
                temp[-2] = temp[-2].partition('\' (')[0]+'\''
                temp.append(file)
                dictionary = dict(zip(self.file_trace_keys, temp))
                dictionary["Timestamp"] = datetime.strptime(dictionary["Timestamp"], "%Y-%m-%d, %H:%M")
                dictionary["Timestamp"] = dictionary["Timestamp"].replace(tzinfo = self.shared.utc)


                results.append(dictionary)
        return results



    def logparse(self):
        """
        This function is used to parse the AnyDesk logs, is responsible for calling the parsing functions for each type of log file
        """
        if not self.shared.no_logging:
            self.log("AnyDesk log parsing <green>started</green>", "info")

        ad_svc_trace, ad_trace, connection_trace, file_trace = self.get_each_type()

        if not self.shared.no_logging:
            self.file_type_count_log(ad_svc_trace, ad_trace, connection_trace)

        # Parse each log type
        self.ad_svc_trace_results = self.trace_parser(ad_svc_trace) if ad_svc_trace else None
        self.ad_trace_results = self.trace_parser(ad_trace) if ad_trace else None
        self.connection_trace_results = self.connection_trace_parser(connection_trace) if connection_trace else None
        self.file_trace_results = self.file_trace_parser(file_trace) if file_trace else None

        if not self.shared.no_logging:
            self.log("AnyDesk log parsing <green>completed</green>")

    def parse(self):
        """
        This is practically the main class function that is called for all relevant functions regarding parsing

        Directly modifies relevant attributes in the class.
        """
        self.update_users()
        if not self.shared.no_logging:
            self.log('Parsing AnyDesk logs...')
        self.logparse()
        self.all_conf()
        self.attribution_ad_svc = self.get_sessions_attribution(self.ad_svc_trace_results)
        self.attribution_ad_trace = self.get_sessions_attribution(self.ad_trace_results)
        self.shared.reporting.report(self)
