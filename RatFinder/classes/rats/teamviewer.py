import re
import sys
import ipaddress
from os import sep
import requests
from datetime import datetime
class Teamviewer:
    """
    This class is responsible for parsing Teamviewer.

    This class is responsible for the parsing of Teamviewer, which includes every type of log parsing, description adding
    to each message, and session attribution.

    Attributes
    ----------
    shared : Shared
        The shared object that contains the necessary data.
    log_results : dict[str, list[dict[str, str | dict[str, str]]]]
        The parsed log results. Each top-level key corresponds to a filename where entries were found.
        The value for each key is a list of dictionaries, each representing a unique session.
        Each session dictionary contains parsed fields: some are direct key–value pairs (shared across the session), while others are grouped under the Data key.
        The Data field holds a dictionary containing the session's detailed entries, parsed from the log lines.
    teamviewer_keys : list[str]
        The keys-fields that are used to store the TeamViewer information in the system_users dictionary.
    fields_wanted : list[str]
        The fields that are used in the log_reporting list. These contain the general fields shared among the session.
    log_fields : list[str]
        The actual fields that come from parsing the logs line by line.
    connection_file_keys : list[str]
        The fields that are used for the connection type files.
    connections : list[dict[str, str]]
        The parsed connection type results. Each entry is a dictionary with keys defined in connection_file_keys.
    rollout_keys : list[str]
        The fields that are used for the rollout type files.
    rollout_info: list[dict[str, str]]
        The parsed rollout type results. Each entry is a dictionary with keys defined in rollout_keys.
    teamviewer_log_dict : dict[str, str]
        The dictionary that contains the log patterns and their descriptions. The keys are the regex patterns to match with log messages.
    log_reporting_fields : list[str]
        The fields that are used for reporting. These are the fields that will be used to report the log results.
        They are a combination of log_fields and some additional fields that are added for reporting purposes.
    """
    def __init__(self, shared):
        """
        Initialises the Teamviewer class.
        Parameters
        ----------
        shared: Shared
            `shared` object that contains the necessary data, shared among scripts.
        """
        self.shared = shared
        self.log_results = None
        self.teamviewer_keys = []
        self.fields_wanted = ["Data", "ID", "IP", "OS", "UserAccount"]
        self.log_fields = ["Timestamp", "PPID", "PID", "LogLevel", "Log", "Explanation"]
        self.connection_file_keys = ["ConnectorTeamViewerID",
                        "ConnectorFullName",
                        "TimestampStart",
                        "TimestampFinish",
                        "LocalMachineUser"
                        ,"ConnectionType",
                        "UnknownIdentifier",
                        "Direction", "FileFound"] #connection file fields
        self.connections = None #connection file results
        self.actor_times = {}
        self.actor_ips = {}
        self.rollout_keys = ["TeamViewerID", "UnknownIdentifier1", "UnknownIdentifier2"]
        self.rollout_info = []
        self.teamviewer_log_dict = {
            # Priority:
            r"Session was NOT closed.* ClientID:": "Session did not terminate gracefully for ClientID that is referenced",
            r"Session.*subscribed.*":"Information about session and relevant Teamviewer ID",
            r"Channel \(":"Channel information",
            # Connection Events
            r".*AddParticipant.*": "Participant - session information",
            r"Outgoing connection": "The local user initiated a remote session to another device.",
            r"Incoming connection": "A remote user connected to this device.",
            r"Connection established": "The remote connection is fully active.",
            r"closed": "A remote session was terminated.",
            r"Quit reason": "The remote session ended and the reason was logged.",
            r"removing session": "Session terminating",
            r"Client connection to":"Client outgoing connection",
            r"participant.*\[":"A participant's id and session was referenced",

            # Authentication Events
            r"Authentication.*successful": "User authentication was successful for a session.",
            r"Authentication.*failed": "Authentication attempt failed, potentially indicating brute force or incorrect login.",
            r"Token.*accepted": "A session token was accepted, allowing continued access.",

            # File Transfer Events
            r"FileTransfer='Allowed'": "FileTransfer operations where allowed",
            r"FileTransfer": "A file transfer operation occurred during the session.",
            r"Transfer.*complete": "A file transfer completed successfully.",
            r"Transfer.*failed": "A file transfer attempt failed — possibly blocked or interrupted."
        }


        self.attributed = {}

        self.log_reporting_fields = self.log_fields.copy()
        self.log_reporting_fields.extend(["Connection ID", "OS", "IPs found in system", "SystemUser", "LogFile"])

    @staticmethod
    def is_date(date):
        """
        Check if the date is in the format dd-mm-yyyy
        Parameters
        ----------
        date: str
            A date string

        Returns
        -------
            bool | None
        """

        try:
            datetime.strptime(date, "%d-%m-%Y")
            return True
        except ValueError:
            return False

    def parse_rollout(self):
        """
        Parse the rollout information from the TeamViewer log files.
        Returns
        -------

        """
        data = []

        for file in self.shared.teamviewer_logfiles:
            actual = file.split(sep)[-1]
            if 'rollout' in actual:
                with open(file, 'r') as f:
                    for line in f:
                        info = dict.fromkeys(self.rollout_keys)
                        split = line.split(',')
                        if split:
                            info[self.rollout_keys[0]] = split[0]
                            info[self.rollout_keys[1]] = split[1]
                            info[self.rollout_keys[2]] = split[2]
                            data.append(info)

        self.rollout_info = data


    def parse_connections(self):
        """
        Parse the connection information from the TeamViewer connection log files.
        Returns
        -------

        """
        data = []


        for file in self.shared.teamviewer_logfiles:
            actual = file.split(sep)[-1]

            if not 'connections' in actual.lower():
                continue

            with open(file, 'r') as f:
                for line in f:
                    split = line.split()
                    if split:
                        assert len(split) >= 8, f"{split} must be over 8 fields so it can be fixed to 10"
                        connection = dict.fromkeys(self.connection_file_keys)
                        if '}' not in split[-1]:
                            split.append('')
                        if len(split) == 8:
                            split.insert(1, "")  # First and last name is missing
                            split.insert(2, "")
                        if len(split) == 9:
                            split.insert(2, "")
                        connection[self.connection_file_keys[0]] = split[0]  # ID
                        connection[self.connection_file_keys[1]] = ' '.join(split[1:3])  # FullName
                        connection[self.connection_file_keys[2]] = ' '.join(split[3:5]) #start
                        try:
                            datetime.strptime(connection[self.connection_file_keys[2]], "%d-%m-%Y %H:%M:%S")
                            connection[self.connection_file_keys[3]] = ' '.join(split[5:7])  # finish
                            connection[self.connection_file_keys[4]] = split[7]
                            connection[self.connection_file_keys[5]] = split[8]
                            connection[self.connection_file_keys[6]] = split[9]
                        except ValueError:
                            connection[self.connection_file_keys[1]] = ' '.join(split[1:4])  # FullName
                            connection[self.connection_file_keys[2]] = ' '.join(split[4:6])
                            connection[self.connection_file_keys[3]] = ' '.join(split[6:8])
                            connection[self.connection_file_keys[4]] = split[8]
                            connection[self.connection_file_keys[5]] = split[9]
                            connection[self.connection_file_keys[6]] = split[10]
                        try:
                            connection[self.connection_file_keys[2]] = datetime.strptime(connection[self.connection_file_keys[2]], "%d-%m-%Y %H:%M:%S")
                            connection[self.connection_file_keys[2]] = connection[self.connection_file_keys[2]].replace(tzinfo=self.shared.utc)
                        except ValueError:
                            pass
                        try:
                            connection[self.connection_file_keys[3]] = datetime.strptime(connection[self.connection_file_keys[3]], "%d-%m-%Y %H:%M:%S")
                            connection[self.connection_file_keys[3]] = connection[self.connection_file_keys[3]].replace(tzinfo=self.shared.utc)
                        except ValueError:
                            pass


                        if len(split) > 10:
                            for i, temporary in enumerate(split):
                                if Teamviewer.is_date(temporary):
                                    split[1] = ' '.join(split[1:i])
                                    break
                            split[2] = ""
                            del split[3:i]

                        assert len(split) == 10, f"{split} line must have 10 fields not {len(split)}"

                        if '_incoming' in file:
                            connection[self.connection_file_keys[7]] = "Incoming"
                        else:
                            connection[self.connection_file_keys[7]] = "Outgoing"

                        connection[self.connection_file_keys[8]] = file

                        data.append(connection)

        self.connections = data

    def __check_description(self, message):
        """
        Check if the message is in the teamviewer_log_dict and return the description.
        Parameters
        ----------
        message: str
            The message to check the patterns against.

        Returns
        -------
            str
                the description if the matching pattern is found, otherwise an empty string.
        """
        for pattern in self.teamviewer_log_dict.keys():
            if re.search(pattern=pattern, string=message):
                return self.teamviewer_log_dict.get(pattern, "")
        return ""


    def __parse_row(self, row):
        """
        Parses a row of the TeamViewer log file and returns a dictionary with the relevant fields.
        Parameters
        ----------
        row: str
            The row to parse.

        Returns
        -------
            dict
                dictionary that contains the relevant fields.
        """
        row_split = [data for data in row.split(' ') if data]
        row_split[5] = ' '.join(row_split[5:]).rstrip().lstrip()
        del row_split[6:]
        if '!!!' in row_split[4]:
            temp1, temp2 = row_split[4].split('!!!')[0], row_split[4].split('!!!')[1]
            row_split[4] = temp1+"!!!"
            row_split[5] = temp2 + " " + row_split[5]

        row_split[1] = ' '.join(row_split[:2])
        row_split.pop(0)
        dictionary = dict(zip(self.log_fields[:-1], row_split))
        dictionary["Explanation"] = self.__check_description(dictionary["Log"])

        dictionary["Timestamp"] = datetime.strptime(dictionary["Timestamp"], "%Y/%m/%d %H:%M:%S.%f")
        dictionary["Timestamp"] = dictionary["Timestamp"].replace(tzinfo=self.shared.timezone)
        dictionary["Timestamp"] = dictionary['Timestamp'].astimezone(self.shared.utc)

        return dictionary

    def update_users(self):
        """
        Update the system_users dictionary with the TeamViewer information.
        Returns
        -------

        """
        for user in self.shared.system_users.keys():
            self.shared.system_users[user]["TeamViewer"] = dict.fromkeys(self.teamviewer_keys)

    def log(self, message, mtype="info"):
        """
        Log the message with the given type.
        Parameters
        ----------
        message: str
            The message you want to log.
        mtype: str
            Message severity.

            Must be one of these:
                - error
                - info
                - success
                - warning

        Returns
        -------

        """
        match mtype:
            case "error":
                self.shared.logger.bind(category="teamviewer").error(message)
            case "info":
                self.shared.logger.bind(category="teamviewer").info(message)
            case "success":
                self.shared.logger.bind(category="teamviewer").success(message)
            case "warning":
                self.shared.logger.bind(category="teamviewer").warning(message)
            case _:
                self.shared.logger.bind(category="teamviewer").info(message)

    def __fix_dict(self):
        """
        Fix the dictionary by changing some wrongly parsed fields that contain : in the key.
        Returns
        -------

        """
        to_del = []
        for key, fields in self.log_results.items():
            for i, field in enumerate(fields):
                for ikey, res in field.items():
                    if ':' in ikey:
                        to_del.append([key, i, ikey])

        for key, i, ikey in to_del:
            self.log_results[key][i][ikey.replace(':', '')] = self.log_results[key][i][ikey]
            del self.log_results[key][i][ikey]

        for key in self.log_results.keys():
            for row in self.log_results[key]:
                todel = [key for key in row if key not in self.fields_wanted]
                for key2 in todel:
                    del row[key2]


    def get_actor_ips(self):
        actor_times = self.actor_times.copy()
        if actor_times.get(" "):
            actor_times[""] = actor_times[" "]
            del(actor_times[" "])
        for actor in self.attributed:
            if not self.actor_ips.get(actor):
                self.actor_ips[actor] = []
            for row in self.attributed[actor]:
                if not actor_times.get(actor):
                    #print(actor_times, f"skipped:{actor}")
                    continue
                for time_dict in actor_times[actor]:
                   if time_dict["start"] <= datetime.fromisoformat(row["Timestamp"]) <= time_dict["end"]:
                        if "udp" in row["Log"].lower() and (ip := re.search(r"\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b", row["Log"])):
                            ip = ip.group(0)
                            geodata = {}
                            if ipaddress.ip_address(ip).is_global:
                                geodata = Teamviewer.query_for_geodata(ip)
                            self.actor_ips[actor].append({"end":time_dict["end"], "start":time_dict["start"], "ip":ip, "is_public":ipaddress.ip_address(ip).is_global, "geodata":geodata})
        #print(self.actor_ips)
    @staticmethod
    def query_for_geodata(ip) -> dict:
        """
        This function is used to query the geolocation data for a given IP address.
        It uses the ip-api.com service to get the geolocation data.
        Arguments:
            ip (str): The IP address to query.
        Returns:
            dict: A dictionary containing the geolocation data for the given IP address.
            The dictionary contains the following fields:

            - query (str): The IP address.
            - status (str): The status of the query (success or fail).
            - country (str): The country of the IP address.
            - countryCode (str): The country code of the IP address.
            - region (str): The region of the IP address.
            - regionName (str): The name of the region of the IP address.
            - city (str): The city of the IP address.
            - zip (str): The zip code of the IP address.
            - lat (float): The latitude of the IP address.
            - lon (float): The longitude of the IP address.
            - timezone (str): The timezone of the IP address.
            - isp (str): The ISP of the IP address.
            - org (str): The organization of the IP address.
            - as (str): The AS number of the IP address.

        If the query fails or the IP address is invalid, an empty dictionary is returned.

        """
        link = f"http://ip-api.com/json/{ip}"
        response = requests.get(link)
        if response.status_code == 200:
            response = response.json()
            if response.get("status") == "success":
                return response
        return {}
    def attribute_connections_w_logs_to_actors(self):
        def compare_str(timestamp_dict, target_):
            for actor_ in timestamp_dict.keys():
                for time_dict in timestamp_dict[actor_]:
                    if time_dict["start"] <= target_ <= time_dict["end"]:
                        return actor_
            return ""

        actors_times = {}
        for connection in self.connections:
            if connection.get("ConnectorFullName") not in actors_times.keys():
                actors_times[connection.get("ConnectorFullName")] = []
            actors_times[connection.get("ConnectorFullName")].append(
                {"start": connection.get("TimestampStart"),
                 "end": connection.get("TimestampFinish")})

        self.actor_times = actors_times.copy()

        for file in self.log_results.keys():
            for session in self.log_results.get(file, []):
                for row in session.get("Data"):
                    target = row.get("Timestamp")
                    actor = compare_str(actors_times, target)
                    if actor not in self.attributed:
                        self.attributed[actor] = []
                    data = row.copy()
                    data["Timestamp"] = str(data["Timestamp"])
                    data["IP"] = session.get("IP")
                    data["ID"] = session.get("ID")
                    data["OS"] = session.get("OS")
                    data["UserAccount"] = session.get("UserAccount")
                    self.attributed[actor].append(data)

    def __log_parse(self):
        """
        Parse the TeamViewer log files and store the results in the log_results dictionary. Also calls the fix_dict method.
        Returns
        -------

        """
        files = {}

        for file in self.shared.teamviewer_logfiles:
            try:
                if "connection" in file or "rollout" in file:
                    continue
                with open(file, 'r') as f:
                    index = -1
                    for line in f:
                        if line:
                            line_split = line.split(' ')
                            field = line_split[0].rstrip().lstrip()

                            # CPU extensions field
                            if 'CPU extensions' in line:  # This is unique so it must be addressed here
                                field = 'CPU extensions'
                                data = line.split(':')[1:]
                                data = ' '.join(data).rstrip().lstrip()
                                # print(repr(line))
                                files[file][index][field] = data

                            # Normal Field
                            if ':' in field:  # If : is present in the first field it means it is a field...
                                data = ''.join(line_split[1:]).rstrip().lstrip()
                                if not file in files:
                                    files[file] = []
                                if 'Start' in field:  # Every connection starts with Start:...
                                    index += 1
                                    files[file].append({})
                                try:
                                    files[file][index][field] = data
                                except IndexError:
                                    print(f"IndexError: {index} for {file}")

                            # Data field
                            if len(line_split) >= 2:
                                if ':' in line_split[1] and 'CPU extensions' not in line:  # Check for the connections data
                                    field = 'Data'
                                    if index != -1:
                                        if not 'Data' in files[file][index]:
                                            files[file][index]['Data'] = []
                                        files[file][index][field].append(self.__parse_row(line))
            except FileNotFoundError:
                print(f"File not found: {file}")
            except UnicodeDecodeError as e:
                print('UnicodeDecodeError:', e, f'in file {file}')
            except PermissionError as e:
                print('PermissionError:', e, f'in file {file}')
            except KeyboardInterrupt:
                print('KeyboardInterrupt received, exiting...')
                sys.exit(0)
            except Exception as e:
                print('Error:', e, f'in file {file}')

        self.log_results =  files
        self.__fix_dict()

    def parse(self):
        """
        "Main" function that is responsible for parsing TeamViewer artifacts.
        Returns
        -------

        """

        if not self.shared.no_logging:
            self.log('Parsing TeamViewer logs...')

        self.update_users()
        self.__log_parse()
        self.parse_connections()
        self.parse_rollout()

        if not self.log_results and not self.shared.no_logging:
            self.log('No TeamViewer logs found.',"warning")
            return

        self.attribute_connections_w_logs_to_actors()
        self.get_actor_ips()
        self.shared.reporting.report(self)
        if not self.shared.no_logging:
            self.log('TeamViewer parsing completed...')
