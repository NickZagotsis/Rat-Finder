import os
import re
import sys
import requests
import ipaddress
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
class Template:
    """
    This class is used to generate HTML reports using Jinja2 templates for all RATs.



    Attributes:
        shared: An instance of the Shared class containing shared data.
        out: The output directory for the generated HTML reports.
        env: The Jinja2 environment for rendering templates.
    """
    def __init__(self, shared):
        self.shared = shared
        self.out = os.path.join(self.shared.output, 'html')
        self.env =  Environment(loader=FileSystemLoader(Template.get_template_dir()))
        if not os.path.isdir(self.out):
            os.makedirs(self.out)

    @staticmethod
    def is_global(address):
        """
        Check if the given IP address is a global address.

        Arguments:
            address (str): The IP address to check.
        """
        try:
            return ipaddress.ip_address(address).is_global
        except ValueError:
            return False

    @staticmethod
    def get_template_dir():
        """
        Get the directory where the Jinja2 templates are located.
        This method checks if the script is running from a bundled executable (e.g., PyInstaller) and adjusts the
        template directory accordingly.

        Returns:
            str: The path to the directory containing Jinja2 templates.
        """
        if getattr(sys, 'frozen', False):  # Check if running from a bundled executable
            # We use _MEIPASS to get the path of the temporary folder where the executable unpacks resources
            return os.path.join(sys._MEIPASS, 'jinja', 'templates')
        else:
            project_dir = os.path.dirname(os.path.abspath(__file__))  # Get the absolute path of the current script
            return os.path.join(project_dir, 'jinja', 'templates')

    @staticmethod
    def convert_to_datetime(timestamps):
        """
        Convert timestamps to datetime objects or format them as strings.
        This method handles both single timestamp strings and lists of timestamps.
        Arguments:
            timestamps (str or list): The timestamp(s) to convert.
        returns:
            str or list[str]: The converted timestamp(s) as list of formated strings or a single formatted string, depending on the input.
        """
        if isinstance(timestamps, str):
            return datetime.strptime(timestamps, "%Y-%m-%d %H:%M:%S.%f").strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(timestamps, list):
            return [datetime.strptime(ts, "%Y-%m-%d %H:%M:%S") for ts in timestamps]

    @staticmethod
    def _anydesk_info_helper(anydesk, data:dict):
        """
        This is a helper function to extract information from the Anydesk logs.

        This function is used to populate the ips, clients, and timestamps dictionaries in the Anydesk class.

        Arguments:
            anydesk (AnyDesk): An instance of the AnyDesk class containing Anydesk data.
            data (dict): A dictionary containing the log data, including 'timestamp', 'log_data', and 'file'.
        """
        timestamp = Template.convert_to_datetime(data['timestamp'])
        if ip := re.search(anydesk.IP_REGEX, data['log_data']):
            ip = ip.group()

            if ip not in anydesk.ips:
                anydesk.ips[ip] = []
            if ip not in anydesk.ips_timestamps:
                anydesk.ips_timestamps[ip] = []

            if data['file'] not in anydesk.ips[ip]:
                anydesk.ips[ip].append(data['file'])

            if timestamp not in anydesk.ips_timestamps[ip]:
                anydesk.ips_timestamps[ip].append(timestamp)

        elif client := re.search(anydesk.CLIENT_ID_REGEX, data['log_data']):
            client = client.group()
            if client not in anydesk.clients_timestamps:
                anydesk.clients_timestamps[client] = []

            if timestamp not in anydesk.clients_timestamps[client]:
                anydesk.clients_timestamps[client].append(timestamp)

    @staticmethod
    def anydesk_info(anydesk):
        """
        This function is used to extract information from the Anydesk logs.
        This is the function that calls the helper function to populate the ips, clients, and timestamps dictionaries in the Anydesk class.

        Arguments:
            anydesk (AnyDesk): An instance of the AnyDesk class containing Anydesk data.
        """
        temp = [anydesk.ad_svc_trace_results,anydesk.ad_trace_results]
        for data_list in temp:
            if not data_list:
                continue
            for temp_values in data_list.values():
                for dic in temp_values:
                    data = {'timestamp': dic["Timestamp"], 'log_data': dic["Message"], 'file': dic['File']}
                    if 'relay' in dic["LogService"] or 'multicast' in data['log_data'] or 'Using' in data['log_data'] or 'External address' in data['log_data']:
                        continue
                    Template._anydesk_info_helper(anydesk, data)

    @staticmethod
    def match_for_anydesk(ips_timestamps, clients_timestamps, ips):
        """
        This function is used to match the ips and clients timestamps.

        It checks if the timestamps are within 1 second of each other and returns a dictionary with the matched data.
        Arguments:
            ips_timestamps (dict): A dictionary containing IP addresses and their timestamps.
            clients_timestamps (dict): A dictionary containing client IDs and their timestamps.
            ips (dict): A dictionary containing IP addresses and their associated file found.

        returns:
            dict[Any , dict[str,str]]: A dictionary containing matched data. The keys are client IDs, and the values are dictionaries with IP addresses and their earliest and latest timestamps.
        """
        match = {}
        if ips_timestamps and clients_timestamps and ips:
            ips_timestamps = {ip: Template.convert_to_datetime(times) for ip, times in ips_timestamps.items()}
            clients_timestamps = {client: Template.convert_to_datetime(times) for client, times in
                                  clients_timestamps.items()}
            for client, client_times in clients_timestamps.items():
                for client_time in client_times:
                    for ip, ip_times in ips_timestamps.items():
                        for ip_time in ip_times:
                            if abs((client_time - ip_time).total_seconds()) < 1:  # Check time difference
                                if client not in match:
                                    match[client] = {}
                                if ip not in match[client]:
                                    match[client][ip] = {"earliest": client_time, "latest": client_time}
                                else:
                                    # Update earliest and latest timestamps
                                    match[client][ip]["earliest"] = min(match[client][ip]["earliest"], client_time)
                                    match[client][ip]["latest"] = max(match[client][ip]["latest"], client_time)
            for client, ips_data in match.items():
                for ip, times in ips_data.items():
                    times["earliest"] = times["earliest"].strftime("%Y-%m-%d %H:%M:%S")
                    times["latest"] = times["latest"].strftime("%Y-%m-%d %H:%M:%S")
        return match

    @staticmethod
    def fix_connection_trace(anydesk):
        client_ids_trace = []
        if anydesk.connection_trace_results is None:
            anydesk.connection_trace_results = []
        for row in anydesk.connection_trace_results:
            client_ids_trace.append(row.split('#')[-1])
            client_ids_trace.append(row.split('#')[-2])
        return client_ids_trace
    @staticmethod
    def write_unique_output(out, name, output):
        """
        This is a function created to produce a unique file given the "name" parameter

        Arguments
        ---------
        out :  str
            the output folder
        name : str
            the name of the file
        output :  str
            the data used to create the file
        """
        if not os.path.isdir(out):
            os.makedirs(out)
        out = os.path.join(out, name)
        i = 1
        # Check if the file already exists and increment the number until a unique filename is found
        while os.path.exists(out + '.html'):
            # Replace the previous number with the next one (e.g., '_1', '_2', ...)
            out_with_number = out + f'_{i}'  # Add a number suffix like '_1', '_2'
            if not os.path.exists(out_with_number + '.html'):
                out = out_with_number  # Set the unique filename
            i += 1
        out = out + '.html'
        with open(out, 'w', errors = 'replace') as f:
            f.write(output)

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

    @staticmethod
    def get_files(anydesk, target):
        """
        This function is used to get the files downloaded or uploaded that match the given AnyDesk ID

        Arguments:
            anydesk (AnyDesk): An instance of the AnyDesk class containing Anydesk data.
            target (str): The AnyDesk ID to search for in the session data.

        Returns:
            tuple[list[dict], list[dict]]:
                A tuple containing two lists of dictionaries:

                - all_files_downloaded: A list of dictionaries containing the downloaded files that match the given AnyDesk ID.
                - all_files_uploaded: A list of dictionaries containing the uploaded files that match the given AnyDesk ID.
        """
        def helper(dic):
            all_files = []
            for file, session in dic.items():
                sess = list(session.keys())[0]
                if 'svc' in file:
                    try:
                        if target in anydesk.attribution_ad_svc[sess]['AnyDesk_id']:
                            all_files.append({file: session})
                    except KeyError:
                        print(
                            f"KeyError: {session} not found in attribution_ad_svc. DEBUG: {anydesk.attribution_ad_svc} {file} {session}")
                else:
                    try:
                        if target in anydesk.attribution_ad_trace[sess]['AnyDesk_id']:
                            all_files.append({file: session})
                    except KeyError:
                        print(
                            f"KeyError: {session} not found in attribution_ad_trace. DEBUG: {anydesk.attribution_ad_trace} {file} {session}"
                        )
            return all_files

        return (
            helper(anydesk.files_downloaded),
            helper(anydesk.files_uploaded)
        )

    @staticmethod
    def get_traffic(anydesk, target):
        """
        This function is used to get the session that matches for a given AnyDesk ID

        Arguments:
            anydesk (AnyDesk): An instance of the AnyDesk class containing Anydesk data.
            target (str): The AnyDesk ID to search for in the session data.
        Returns:
            list[dict[str, list]]: A list of dictionaries containing the session data that matches the given AnyDesk ID.
            The dictionaries contain the following fields:

            - Alias (list)
            - IP (list)
            - AnyDesk_id (list)
        """
        all_traffic = []
        files = []
        for key in anydesk.attribution_ad_trace:
            if target in anydesk.attribution_ad_trace[key]['AnyDesk_id']:
                all_traffic.extend(anydesk.ad_trace_results[key])
                for file in anydesk.file_trace_results:
                    if anydesk.attribution_ad_trace[key]["EarliestTimestamp"] <= file["Timestamp"] <= anydesk.attribution_ad_trace[key]["LatestTimestamp"]:
                        files.append(file)

        for key in anydesk.attribution_ad_svc:
            if target in anydesk.attribution_ad_svc[key]['AnyDesk_id']:
                all_traffic.extend(anydesk.ad_svc_trace_results[key])
                for file in anydesk.file_trace_results:
                    if anydesk.attribution_ad_svc[key]["EarliestTimestamp"] <= file["Timestamp"] <= anydesk.attribution_ad_svc[key]["LatestTimestamp"]:
                        files.append(file)

        unique_files = []
        seen = set()
        for d in files:
            t = tuple(sorted(d.items()))
            if t not in seen:
                seen.add(t)
                unique_files.append(d)
        return all_traffic, unique_files

    def generate_anydesk(self, anydesk):
        """
        Generate HTML reports for AnyDesk data.

        This method processes AnyDesk data and generates HTML reports using Jinja2 templates.

        Arguments:
            anydesk (AnyDesk): An instance of the AnyDesk class containing AnyDesk data.
        """
        out = self.out
        out = os.path.join(out,"AnyDesk")
        if not os.path.isdir(out):
            os.makedirs(out)
        Template.anydesk_info(anydesk)
        env = self.env
        ips = anydesk.ips if anydesk.ips else {}
        ips_timestamps = anydesk.ips_timestamps if anydesk.ips_timestamps else {}
        clients_timestamps = anydesk.clients_timestamps if anydesk.clients_timestamps else {}
        match = Template.match_for_anydesk(ips_timestamps, clients_timestamps, ips)
        ip_geo = {}
        for key, ips in match.items():
            for ip in ips:
                match[key][ip]["Global"] = Template.is_global(ip)
                if match[key][ip]["Global"]:
                    if not ip_geo.get(ip):
                        ip_geo[ip] = Template.query_for_geodata(ip)
                    match[key][ip]["Geodata"] = ip_geo.get(ip)


        countries = {}
        for key in match:
            countries[key] = []
            for ip in match[key]:
                countries[key].append(match[key][ip].get("Geodata",{}).get("country",""))
            countries[key] = ','.join([country for country in list(set(countries[key])) if country])


        template = env.get_template('AnyDesk/report.html')
        client_ids_trace = sorted(list(set(self.fix_connection_trace(anydesk))))
        match = dict(sorted(match.items()))
        ips_items = dict(sorted(ips.items()))
        output = template.render(ips=ips_items, matches= match, countries=countries,full=self.shared.full,
                                 users=anydesk.shared.system_users,
                                 connection_trace=anydesk.connection_trace_results,
                                 client_ids_trace=client_ids_trace, aliases = anydesk.ids_w_aliases, files = anydesk.file_trace_results)

        Template.write_unique_output(out, "general_report",output)

        for client in match.keys():
            all_traffic, files = self.get_traffic(anydesk, client)
            all_files_d, all_files_u = self.get_files(anydesk, client)
            template = env.get_template('AnyDesk/user_report.html')
            sum_ = {}

            for i, row in enumerate(all_traffic):
                if row["Explanation"]:
                    if not sum_.get(row["Explanation"], None):
                        sum_[row["Explanation"]] = []
                    sum_[row["Explanation"]].append(row)
            output = template.render(client = client, match = match[client], all_traffic=all_traffic, sum = sum_, all_files_d=all_files_d, all_files_u=all_files_u, files = files)
            Template.write_unique_output(os.path.join(out, "data", client), client, output)

            template = env.get_template('AnyDesk/logs.html')
            output = template.render(all_traffic=all_traffic)
            Template.write_unique_output(os.path.join(out, "data", client), client+"_logs", output)

    def generate_teamviewer(self, teamviewer):
        """
        Generate HTML reports for TeamViewer data.
        This method processes TeamViewer data and generates HTML reports using Jinja2 templates.
        Arguments:
            teamviewer (TeamViewer): An instance of the TeamViewer class containing TeamViewer data.
        """
        out = self.out
        out = os.path.join(out, "TeamViewer")
        if not os.path.isdir(out):
            os.makedirs(out)
        env = self.env

        ips = {}
        for actor in teamviewer.actor_ips:
            if not ips.get(actor, None):
                ips[actor] = []
            for entry in teamviewer.actor_ips[actor]:
                if entry.get("geodata").get("country"):
                    ips[actor].append(entry.get("geodata").get("country"))
                    ips[actor] = list(set(ips[actor]))

        for actor in ips:
            ips[actor] = ', '.join(ips[actor])


        template = env.get_template('TeamViewer/report.html')
        output = template.render(attributed=teamviewer.attributed, ips = ips ,connections = teamviewer.connections, rollout = teamviewer.rollout_info, log_fields = teamviewer.log_reporting_fields)
        Template.write_unique_output(out, "general_report",output)

        for actor in teamviewer.attributed.keys():
            if not actor:
                actor_temp = "Unknown"
            else:
                actor_temp = actor.replace('<', '_').replace('>', '_').replace(':', '_').replace('"', '_') .replace('/', '_').replace('\\', '_') .replace('|', '_').replace('?', '_').replace('*', '_')

            sum_ = {}
            for dic in teamviewer.attributed[actor]:
                if dic["Explanation"]:
                    if not sum_.get(dic["Explanation"], None):
                        sum_[dic["Explanation"]] = []
                    sum_[dic["Explanation"]].append(dic)

            template = env.get_template('TeamViewer/user_report.html')
            output = template.render(attributed = teamviewer.attributed[actor], actor = actor,
                                     connections = teamviewer.actor_times.get(actor, None), sum = sum_, ips=teamviewer.actor_ips[actor])
            Template.write_unique_output(os.path.join(out, "data", actor_temp), actor_temp, output)


            template = env.get_template('TeamViewer/user_logs.html')
            output = template.render(attributed = teamviewer.attributed[actor])
            Template.write_unique_output(os.path.join(out, "data", actor_temp), actor_temp+"_logs", output)