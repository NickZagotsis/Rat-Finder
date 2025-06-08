import re
from os import makedirs
from os.path import join as pjoin, exists
class CsvGen:
    """
    This class is used for the generation of csv reports of all RAT instances provided.

    Attributes
    --------
    rat : Anydesk | Teamviewer
        The RAT instance to be used for the generation of csv reports.
    out : str
        The output directory for the csv reports.
    delim : str
        The delimiter used for the csv reports. Default is tab (\\t character).

    """
    def __init__(self, rat):
        self.rat = rat
        self.out = pjoin(self.rat.shared.output, 'csv')
        self.delim = '\t'
        if not exists(self.out):
            makedirs(self.out)

    def __create_file_trace(self, writable):
        if self.rat.file_trace_results:
            writable.write(self.delim.join(self.rat.file_trace_keys) + "\n")
            for row in self.rat.file_trace_results:
                writable.write(self.delim.join([str(s).rstrip().lstrip() for s in row.values()]) + "\n")



    def generate_anydesk(self):
        """
        This method generates the csv reports for Anydesk RAT instance.
        It generates two csv files: Anydesk_results.csv and Anydesk_connections.csv.
        Anydesk_results.csv contains the results of the two anydesk logs (ad_svc.trace and ad.trace), whereas
        anydesk_connections.csv contains the connections found in connection_trace.txt file.
        """
        cols = ["LogLevel", "Timestamp", "Service", 'LogService', 'Message', "Explanation", 'File', "File_Type",
                "Session"]
        with open(pjoin(self.out, 'anydesk_results.csv'), 'w') as f:
            self.__create_csv_anydesk(f, cols, self.rat.ad_svc_trace_results, 'ad_svc.trace')

        with open(pjoin(self.out, 'anydesk_results.csv'), 'a') as f:
            self.__create_csv_anydesk(f, cols, self.rat.ad_trace_results, 'ad.trace')

        with open(pjoin(self.out, 'anydesk_results_connections.csv'), 'w') as f:
            self.__create_csv_connections_anydesk(f, self.rat.connection_trace_results)

        with open(pjoin(self.out, "anydesk_file_transfers.csv"), 'w') as f:
            self.__create_file_trace(f)


    def __create_csv_connections_anydesk(self, writable, data_list: list[str]):
        """
        This is a helper method that creates the csv file for Anydesk RAT instance.

        Arguments
        ---------
            writable : TextIO
                The writable object to write the csv file.
            data_list : dict[list[dict]]
                The dictionary containing the data to be written in the csv file.

        """
        cols = ["Connection type", "Timestamp", "Authentication", "User", "AnyDesk Connection ID"]
        writable.write(self.delim.join(cols) + '\n')
        for row in data_list[:-1]:
            writable.write(self.delim.join(row.split('#')) + '\n')

    def __create_csv_anydesk(self, writable, cols, data_list: dict[list[dict]], file_type):
        """
        This is a helper method that creates the csv file for Anydesk RAT instance.

        Arguments
        ---------
            writable : TextIO
                The writable object to write the csv file.
            cols : list
                The list of columns to be used in the csv file.
            data_list : dict[list[dict]]
                The dictionary containing the data to be written in the csv file.
            file_type : str
                The type of the file to be used in the csv file. It can be either 'ad_svc.trace' or 'ad.trace'.

        """
        writable.write(self.delim.join(cols) + '\n')
        for key, data_values in data_list.items():
            for data in data_values:
                values = list(data.values())
                values.append(file_type)
                values.append(str(key))
                writable.write(self.delim.join(values) + '\n')

    def teamviewer_write(self):
        """
        This method generates the csv reports for Teamviewer RAT instance.
        It generates three csv files: teamviewer_logs.csv, teamviewer_connections.csv and rollout_info.csv.
        teamviewer_logs.csv contains the results of the teamviewer logs (teamviewer*.log)
        teamviewer_connections.csv contains the connections found in connections*.txt files.
        rollout_info.csv contains the rollout information found in the teamviewer logs.
        """
        dic = self.rat.log_results
        if dic:
            with open(pjoin(self.out, 'teamviewer_logs.csv'),'w') as f:
                field_list = self.rat.log_reporting_fields
                f.write('\t'.join(field_list)+'\n')
                for filename in dic.keys():
                    rows = dic[filename]
                    for row in rows:
                        general_data = [row[key].rstrip().lstrip() for key in row.keys() if key != "Data"]
                        for data_row in row["Data"]:
                            toprint = []
                            toprint.extend([str(temp).lstrip().rstrip() for temp in data_row.values()])
                            toprint.extend(general_data)
                            toprint.append(filename)
                            f.write(self.delim.join(toprint)+"\n")

        connections = self.rat.connections
        if connections:
            with open(pjoin(self.out, 'teamviewer_connections.csv'),'w') as f:
                f.write(self.delim.join(list(connections[0].keys())) +'\n')
                for connection in connections:
                    f.write(self.delim.join([str(t) for t in connection.values()]) + '\n')

        rollout_info = self.rat.rollout_info
        if rollout_info:
            with open(pjoin(self.out, 'rollout_info.csv'), 'w') as f:
                f.write(self.delim.join(list(rollout_info[0].keys()))+'\n')
                for entry in rollout_info:
                    f.write(self.delim.join(list(entry.values())) + '\n')


    def generate_teamviewer(self):
        """
        Base class to generate the csv reports for Teamviewer RAT instance.
        """
        self.teamviewer_write()