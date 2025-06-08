from os import makedirs
from os.path import isdir
from RatFinder.classes.rats.anydesk import Anydesk
from RatFinder.classes.rats.teamviewer import Teamviewer
from RatFinder.classes.utils.Reports.excel import Excel
from RatFinder.classes.utils.Reports.csv_gen import CsvGen
from RatFinder.classes.utils.Templates.produce_template import Template


class Reporting:
    """
    Class for generating reports from RAT data.

    It generates reports in HTML, CSV, and Excel formats based on the provided RAT object, and is responsible
    to check if the RAT object contains any data to report. The reports are saved in the specified output directory. Also,
    it calls the appropriate methods to generate the reports based on the RAT type (Anydesk or Teamviewer).

    Attributes
    ----------
    shared : Shared
        `Shared` object containing output directory and report types, among other data.
    template: Template
        `Template` object for generating HTML reports.
    excel: Excel
        `Excel` object for generating Excel reports.

    """
    def __init__(self, shared):
        """
        Initializes the Reporting class.
        Parameters
        ----------
        shared: Shared
            `shared` object containing output directory and report types, among other data.
        """
        self.shared = shared
        self.template = None
        self.excel = None

    @staticmethod
    def check_for_data(rat_obj):
        """
        Static method to check if RAT object contains any data to report.
        Parameters
        ----------
        rat_obj: Anydesk or Teamviewer
            The RAT object to check for data.

        Returns
        -------
            bool | None
        """
        if isinstance(rat_obj, Anydesk):
            if rat_obj.ad_trace_results:
                return True
            if rat_obj.ad_svc_trace_results:
                return True
            return False
        elif isinstance(rat_obj, Teamviewer):
            if rat_obj.log_results or rat_obj.connections or rat_obj.rollout_info:
                return True
            else:
                return False

    @staticmethod
    def check_for_users(rat_object:Anydesk):
        """
        Static method to check if RAT object contains any users to report.
        Parameters
        ----------
        rat_object: Anydesk or Teamviewer

        Returns
        -------
            bool | None
        """
        for user in rat_object.shared.system_users.values():
            for values in user.values():
                for inner_values in values.values():
                    if inner_values:
                        return True

        return False

    def report(self, rat_object):
        """
        Main class that generates the reports based on the RAT object automatically.
        Parameters
        ----------
        rat_object: Anydesk or Teamviewer
        """
        has_data = Reporting.check_for_data(rat_object)
        has_users = Reporting.check_for_users(rat_object)

        if not isdir(self.shared.output) and (has_users or has_data):
            makedirs(self.shared.output)

        if 'HTML' in self.shared.reports and (has_users or has_data):
            self.__html_log_report(rat_object)

        if not has_data:
            return

        if 'CSV' in self.shared.reports:
            self.__csv_log_report(rat_object)

        if 'EXCEL' in self.shared.reports:
            self.__excel_log_report(rat_object)

    def __excel_log_report(self, rat_object):
        """
        Helper function that generates the EXCEL report based on the RAT object.
        Parameters
        ----------
        rat_object: Anydesk or Teamviewer

        """
        self.excel = Excel(rat_object)
        if isinstance(rat_object, Anydesk):
            self.excel.write_anydesk()
        elif isinstance(rat_object, Teamviewer):
            self.excel.write_teamviewer()

    def __csv_log_report(self, rat_object):
        """
        Helper function that generates the CSV report based on the RAT object.
        Parameters
        ----------
        rat_object: Anydesk or Teamviewer
        """
        self.csv = CsvGen(rat_object)
        if isinstance(rat_object, Anydesk):
            self.csv.generate_anydesk()
        elif isinstance(rat_object, Teamviewer):
            self.csv.generate_teamviewer()

    def __html_log_report(self, rat_object):
        """
        Helper function that generates the HTML report based on the RAT object.
        Parameters
        ----------
        rat_object: Anydesk or Teamviewer
        """
        self.template = Template(self.shared)
        if isinstance(rat_object, Anydesk):
            self.template.generate_anydesk(rat_object)
        elif isinstance(rat_object, Teamviewer):
            self.template.generate_teamviewer(rat_object)