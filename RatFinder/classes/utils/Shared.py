from zoneinfo import ZoneInfo

from RatFinder.classes.rats.Reporting import Reporting

class Shared:
    """
    Shared class to hold all the shared variables and instances, this is practically a dataclass.

    Attributes:
        input (str): Input file path
        output (str): Output file path
        no_logging (bool): Disable logging
        logger (Logger): Logger instance
        system_users (dict): Dictionary of system users
        full (bool): Full mode flag
        rats (list): List of RATs to be parsed
        modules (list): List of modules to be parsed
        reports (list): List of reports
        reporting (Reporting): Reporting instance
        trace_files (list): List of Anydesk trace files
        teamviewer_logfiles (list): List of Teamviewer log files
    """
    def __init__(self):
        #IO
        self.input = None
        self.output = None

        #Logging
        self.no_logging = None # Disable logging
        self.logger = None # Logger instance

        #Users
        self.system_users = {}

        #Logic
        self.full = True
        self.rats = None # List of RATs to be parsed
        self.modules = None # List of modules to be parsed
        self.reports = None
        self.reporting = Reporting(self) # Reporting instance

        #Anydesk
        self.trace_files = [] # List of trace files
    
        #Teamviewer
        self.teamviewer_logfiles = []

        #Timezones
        self.timezone = ZoneInfo("Europe/Athens")
        self.utc = ZoneInfo("UTC")

    def __str__(self):
        return self.__dict__.__str__()