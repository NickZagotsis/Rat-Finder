from loguru import logger
from os import path, makedirs
from datetime import datetime

class Logger:
    """
    Logger class to handle logging for different RATs, using loguru.
    """
    def __init__(self, shared):
        self.shared = shared
        self.shared.logger = logger
        self.time = str(datetime.now().strftime("%Y-%m-%d %H-%M-%S"))+'.log'

    @staticmethod
    def __check_directory(given_path):
        if not path.isdir(given_path):
            makedirs(given_path)

    def __add_new_log(self, folder, category):
        self.shared.logger.add(path.join(folder, category+".log"), rotation="1 MB", backtrace=True, diagnose=True,
                   filter=lambda record: record["extra"].get("category") == category)

    def generate_general_logger(self):
        given_path = path.join(self.shared.output, "logs", "General")
        self.__check_directory(given_path)
        self.__add_new_log(given_path, "general")

    def generate_anydesk_logger(self):
        given_path = path.join(self.shared.output, "logs", "Anydesk")
        self.__check_directory(given_path)
        self.__add_new_log(given_path, "anydesk")

    def generate_teamviewer_logger(self):
        given_path = path.join(self.shared.output, "logs", "Teamviewer")
        self.__check_directory(given_path)
        self.__add_new_log(given_path, "teamviewer")