from abc import ABC, abstractmethod

from .log_parser import LogEntry


class AbstractIpBlockExecution(ABC):
    @abstractmethod
    def begin_execute(self):
        pass

    @abstractmethod
    def block(self,log: LogEntry):
        pass

    @abstractmethod
    def end_execute(self):
        pass


class FileBasedUWFBlock(AbstractIpBlockExecution):
    """
        write generated firewall rules into a file
    """

    def __init__(self, destinate_path: str):
        self.__destinate_path = destinate_path
        self.__blocked_item = []

    def begin_execute(self):
        self.__blocked_item = []
        pass

    def block(self,log: LogEntry):
        self.__blocked_item.append(f"ufw deny from {log.network} to any\n")
        pass

    def end_execute(self):
        with open(self.__destinate_path, 'w') as f:
            f.write("#!/bin/bash\n")
            f.writelines(self.__blocked_item)
        pass