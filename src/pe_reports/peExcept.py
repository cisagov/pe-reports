from pe_reports import CENTRAL_LOGGING_FILE
import logging
LOGGER = logging.getLogger(__name__)

class CustomException(Exception):
    """No Data in the domain list. """
    def __init__(self, org, message="DnsTwist data did not collect seccessfully for org"):
        self.org = org
        self.message = message
        self.log()
        super().__init__(self.message)
    def __str__(self):
        return f'{self.message} : {self.org}'
    def log(self):
        LOGGER.error(f'{self.message} : {self.org}')


class SixGillApiException(Exception):
    """Exception for failure in sixgill alert insertions. """
    def __init__(self, org_id,six_gill_id, message="CyberSixGill was call was unsuccessful"):
        self.six_gill_id = six_gill_id  
        self.org = org
        self.message = message
        super().__init__(self.message)
    def __str__(self):
        return f'{self.message}, Org ID : {self.org}, Six Gill ID: {self.six_gill_id}'
    def log(self):
        LOGGER.error(f'{self.message} : {self.org}, Six Gill ID: {self.six_gill_id}')

class SixGillDatabaseException(Exception):
    """Exception for failure in sixgill alert insertions. """
    def __init__(self, org_id, message="Data insertion into the database was unsuccessful"):
        self.org = org
        self.message = message
        super().__init__(self.message)
    def __str__(self):
        return f'{self.message} , Source UID : {self.org}'
    def log(self):
        LOGGER.error(f'{self.message} : {self.org}')

class ShodanIPFailure(Exception):
    """Exception for failing to lookup Shodan ips . """
    def __init__(self, thread_name, org_name):
        self.org = org
        self.message = message
        super().__init__(self.message)
    def __str__(self):
        return "{} Failed fetching IPs for {}.".format(thread_name, org_name)
    def log(self):
        LOGGER.error(f'{self.message} : {self.org}')