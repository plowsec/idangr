# Configure logging
import logging

fmt = '%(asctime)s | %(levelname)3s | [%(filename)s:%(lineno)3d] %(funcName)s() | %(message)s'
datefmt = '%Y-%m-%d %H:%M:%S'  # Date format without milliseconds


class CustomFormatter(logging.Formatter):
    COLOR_CODES = {
        'DEBUG': '\033[36m',  # Cyan
        'INFO': '\033[35m',  # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',  # Red
        'CRITICAL': '\033[41m',  # Red background
        'RESET': '\033[0m'  # Reset to default
    }

    def format(self, record):
        color_code = self.COLOR_CODES.get(record.levelname, self.COLOR_CODES['RESET'])
        record.msg = f"{color_code}{record.msg}{self.COLOR_CODES['RESET']}"
        return super().format(record)


logger = logging.getLogger(__name__)
logger.propagate = False  # Prevent log messages from being passed to the root logger

# Create and add the stream handler
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(CustomFormatter(fmt, datefmt))
logger.addHandler(stream_handler)

# Add a file handler to the logger
file_handler = logging.FileHandler('../logfile.log')
file_handler.setFormatter(CustomFormatter(fmt, datefmt))
logger.addHandler(file_handler)

logger.setLevel(logging.DEBUG)