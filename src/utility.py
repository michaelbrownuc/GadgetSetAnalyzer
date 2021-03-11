"""
Gadget Set Analyzer Utility Library
This common utility library contains generally useful system functions that are frequently used by GSA.
"""

# Standard Library Imports
from datetime import datetime
import os

# Third Party Imports

# Local Imports


def create_output_directory(prefix, timestamp=True):
    """
    Create a subdirectory in the current directory for output like logs, fuzzing results, etc.

    :param str prefix: String to prefix to the timestamp on the directory label
    :param bool timestamp: Whether or not to timstamp the directory.
    :return: Name of the directory created by the system
    :rtype: str
    :raises: OSError if an error occurs during directory creation.
    """
    if timestamp:
        directory_name = prefix + str(datetime.now())
    else:
        directory_name = prefix
    os.makedirs(directory_name)
    return directory_name
