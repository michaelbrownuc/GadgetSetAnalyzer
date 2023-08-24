"""
Gadget Set Analyzer Utility Library
This common utility library contains generally useful system functions that are frequently used by GSA.
"""

# Standard Library Imports
from datetime import datetime
import os

# Third Party Imports
from numpy import format_float_positional

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

def fmt_percent_keep_nonzero(num, digits):
    """
    Format a number to be a percent, following the rounding rules of fmt_round_keep_nonzero 
    :param float num: Number to format
    :param int digits: Number of digits in the percent to keep (will keep n+2 of original number)
    :rtype str
    """
    num *= 100
    formatted = fmt_round_keep_nonzero(num, digits)
    return f"{formatted}%"

def fmt_round_keep_nonzero(num, digits):
    """
    Round a number to n decimal places. If rounding would make a nonzero number zero,
    round to keep n significant digits

    :param float num: Number to format
    :param int digits: Number of nonzero decimal digits to keep
    :rtype str
    """
    rounded = round(num, digits)
    if rounded != 0 or num == 0:
        return "{:.2f}".format(num)
    else:
        return to_significant_digits(num, digits)

def to_significant_digits(float_num, digits):
    """
    Format a float to the number of significant digits
    
    :param float float_num: Floating point number to convert
    :param int digits: Number of significant digits to keep
    :rtype: str
    """
    return format_float_positional(float_num, precision=digits, trim='k', unique=False, fractional=False)
