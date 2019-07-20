"""
Debloater Utility Library
This common utility library contains generally useful system functions that are frequently used by the debloater script.
"""

# Standard Library Imports
from datetime import datetime
import os

# Third Party Imports

# Local Imports


def flatten_dict(dictionary):
    """
    Utility Function: flatten_dict
    Used to (potentially recursively) flatten the input dictionary into a list of strings containing all of the keys and
    values present in the input dictionary.
    """

    flat_list = list()

    for key in dictionary.keys():
        flat_list.append(key)
        value = dictionary.get(key)
        if type(value) is list:
            flat_list.extend(value)
        if type(value) is dict:
            flat_list.extend(flatten_dict(value))

    return flat_list


def search_hierarchy(target, hierarchy):
    """
    Utility Function: search_hierarchy
    Searches the (potentially nested) dictionary hierarchy for the string target.  If the target is not found, an
    exception is raised.  If the target is found and it is an index to a list of values, the list of values is returned.
    If the target is found and is an index into a subhierachy, search hierarchy is recursively flattened and returned.

    Ultimately, a call to this function returns a list of all the intermediate nodes and leaf nodes in the hierarchy
    under the target.
    """

    found = list()

    if type(hierarchy) is not dict:
        raise Exception("Hierarchy is not a dictionary.")

    for key in hierarchy.keys():
        item = hierarchy.get(key)

        if key == target:
            if type(item) is list:
                found.extend(item)
                break
            elif type(item) is dict:
                found.extend(flatten_dict(item))
                break
        else:
            if type(item) is dict:
                found.extend(search_hierarchy(target, item))
            elif type(item) is list and target in item:
                found.append(target)
                break

    return found


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


def get_final_subfolder(filepath):
    """
    Takes a filepath string and removes the final subfolder in the filepath and returns it.
    :param str filepath: String filepath to search for the final subfolder
    :return: A string with the final subfolder only
    """
    split_string = filepath.split(os.sep)
    last_index = len(split_string)-1
    if split_string[last_index] == '':
        return split_string[last_index-1]
    else:
        return split_string[last_index]


def get_extension(filename):
    """
    Returns the extension of the filename passed, if it exists.
    :param str filename: Name of the file to find the extension of
    :return: A string containing the extension (no '.' character)
    """
    split_string = filename.split(".")
    last_index = len(split_string)-1
    return split_string[last_index]