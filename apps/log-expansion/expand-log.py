# IRON: iron_headers
#
# Distribution A
#
# Approved for Public Release, Distribution Unlimited
#
# EdgeCT (IRON) Software Contract No.: HR0011-15-C-0097
# DCOMP (GNAT)  Software Contract No.: HR0011-17-C-0050
# Copyright (c) 2015-20 Raytheon BBN Technologies Corp.
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contracts No. HR0011-15-C-0097 and
# HR0011-17-C-0050. Any opinions, findings and conclusions or
# recommendations expressed in this material are those of the author(s)
# and do not necessarily reflect the views of the Defense Advanced
# Research Project Agency.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# IRON: end

"""
Expand binary log files.
"""
from __future__ import print_function

import argparse
import codecs
from collections import namedtuple
import re
from struct import calcsize, unpack

DEFAULT_EXPAND_EXT = ".txt"
IDENTIFICATION_HEADER = "IRON COMPRESSED LOG"


class InvalidFileException(Exception):
    def __init__(self, filename):
        Exception.__init__(self,
                           "{} is not a compressed log file.".format(filename))

LogRecord = namedtuple("LogRecord", ["format", "arg_types"])


# global set when parsing command line arguments
QUIET = False


def print_debug(msg, *format_args):
    """Print when not in quiet mode. Supports string formatting."""
    if not QUIET:
        print(msg.format(*format_args))


def print_error(msg, *format_args):
    """Print an error message. Supports string formatting."""
    print("ERROR: " + msg.format(*format_args))


class Unpack(object):
    _FORMAT = "="  # native byte order, standard sizes, no alignment
    CHAR = _FORMAT + "c"
    SCHAR = _FORMAT + "b"
    UCHAR = _FORMAT + "B"
    SHORT = _FORMAT + "h"
    USHORT = _FORMAT + "H"
    INT = _FORMAT + "i"
    UINT = _FORMAT + "I"
    LONG = _FORMAT + "q"
    ULONG = _FORMAT + "Q"
    FLOAT = _FORMAT + "f"
    DOUBLE = _FORMAT + "d"
    UINT_32 = UINT
    _STRING_FMT = _FORMAT + "{}s"

    @classmethod
    def string(cls, length):
        return cls._STRING_FMT.format(length)


def read(read_from, unpack_fmt):
    """
    Read a value from a file.

    :param file read_from: File to read from.
    :param string unpack_fmt: Unpack format string specifying what to read.
    Unpack format strings that specify multiple values are not supported.
    :returns: Value read from file.
    :raises EOFError: File did not contain enough bytes to read requested value.
    """
    size = calcsize(unpack_fmt)
    buff = read_from.read(size)
    if buff == "":
        raise EOFError("Reached end of file while trying to read "
                       "'{}' ({} bytes)".format(unpack_fmt, size))
    while len(buff) != size:
        read_buff = read_from.read(size - len(buff))
        if read_buff == "":
            raise EOFError("Reached end of file while trying to read "
                           "'{}' ({} bytes read)".format(unpack_fmt, len(buff)))
        buff += read_buff
    return unpack(unpack_fmt, buff)[0]


def read_string(read_from, length, name=None, nul_byte_check=True):
    """
    Read an ASCII encoded string from a file.

    :param file read_from: File to read from.
    :param int length: Number characters to be read.
    :param string name: Name describing string being read for use in error
    message. If `None`, the error message will not specify what was being read.
    :param bool nul_byte_check: `True` if the string should be checked for a NUL
    byte at the end.
    :returns string: String that was read from file.
    :raises EOFError: File did not contain enough bytes to read requested string
    length.
    """
    the_bytes = read(read_from, Unpack.string(length))
    if nul_byte_check:
        if the_bytes[-1] == '\0':
            the_bytes = the_bytes[:-1]
        else:
            if name is None:
                name = "String"
            print_debug("{} ending at byte {} does not have a trailing NUL "
                        "byte. Allowing for now.", name, read_from.tell())

    return codecs.decode(the_bytes, "ascii")


def read_uint32(read_from):
    """
    Read a 32 bit unsigned integer from a file.

    :param file read_from: File to read from.
    :returns int: Integer that was read from file.
    :raises EOFError: File did not contain enough bytes to read requested value.
    """
    return read(read_from, Unpack.UINT_32)


class ParseType(object):
    """Type that can be parsed from the compressed log file"""
    def __init__(self, name, unpack_formats):
        """
        Initialize an instance.

        :param string name: Name of the type.
        :param dict[int, string]|None unpack_formats: Mapping of
        valid lengths to unpack format string. If `None`, all lengths are valid
        and `_read_value()` must be overridden.
        """
        self.name = name
        self._unpack_formats = unpack_formats

    def read_value(self, read_from, arg_len, fmt):
        """
        Validate that the length of an argument.

        :param file read_from: File to read from.
        :param int arg_len: Length of argument read from the file.
        :param string fmt: Format string argument is associated with.
        :raises ValueError: `arg_len` is not valid and a default is not
        possible.
        """
        self._validate(arg_len, fmt)
        return self._read_value(read_from, arg_len)

    def _validate(self, arg_len, fmt):
        """
        Validate that the length of an argument.

        :param int arg_len: Length of argument read from the file.
        :param string fmt: Format string argument is associated with.
        :raises ValueError: `arg_len` is not valid and a default is not
        possible.
        """
        if self._unpack_formats is None or arg_len in self._unpack_formats:
            return
        valid_lengths = self._unpack_formats.values()
        if len(valid_lengths) == 1:
            pluralize = "s" if valid_lengths[0] > 1 else ""
            print_error("{0} should be {1} byte{2}, was {3}. Assuming {1} "
                        "byte{2} for '{4}'", self.name,
                        valid_lengths[0], pluralize, arg_len, fmt)
        else:
            values = ", ".join(str(x) for x in valid_lengths[:-1])
            values += " or " + str(valid_lengths[-1])
            msg = "{} must have a length of {}, was {} for '{}'."
            raise ValueError(msg.format(self.name, values, arg_len, fmt))

    def _read_value(self, read_from, arg_len):
        """
        Read a value from the given file.

        :param file read_from: File to read from.
        :param int arg_len: Length of argument read from the file.
        :returns: Value read from file.
        """
        if self._unpack_formats is None:
            raise NotImplementedError("_read_value() must be overridden when "
                                      "unpack_formats is set to None")
        return read(read_from, self._unpack_formats[arg_len])


class String(ParseType):
    def __init__(self):
        ParseType.__init__(self, "String", None)

    def _read_value(self, read_from, arg_len):
        return read_string(read_from, arg_len)

CHAR = ParseType("Char", {1: Unpack.CHAR})
INT = ParseType("Int", {1: Unpack.SCHAR, 2: Unpack.SHORT, 4: Unpack.INT,
                        8: Unpack.LONG})
UINT = ParseType("UInt", {1: Unpack.UCHAR, 2: Unpack.USHORT, 4: Unpack.UINT,
                          8: Unpack.ULONG})
FLOAT = ParseType("Float", {4: Unpack.FLOAT, 8: Unpack.DOUBLE})

TYPE_CONVERSION_MAP = {
        "c": CHAR,
        "s": String(),
        "d": INT,
        "i": INT,
        "o": UINT,
        "x": UINT,
        "X": UINT,
        "u": UINT,
        "f": FLOAT,
        "F": FLOAT,
        "e": FLOAT,
        "E": FLOAT,
        "a": FLOAT,
        "A": FLOAT,
        "g": FLOAT,
        "G": FLOAT,
        "p": INT,
    }

_INTEGER_FMT_OPTION = r"(?<![^%]%)" \
                      r"(%[+\- #0]?" \
                      r"(\d+?|\*)?" \
                      r"(\.(\d+?|\*)?)?)" \
                      r"([hl]{1,2}|[jzt])([dioxXu])"
_POINTER_FMT_OPTION = r"(?<![^%]%)" \
                      r"(%[+\- #0]?" \
                      r"(\d+?|\*)?" \
                      r"(\.(\d+?|\*)?)?)p"


def parse_format(fmt):
    """
    Parse a format string for the types of the arguments.

    Python does not support the "%p" format specifier. If "%p" is present in
    `fmt`, the format string will be altered to a type that Python supports.

    :param string fmt: Format string to parse.
    :returns list[ParseType], string: Conversion types for format arguments,
    Corrected format string.
    """
    # This is a simplified implementation of format string parsing.
    # It does NOT validate format string. It only matches the conversion
    # specifiers. Things like extra length modifiers, stray % characters with
    # no matching conversion specifier, etc will break this and lead to
    # unspecified behavior.
    arg_types = []
    percent_found = False

    for curr in fmt:
        if percent_found:
            if curr == "%":
                percent_found = False
                continue

            arg_type = TYPE_CONVERSION_MAP.get(curr)
            if arg_type is not None:
                arg_types.append(arg_type)
                percent_found = False
        elif curr == '%':
            percent_found = True

    # strip length modifiers from integer format patterns
    fmt = re.sub(_INTEGER_FMT_OPTION, r"\1\6", fmt)
    # replace pointer conversion with hex formatted integer
    p_match = re.search(_POINTER_FMT_OPTION, fmt)
    if p_match is not None:
        if any(p_match.groups()[1:]):
            # use existing options
            replace = r"\1x"
        else:
            replace = "0x%06x"
        fmt = re.sub(_POINTER_FMT_OPTION, replace, fmt)

    return arg_types, fmt


class LogExpansion(object):

    def __init__(self, source_path, dest_path):
        self._source_path = source_path
        self._dest_path = dest_path
        self._source = None
        self._dest = None
        self._formats = {}

    def __enter__(self):
        self._source = open(self._source_path, "rb")
        try:
            header = read_string(self._source, len(IDENTIFICATION_HEADER),
                                 nul_byte_check=False)
            if header != IDENTIFICATION_HEADER:
                raise InvalidFileException(self._source_path)
        except EOFError:
            raise InvalidFileException(self._source_path)

        self._dest = open(self._dest_path, mode="w")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._source.close()
        if self._dest is not None:
            self._dest.close()

    def expand(self):
        while True:
            record = self._read_record()
            if record is None:
                break
            if len(record.arg_types) == 0:
                self._dest.write(record.format)
                continue

            args = []
            for i, arg_type in enumerate(record.arg_types):
                try:
                    arg_len = read_uint32(self._source)
                except EOFError as ex:
                    print_error("Reached end of file while attempting to read"
                                "{} argument length for '{}': {}",
                                number_ordinal(i), record.format,
                                ex)
                    return
                try:
                    value = arg_type.read_value(self._source, arg_len,
                                                record.format)
                except EOFError as ex:
                    print_error("Reached end of file while attempting to read"
                                "{} ({} argument for '{}'): {}",
                                arg_type.name, number_ordinal(i), record.format,
                                ex)
                    return
                args.append(value)

            try:
                self._dest.write(record.format % tuple(args))
            except ValueError as ex:
                print_error("Failed to format '{}' with args ({}): {}",
                            record.format, args, ex)
            except TypeError as ex:
                print_error("Failed to format '{}' with args ({}): {}",
                            record.format, args, ex)

    def _read_record(self):
        try:
            fmt_id = read_uint32(self._source)
        except EOFError:
            return None
        record = self._formats.get(fmt_id)
        if record is None:
            try:
                fmt_len = read_uint32(self._source)
            except EOFError as ex:
                print_error("Reached end of file while attempting to read "
                            "the length of log record {}'s format string: {}",
                            fmt_id, ex)
                return None
            try:
                fmt = read_string(self._source, fmt_len, "Format string")
            except EOFError as ex:
                print_error("Reached end of file while attempting to read "
                            "log record {}'s format string: {}",
                            fmt_id, ex)
                return None
            try:
                arg_count = read_uint32(self._source)
            except EOFError as ex:
                print_error("Reached end of file while attempting to read "
                            "log record {}'s argument count: {}",
                            fmt_id, ex)
                return None
            arg_types, fmt = parse_format(fmt)
            if len(arg_types) != arg_count:
                print_error("Log record {} claims to have more arguments than "
                            "were found in the format string. "
                            "Expected {} Found {}", fmt_id, arg_count,
                            len(arg_types))
            record = LogRecord(fmt, arg_types)
            self._formats[fmt_id] = record
        return record


def number_ordinal(n):
    if 4 <= n % 100 <= 20:
        # special handling for teens
        suffix = "th"
    else:
        ones_digit = n % 10
        if ones_digit == 1:
            suffix = "st"
        elif ones_digit == 2:
            suffix = "nd"
        elif ones_digit == 1:
            suffix = "rd"
        else:
            suffix = "th"
    return str(n) + suffix


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--extension", dest="ext",
                        default=DEFAULT_EXPAND_EXT,
                        help="file extension added to file name")
    parser.add_argument("files", nargs="+", metavar="FILE",
                        help="file to expand into a text file")

    args = parser.parse_args()

    for to_expand in args.files:
        output_file = to_expand + args.ext
        try:
            with LogExpansion(to_expand, output_file) as logex:
                print("Expanding", to_expand)
                logex.expand()
        except InvalidFileException as ex:
            print_error(str(ex))

if __name__ == '__main__':
    main()
