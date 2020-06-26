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
Validate the experiment configuration.
"""

from __future__ import print_function
import argparse
from collections import defaultdict
from os import path
import re

from iron.util.file_reader import FileReader

DEFAULT_FILE_GLOB = "*"
DEFAULT_HANDLE_ALL_LINES = False
DEFAULT_STRIP_WHITESPACE = True
DEFAULT_STAGE_DIR = path.join("~", "iron_exp_staging")
CONFIG_DIRNAME = "cfgs"
CONFIG_GLOB = "*.cfg"

# global set when parsing command line arguments
QUIET = False


def print_debug(msg, *format_args):
    """Print when not in quiet mode. Supports string formatting."""
    if not QUIET:
        print(msg.format(*format_args))


class Validator(object):
    def __init__(self, experiment_dir, config_dir, reader=None):
        self._issue_count = 0
        self._experiment_dir = experiment_dir
        self._config_dir = config_dir
        self.reader = FileReader() if reader is None else reader

    @property
    def issue_count(self):
        return self._issue_count

    def _incr_issue_count(self):
        self._issue_count += 1


class ParamSubstitution(Validator):
    """Validate that parameter substitution is done correctly."""
    PARAM_FILENAME = "params.txt"
    REGEX = ".+?(%.+?%).*?"

    def __init__(self, experiment_dir, config_dir):
        super(ParamSubstitution, self).__init__(experiment_dir, config_dir)
        self._param_file_path = path.join(config_dir,
                                          ParamSubstitution.PARAM_FILENAME)

    def validate(self):
        print_debug("Checking for {}.".format(self._param_file_path))
        if path.exists(self._param_file_path):
            self._validate_substitutions()
        else:
            self._validate_no_substitution()

    def _validate_no_substitution(self):
        # The substitution logic is broad enough that it treats any line with
        # two percent signs as a replacement, so matching logic can be simple
        def no_substitution(fileline):
            if fileline.line.count("%") > 1:
                self._incr_issue_count()
                fileline.log_issue("Substitution found when no {} "
                                   "file exists",
                                   ParamSubstitution.PARAM_FILENAME)

        print_debug("Param file not found. Checking no substitutions are"
                    " attempted.")
        self.reader.scan_files(self._config_dir, no_substitution, CONFIG_GLOB)

    # TODO: Use same logic as generate_exp_run_cfg
    def _load_tags(self):
        """
        Parse the parameter substitution information.

        Returns tags found in parameter file.

        Raises BadTagError if any substitution tags are repeated.
        Raises FileFormatError if the parameter file could not be parsed.
        """
        scope = {"tags": set(), "value_count": None}

        def parse_tag(fileline):
            # Expected Line Format
            # TAG = VAL1 VAL2 ... VALn
            values = fileline.line.split("=")
            if len(values) != 2:
                self._incr_issue_count()
                fileline.log_issue("Line did not contain an '='. "
                                   "May cause later issues.")

            tag, values = values
            tag = tag.strip()
            if tag in scope["tags"]:
                self._incr_issue_count()
                fileline.log_issue("Repeated substitution tag '{}'", tag)
            scope["tags"].add(tag)

            values = values.split()
            value_count = len(values)
            if scope["value_count"] is None:
                scope["value_count"] = value_count
            elif scope["value_count"] != value_count:
                self._incr_issue_count()
                msg = "The substitute tag {} has {} values, {} expected."
                fileline.log_issue(msg, tag, value_count, scope["value_count"])

        self.reader.scan_file(self._param_file_path, parse_tag)
        if len(scope["tags"]) == 0:
            self._incr_issue_count()
            print("{} exists, "
                  "but does not define any tags.".format(self._param_file_path))
        return scope["tags"]

    def _validate_substitutions(self):
        print_debug("Checking no substitutions are correct.")
        total_tags_used = set()
        tags_used_by_file = defaultdict(set)
        tags = self._load_tags()

        def correct_substitutions(fileline):
            # doing look-up now ensures that each file's set is created
            tags_used_by_this_file = tags_used_by_file[fileline.filename]
            matches = re.findall(ParamSubstitution.REGEX, fileline.line)
            for match in matches:
                tag_to_substitute = match.strip("%")
                if tag_to_substitute not in tags:
                    self._incr_issue_count()
                    fileline.log_issue("Tag '{}' not present in parameter"
                                       "substitution information",
                                       tag_to_substitute)
                else:
                    tags_used_by_this_file.add(tag_to_substitute)
                    total_tags_used.add(tag_to_substitute)

        self.reader.scan_files(self._config_dir, correct_substitutions,
                               CONFIG_GLOB)

        if len(tags) != len(total_tags_used):
            self._incr_issue_count()
            if len(total_tags_used) == 0:
                print("None of the config files in {} used any of the tags"
                      " defined in {}".format(self._config_dir,
                                              self._param_file_path))
            else:
                print("None of the config files in {} used the following tags: "
                      "{}".format(self._config_dir, tags - total_tags_used))

        # TODO: decide if this is a check worth doing.
        # don't check every file if we know no tags were ever used
        if len(total_tags_used) != 0:
            for filename, tags_used in tags_used_by_file.items():
                if len(tags) != len(tags_used):
                    self._incr_issue_count()
                    if len(tags_used) == 0:
                        print("{} did not use any of the tags defined in "
                              "{}.".format(filename, self._param_file_path))
                    else:
                        print("{} did not use the following tags: "
                              "{}".format(filename, tags - tags_used))


class UdpProxy(Validator):
    """Validate upd proxy is configured correctly."""
    FILE_GLOB = "udp_proxy_*.cfg"
    REQUIRED_SERVICE_SETTING_COUNT = 7
    MAX_SETTING_COUNT = REQUIRED_SERVICE_SETTING_COUNT + 2
    MAX_PORT = 65535
    MAX_FEC_RATE = 32
    MAX_CHUNK_SIZE = 65535
    MAX_DSCP = 63

    def __init__(self, experiment_dir, config_dir):
        super(UdpProxy, self).__init__(experiment_dir, config_dir)

    def validate(self):
        # TODO: support more than just service definition
        def correct_config(fileline):
            # Expected Line Format
            # ServiceX loPort-hiPort;baseRate/totrate;maxChunkSz;
            #   maxHoldTimeMsecs;orderFlag;timeout;timeToGo
            #   [;utilityFunction[;dscp=VALUE]]
            match = re.match("(Service(\d|1[0-5])|defaultService)\s(.+)",
                             fileline.line)
            if match is None:
                return

            settings = match.group(3).split(";")
            if (len(settings) < UdpProxy.REQUIRED_SERVICE_SETTING_COUNT or
                    len(settings) > UdpProxy.MAX_SETTING_COUNT):
                self._incr_issue_count()
                fileline.log_issue("Had {} values, [{},{}] expected",
                                   len(settings),
                                   UdpProxy.REQUIRED_SERVICE_SETTING_COUNT,
                                   UdpProxy.MAX_SETTING_COUNT)
                return

            if len(settings) == UdpProxy.REQUIRED_SERVICE_SETTING_COUNT:
                print_debug("Experiment will use default utility definition.")

            self._validate_port(fileline, settings[0])
            self._validate_rate(fileline, settings[1])

            self._extract_int_range(fileline, settings[2], "maxChunkSz",
                                    UdpProxy.MAX_CHUNK_SIZE, min_value=1)

            self._extract_int_range(fileline, settings[3], "maxHoldTimeMsecs",
                                    min_value=0)

            self._extract_int(fileline, settings[4], "orderFlag")
            self._extract_int(fileline, settings[5], "timeout")
            self._extract_int(fileline, settings[6], "timeToGo",
                              extra_msg=". If values is utility definition,"
                                        "timeToGo field was likely omitted.")

            if len(settings) > UdpProxy.REQUIRED_SERVICE_SETTING_COUNT:
                if settings[7] == "":
                    self._incr_issue_count()
                    fileline.log_issue("Utility definition can't be empty.")
            if (len(settings) == UdpProxy.MAX_SETTING_COUNT and
                    settings[8] != ""):
                if not settings[8].startswith("dscp="):
                    self._incr_issue_count()
                    fileline.log_issue("Unsupported dscp setting '{}'.",
                                       settings[8])
                    return

                dscp = settings[8].replace("dscp=", "", 1)
                self._extract_int_range(fileline, dscp, "dscp",
                                        UdpProxy.MAX_DSCP)

        self.reader.scan_files(self._config_dir, correct_config,
                               UdpProxy.FILE_GLOB)

    def _validate_port(self, fileline, ports):
        ports = ports.split("-")
        if len(ports) != 2:
            self._incr_issue_count()
            fileline.log_issue("Port range had {} values, {} expected",
                               len(ports), 2)
            return

        lo_port = self._extract_int_range(fileline, ports[0], "loPort",
                                          UdpProxy.MAX_PORT)
        hi_port = self._extract_int_range(fileline, ports[1], "lhiPort",
                                          UdpProxy.MAX_PORT)

        if lo_port is not None and hi_port is not None and \
                lo_port > hi_port:
            self._incr_issue_count()
            fileline.log_issue("loPort must not be larger than hiPort")

    def _validate_rate(self, fileline, rates):
        rates = rates.split("/")
        if len(rates) != 2:
            self._incr_issue_count()
            fileline.log_issue("Coding rate had {} values, {} expected",
                               len(rates), 2)
            return

        base_rate = self._extract_int_range(fileline, rates[0], "baseRate",
                                            UdpProxy.MAX_FEC_RATE)
        tot_rate = self._extract_int_range(fileline, rates[1], "totRate",
                                           UdpProxy.MAX_FEC_RATE)

        if base_rate is not None and tot_rate is not None:
            if base_rate > tot_rate:
                self._incr_issue_count()
                fileline.log_issue("baseRate must not be larger than totRate.")
            if tot_rate - base_rate > UdpProxy.MAX_FEC_RATE:
                self._incr_issue_count()
                fileline.log_issue("totRate must not be larger than the max "
                                   "rate plus baseRate.")

    def _extract_int_range(self, fileline, text, name, max_value=None,
                           min_value=0, extra_msg=""):
        value = self._extract_int(fileline, text, name, extra_msg)
        if value is not None:
            if ((max_value is None and min_value <= value) or
                    (max_value is not None and
                     min_value <= value <= max_value)):
                return value
            else:
                self._incr_issue_count()
                fileline.log_issue("{} value '{}' is not in the "
                                   "allowed range [{},{}]", name, value,
                                   min_value, max_value)
        return None

    def _extract_int(self, fileline, text, name, extra_msg=""):
        try:
            return int(text)
        except ValueError:
            self._incr_issue_count()
            fileline.log_issue("{} value '{}' is not an integer{}",
                               name, text, extra_msg)
        return None

ALL_VALIDATORS = [ParamSubstitution, UdpProxy]


def main():
    global QUIET
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", action="store_true", dest="quiet",
                        default=False,
                        help="Only output text if there is an issue.")
    parser.add_argument("--stage_dir", default=DEFAULT_STAGE_DIR,
                        help="Directory containing staged experiment(s).")
    parser.add_argument("experiments", nargs="+", metavar="experiment",
                        help="Name(s) of experiment(s) to validate.")

    args = parser.parse_args()
    QUIET = args.quiet

    stage_dir = path.expanduser(args.stage_dir)

    total_issues = 0
    for experiment in args.experiments:
        print_debug("Validating experiment {}.".format(experiment))
        experiment_dir = path.join(stage_dir, experiment)
        if not path.exists(experiment_dir):
            total_issues += 1
            print("Experiment directory '{}' does not "
                  "exists".format(args.staged_directory))
            continue

        config_dir = path.join(experiment_dir, CONFIG_DIRNAME)

        for validator_cls in ALL_VALIDATORS:
            validator = validator_cls(experiment_dir, config_dir)
            print_debug(validator.__doc__)
            validator.validate()
            total_issues += validator.issue_count

        print_debug("")

    if total_issues != 0:
        print(" -- {} issues detected --".format(total_issues))

    return total_issues

if __name__ == "__main__":
    exit(main())
