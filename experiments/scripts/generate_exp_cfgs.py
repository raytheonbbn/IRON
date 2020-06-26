#!/usr/bin/env python

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

# A script to generate IRON configuration files for an experiment from
# templated experiment configuration files. The templated
# configuration files describe experiment aspects using "notional
# enclave" terminology. The "notional enclave" information is mapped to
# real physical enclave information, which is then used to extract the
# relevant information from the testbed topology file.

import argparse
import glob
import os
from os import path
import re
import sys

# Remembers if we are enabling low level diagnostic log messages.
debug_mode = False

#=============================================================================
def errmsg(msg):
    """
    Print an error message string to stderr.
    """
    print >> sys.stderr, msg

#=============================================================================
def log(msg, *format_args):
    """
    Log a diagnostic message when not in quiet mode. Supports string
    formatting.
    """
    global debug_mode

    if debug_mode:
        print(msg.format(*format_args))

#=============================================================================
def compute_subnet(ip_str, prefix):
    """
    Compute a subnet address from the provided IP Address and prefix length.
    """
    if (int(prefix) == 0):
        sub_mask = 0
    else:
        sub_mask = 0xFFFFFFFF << (32 - int(prefix))

    ip_str_parts = ip_str.split(".")
    ip_addr = (int(ip_str_parts[0]) << 24) + (int(ip_str_parts[1]) << 16) + \
              (int(ip_str_parts[2]) << 8) + (int(ip_str_parts[3]))
    subnet = ip_addr & sub_mask
    subnet_str = '.'.join([str(subnet >> (j << 3) & 0xFF) \
                           for j in range(4)[::-1]])
    subnet_str = "%s/%s" % (subnet_str, prefix)

    return subnet_str

#=============================================================================
def process_enclave_map_file(enclave_map_fn, phy_enclave_map, enclave_map,
                             enclave_info, node_map, out_dir):
    """
    Process the enclave mapping file.
    """

    # Extract the enclaves that are being used and generate the
    # appropriate generic node ids and link ids for the enclave's
    # components (application node, iron node, link emulator nodes).
    if (not path.exists(enclave_map_fn)):
        log("Enclave mapping file {} does not exist. Aborting... "
            .format(enclave_map_fn))
        return(False)

    log("Extracting information from enclave mapping file {}...".
        format(enclave_map_fn))

    in_file = open(enclave_map_fn, 'r')

    nodes_per_enclave = (enclave_info['app_nodes_per_enclave'] +
                         enclave_info['le_nodes_per_enclave'] + 1)
    links_per_enclave = (enclave_info['app_nodes_per_enclave'] +
                         (enclave_info['le_nodes_per_enclave'] * 2))

    for line in in_file.readlines():
        # Only process lines that are not comment lines, not blank
        # lines, and lines that start with ENCLAVES.
        if ((not line.startswith("#")) and (not line == "\n")
            and (line.startswith("ENCLAVES="))):
            enclaves = line.rsplit("=")[1].strip('()\n').split(" ")
            enclave_cnt = 1

            out_fn = os.path.join(out_dir, "node_to_enclave_map.txt")
            out_file = open(out_fn, "w")

            # Add the generic node and generic link identifiers for
            # each of the experiment enclaves. We also populate the
            # "notional" to "physical" enclave map.
            for enclave in enclaves:
                enclave_id = int(enclave)
                phy_enclave_map[str(enclave_cnt)] = enclave
                enclave_cnt = enclave_cnt + 1

                if enclave not in enclave_map:
                    enclave_map[enclave] = {}

                # Add the app node information. Note that there may be
                # more than 1 app node.
                for i in range(1, enclave_info['app_nodes_per_enclave'] + 1):
                    enclave_map[enclave]['app%d_node' % i] = (
                        'node' + str(((enclave_id - 1) *
                                      nodes_per_enclave) + i))
                    enclave_map[enclave]['app%d_wan_link' % i] = (
                        'link' + str(((enclave_id - 1) *
                                      links_per_enclave) + i))

                # Add the IRON node information. Note there is always
                # only 1 IRON node. The IRON WAN link information is
                # LinkEm dependent (depends on the number of LinkEm
                # nodes), so will be done when we add the LinkEm
                # information.
                enclave_map[enclave]['iron_node'] = (
                    'node' + str(((enclave_id - 1) * nodes_per_enclave)
                                 + enclave_info['app_nodes_per_enclave'] + 1))
                enclave_map[enclave]['iron_lan_link'] = (
                    'link' + str(((enclave_id - 1) * links_per_enclave) + 1))

                # Add the LinkEm node information. Note that up to 2
                # LinkEm nodes are supported.
                for i in range(1, enclave_info['le_nodes_per_enclave'] + 1):
                    enclave_map[enclave]['le%d_node' % i] = (
                        'node' + str(((enclave_id - 1) * nodes_per_enclave) +
                                     i + enclave_info['app_nodes_per_enclave']
                                     + 1))
                    enclave_map[enclave]['le%d_lan_link' % i] = (
                        'link' + str(((enclave_id - 1) *
                                      links_per_enclave) +
                                     enclave_info['app_nodes_per_enclave'] +
                                     ((i - 1) * 2) + 1))
                    enclave_map[enclave]['le%d_wan_link' % i] = (
                        'link' + str(((enclave_id - 1) *
                                      links_per_enclave) +
                                     enclave_info['app_nodes_per_enclave'] +
                                     ((i - 1) * 2) + 2))

                    enclave_map[enclave]['iron_wan%d_link' % i] = (
                        'link' + str(((enclave_id - 1) *
                                      links_per_enclave) +
                                     enclave_info['app_nodes_per_enclave'] +
                                     (i - 1) * 2 + 1))

                if (enclave_info['le_nodes_per_enclave'] == 0):
                    enclave_map[enclave]['iron_wan1_link'] = (
                        'link' + str(((enclave_id - 1) *
                                      links_per_enclave) +
                                     enclave_info['app_nodes_per_enclave'] +
                                     + 1))

                # Generate the node_to_enclave_map.txt file. This file
                # contains lines that map generic node id from the
                # testbed topology file to physical hostnames and the
                # directory that the experiment results should be
                # place in for the generic node id. Following is an
                # example:
                #
                #   node1 gnat-app1 enclave1/app1
                enclave_map_keys = enclave_map[enclave].keys()
                enclave_map_keys.sort()
                for key in enclave_map_keys:
                    if "node" in key:
                        for key2 in phy_enclave_map.keys():
                            if phy_enclave_map[key2] == enclave:
                                gen_node = enclave_map[enclave][key]
                                host     = node_map[gen_node]['host']
                                out_file.write("%s %s enclave%s/%s\n" % \
                                               (gen_node, host, key2,
                                                key.split("_")[0]))

    # Close the input file.
    in_file.close()

    # Close the output file.
    out_file.close()

    log("Enclave Map: {}", enclave_map)
    log("Physical Enclave Map: {}", phy_enclave_map)

    return(True)

#=============================================================================
def process_testbed_file(testbed_fn, node_map, enclave_info):
    # Extract the information from the testbed topology file.
    if (not path.exists(testbed_fn)):
        log("Testbed file {} does not exist. Aborting... "
            .format(testbed_fn))
        return(False)

    log("Extracting information from Testbed file {}...", testbed_fn)

    f = open(testbed_fn, 'r')

    found_app_nodes_per_enclave = False
    found_le_nodes_per_enclave = False

    for line in f.readlines():
        # Skip comments and blank lines.
        if not line.startswith("#") and not line == "\n":
            if line.startswith("app_nodes_per_enclave"):
                enclave_info['app_nodes_per_enclave'] = \
                    int(line.split(" ")[1])
                found_app_nodes_per_enclave = True
            elif line.startswith("le_nodes_per_enclave"):
                enclave_info['le_nodes_per_enclave'] = \
                    int(line.split(" ")[1])
                found_le_nodes_per_enclave = True
            elif line.startswith("node"):
                (key, value) = line.split(" ", 1)
                (host, links) = value.strip().split(" ")
                node_map[key] = {}
                node_map[key]['host'] = host
                link_list = links.split(",")
                for link in link_list:
                    (link_key, link_val) = link.split("=")
                    node_map[key][link_key] = link_val

    # Close the file.
    f.close()

    if (not found_app_nodes_per_enclave):
        errmsg("Must provide app_nodes_per_enclave in testbed topology file.")
        return(False)

    if (not found_le_nodes_per_enclave):
        errmsg("Must provide le_nodes_per_enclave in testbed topology file.")
        return(False)

    if (enclave_info['le_nodes_per_enclave'] > 2):
        errmsg("LinkEm count of %d unsupported." %
               enclave_info['le_nodes_per_enclave'])
        return(False)

    log("Node Map: {}", node_map)

    return(True)

#=============================================================================
def substitute_app_node_info(line, phy_enclave_map, enclave_map, node_map):
    # The enclave application node identifier regular expression of
    # interest. We are interested in finding strings that have the
    # following format in the configuration file templates:
    #
    #   $enclaveX_appY_node$
    #
    # where X is the enclave identifier and Y is the application
    # identifier.
    #
    # All instances of this string will be replaced with the generic
    # node identifier for the application node Y of enclave X,
    # extracted from the testbed topology file.
    app_node_regex = re.compile(
        '.*?([$]enclave[\d]+_app[\d]+_node[$]).*?')

    matches = app_node_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]
            app_id = tag.split("_")[1][3:]

            line = line.replace(
                match, enclave_map[enclave]['app%s_node' % app_id])

    # The enclave application node WAN IP Address identifier regular
    # expression of interest. We are interested in finding strings
    # that have the following format in the configuration file
    # templates:
    #
    #   $enclaveX_appY_wan_addr$
    #
    # where X is the enclave identifier and Y is the application
    # identifier.
    #
    # All instances of this string will be replaced with the WAN
    # facing IP Address for application node Y of enclave X, extracted
    # from the testbed topology file.
    app_node_wan_addr_regex = re.compile(
        '.*?([$]enclave[\d]+_app[\d]+_wan_addr[$]).*?')

    matches = app_node_wan_addr_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]
            app_id = tag.split("_")[1][3:]
            node = enclave_map[enclave]['app%s_node' % app_id]
            link = enclave_map[enclave]['app%s_wan_link' % app_id]
            line = line.replace(match, node_map[node][link])

    # The enclave application node WAN link identifier regular
    # expression of interest. We are interested in finding strings
    # that have the following format in the configuration file
    # templates:
    #
    #   $enclaveX_appY_wan_link$
    #
    # where X is the enclave identifier and Y is the application
    # identifier.
    #
    # All instances of this string will be replaced with the WAN
    # facing generic link identifier for application node Y of enclave
    # X, extracted from the testbed topology file.
    app_node_wan_link_regex = re.compile(
        '.*?([$]enclave[\d]+_app[\d]+_wan_link[$]).*?')

    matches = app_node_wan_link_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]
            app_id = tag.split("_")[1][3:]
            link = enclave_map[enclave]['app%s_wan_link' % app_id]

            line = line.replace(match, link)

    return line

#=============================================================================
def substitute_iron_node_info(line, phy_enclave_map, enclave_map, node_map):
    # The enclave IRON node identifier regular expression of interest. We
    # are interested in finding strings that have the following format in
    # the configuration file templates:
    #
    #   $enclaveX_iron_node$
    #
    # where X is the enclave identifier.
    #
    # All instances of this string will be replaced with the generic node
    # identifier for the IRON node of enclave X, extracted from the
    # testbed topology file.
    iron_node_regex = re.compile(
        '.*?([$]enclave[\d]+_iron_node[$]).*?')

    matches = iron_node_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]

            line = line.replace(match, enclave_map[enclave]['iron_node'])

    # The enclave IRON LAN facing IP Address regular expression of
    # interest. We are interested in finding strings that have the
    # following format in the configuration file templates:
    #
    #    $enclaveX_iron_lan_addr$
    #
    # where X is the enclave identifier.
    #
    # All instances of this string will be replaced with the IRON node's
    # LAN facing IP Address, extracted from the testbed topology file.
    iron_node_lan_addr_regex = re.compile(
        '.*?([$]enclave[\d]+_iron_lan_addr[$]).*?')

    matches = iron_node_lan_addr_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]

            node = enclave_map[enclave]['iron_node']
            link = enclave_map[enclave]['iron_lan_link']
            line = line.replace(match, node_map[node][link])

    # The enclave IRON LAN facing link identifier regular expression of
    # interest. We are interested in finding strings that have the
    # following format in the configuration file templates:
    #
    #    $enclaveX_iron_lan_link$
    #
    # where X is the enclave identifier.
    #
    # All instances of this string will be replaced with the IRON node's
    # LAN facing generic link identifier, extracted from the testbed
    # topology file.
    iron_node_lan_link_regex = re.compile(
        '.*?([$]enclave[\d]+_iron_lan_link[$]).*?')

    matches = iron_node_lan_link_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]

            link = enclave_map[enclave]['iron_lan_link']
            line = line.replace(match, link)

    # The enclave IRON LAN facing subnet address regular expression of
    # interest. We are interested in finding strings that have the
    # following format in the configuration file templates:
    #
    #    $enclaveX_iron_lan_subnet/YY$
    #
    # where X is the enclave identifier, and YY is the prefix length
    # (between 0 and 32).
    #
    # All instances of this string will be replaced with the IRON node's
    # LAN facing subnet address.
    iron_node_lan_subnet_regex = re.compile(
        '.*?([$]enclave[\d]+_iron_lan_subnet/[\d]+[$]).*?')

    matches = iron_node_lan_subnet_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]
            prefix = tag.split("/")[1]
            node = enclave_map[enclave]['iron_node']
            link = enclave_map[enclave]['iron_lan_link']
            if (int(prefix) > 32):
                continue
            rep_str = compute_subnet(node_map[node][link], prefix)
            line = line.replace(match, rep_str)

    # The enclave IRON WAN facing IP Address regular expression of
    # interest. We are interested in finding strings that have the
    # following format in the configuration file templates:
    #
    #    $enclaveX_iron_wanY_addr$
    #
    # where X is the enclave identifier and Y is the WAN address
    # identifier (either 1 or 2 as ALL enclaves are dual homed).
    #
    # All instances of this string will be replaced with the desired IP
    # Address, extracted from the testbed topology file.
    iron_node_wan_addr_regex = re.compile(
        '.*?([$]enclave[\d]+_iron_wan[12]_addr[$]).*?')

    matches = iron_node_wan_addr_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]
            wan_id = tag.split("_")[2][3:]

            node = enclave_map[enclave]['iron_node']
            if wan_id == "1":
                link = enclave_map[enclave]['iron_wan1_link']
            else:
                link = enclave_map[enclave]['iron_wan2_link']

            line = line.replace(match, node_map[node][link])

    # The enclave IRON WAN facing link identifier regular expression of
    # interest. We are interested in finding strings that have the
    # following format in the configuration file templates:
    #
    #    $enclaveX_iron_wanY_link$
    #
    # where X is the enclave identifier and Y is the WAN link identifier
    # (either 1 or 2 as ALL enclaves are dual homed).
    #
    # All instances of this string will be replaced with the desired
    # generic WAN facing link identifier, extracted from the testbed
    # topology file.
    iron_node_wan_link_regex = re.compile(
        '.*?([$]enclave[\d]+_iron_wan[12]_link[$]).*?')

    matches = iron_node_wan_link_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]
            wan_id = tag.split("_")[2][3:]

            if wan_id == "1":
                link_id = 'iron_wan1_link'
            else:
                link_id = 'iron_wan2_link'

            link = enclave_map[enclave][link_id]
            line = line.replace(match, link)

    return line

#=============================================================================
def substitute_le_node_info(line, phy_enclave_map, enclave_map, node_map):
    # The enclave LinkEm node identifier regular expression of interest. We
    # are interested in finding strings that have the following format in
    # the configuration file templates:
    #
    #   $enclaveX_leY_node$
    #
    # where X is the enclave identifier and Y is the LinkEm identifier
    # (either 1 or 2 as ALL enclaves are dual homed).
    #
    # All instances of this string will be replaced with the generic node
    # identifier for the appropriate LinkEm node of enclave X, extracted
    # from the testbed topology file.
    le_node_regex = re.compile(
        '.*?([$]enclave[\d]+_le[12]_node[$]).*?')

    matches = le_node_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]
            le_id = tag.split("_")[1][2:]

            node = enclave_map[enclave]['iron_node']
            if le_id == "1":
                node = enclave_map[enclave]['le1_node']
            else:
                node = enclave_map[enclave]['le2_node']

            line = line.replace(match, node)

    # The enclave LinkEm node LAN link identifier regular
    # expression of interest. We are interested in finding strings
    # that have the following format in the configuration file
    # templates:
    #
    #   $enclaveX_leY_lan_link$
    #
    # where X is the enclave identifier and Y is the LinkEm identifier
    # (either 1 or 2 as ALL enclaves are dual homed).
    #
    # All instances of this string will be replaced with the LAN
    # facing generic link identifier of the appropriate LinkEm node
    # enclave X, extracted from the testbed topology file.
    le_node_lan_link_regex = re.compile(
        '.*?([$]enclave[\d]+_le[12]_lan_link[$]).*?')

    matches = le_node_lan_link_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]
            le_id = tag.split("_")[1][2:]

            if le_id == "1":
                link = enclave_map[enclave]['le1_lan_link']
            else:
                link = enclave_map[enclave]['le2_lan_link']

            line = line.replace(match, link)

    # The enclave LinkEm node WAN link identifier regular
    # expression of interest. We are interested in finding strings
    # that have the following format in the configuration file
    # templates:
    #
    #   $enclaveX_leY_wan_link$
    #
    # where X is the enclave identifier and Y is the LinkEm identifier
    # (either 1 or 2 as ALL enclaves are dual homed).
    #
    # All instances of this string will be replaced with the WAN
    # facing generic link identifier of the appropriate LinkEm node
    # enclave X, extracted from the testbed topology file.
    le_node_wan_link_regex = re.compile(
        '.*?([$]enclave[\d]+_le[12]_wan_link[$]).*?')

    matches = le_node_wan_link_regex.findall(line)
    if matches:
        for match in matches:
            tag = match.strip('$').rstrip('$')
            enclave = phy_enclave_map[tag.split("_")[0][7:]]
            le_id = tag.split("_")[1][2:]

            if le_id == "1":
                link = enclave_map[enclave]['le1_wan_link']
            else:
                link = enclave_map[enclave]['le2_wan_link']

            line = line.replace(match, link)

    return line

#=============================================================================
def process_template_file(input_fn, phy_enclave_map, enclave_map, node_map):
    """
    Process an experiment configuration template file. Replace
    templated tags, enclosed in '$' characters with the appropriate
    enclave information that has been extracted from the experiment
    testbed topology file.
    """
    base_input_fn = os.path.basename(input_fn)

    if "lem" in base_input_fn:
        fn = input_fn.strip('\n').rsplit(".", 1)[0]
        output_fn = "%s.sh" % fn
    elif "app_enclave" in base_input_fn:
        component, enclave, name = input_fn.strip('\n').rsplit("_", 2)
        name = name.rsplit(".",1)[0]
        path = os.path.dirname(input_fn)
        enclave = phy_enclave_map[enclave[7:]]
        output_fn = "%s/%s_app_%s.sh" % (path, enclave_map[enclave]['app1_node'], name)
    elif "enclave" in base_input_fn:
        component, enclave = input_fn.strip('\n').rsplit("_", 1)
        enclave = phy_enclave_map[enclave.rsplit(".", 1)[0][7:]]
        output_fn = "%s_%s.cfg" % (component, enclave_map[enclave]['iron_node'])
    else:
        component = input_fn.strip('\n').rsplit(".", 1)[0]
        output_fn = "%s.cfg" % component

    log("Output filename: {}", output_fn)

    # Open the output file.
    out_file = open(output_fn, "w")

    ln = 0

    # Open the experiment configuration template file that is to be
    # processed.
    with open(input_fn) as in_file:
        lines = in_file.read().splitlines()

        # Process each line from the input file. Search for
        # replacement strings with the following format: $xyzzy$. If a
        # replacement string is found, it is replaced with the
        # appropriate information extracted from the testbed topology
        # file.
        for line in lines:
            ln += 1

            line = substitute_app_node_info(line, phy_enclave_map,
                                            enclave_map, node_map)
            line = substitute_iron_node_info(line, phy_enclave_map,
                                             enclave_map, node_map)
            line = substitute_le_node_info(line, phy_enclave_map,
                                           enclave_map, node_map)

            # We are finished with all substitutions for the
            # current line, so we can now write it to the output
            # file.
            out_file.write(line)
            out_file.write("\n")


#=============================================================================
def process_template_files(directory, phy_enclave_map, enclave_map, node_map):
    """
    Process all experiment template configuration files.
    """
    # Process all of the experiment template files in the directory.
    for fn in os.listdir(directory):
        fqfn = os.path.join(directory, fn)
        if os.path.isfile(fqfn):
            if fqfn.endswith("tmpl"):
                process_template_file(fqfn, phy_enclave_map, enclave_map,
                                      node_map)
        elif os.path.isdir(fqfn):
            process_template_files(fqfn, phy_enclave_map, enclave_map,
                                   node_map)

    return(True)

#=============================================================================
def main():
    """
    The main function.
    """
    global debug_mode

    # The default base directory location.
    DEFAULT_BASE_DIR = os.path.join(os.path.expanduser("~"),
                                    'iron_exp_staging')

    # The default base directory location.
    DEFAULT_ENCLAVE_CFG_FN = os.path.join(DEFAULT_BASE_DIR, 'enclaves.cfg')

    # The "notional-to-physical" enclave map.
    phy_enclave_map = {}

    # Information relevant to an enclave, expressed in terms of generic
    # node names and generic link names.
    enclave_map = {}

    # The node information, extracted from the testbed topology file.
    node_map = {}

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true",
                        dest="debug", default=False,
                        help="Enable low level diagnostic output.")
    parser.add_argument('-b', '--basedir', dest='base_dir',
                        metavar='BASE_DIR', default='_DEFAULT_',
                        help='Base directory over which to operate '
                        '[default: %s]' % DEFAULT_BASE_DIR)
    parser.add_argument('-e', '--enclavefn', dest='enclave_cfg_fn',
                        metavar="ENCLAVE_CONFIG_FILENAME",
                        default='_DEFAULT_',
                        help='Name of the enclave configuration mapping '
                        'file [default: %s]' % DEFAULT_ENCLAVE_CFG_FN)
    parser.add_argument("testbed_fn", metavar="TESTBED_FILENAME",
                        help="Name of the testbed topology file.")

    args = parser.parse_args()

    debug_mode = args.debug

    # Get the path to the base directory.
    base_dir = DEFAULT_BASE_DIR
    if args.base_dir != '_DEFAULT_':
        base_dir = args.base_dir

    # Expand any '~' or '~user' in the base directory.
    base_dir = os.path.expanduser(base_dir)

    enclave_info = {'app_nodes_per_enclave' : 1, 'le_nodes_per_enclave' : 2}

    # Extract the information from the experiment testbed topology
    # file.
    fq_testbed_fn = os.path.join(base_dir, "testbeds", args.testbed_fn)
    if (not process_testbed_file(fq_testbed_fn, node_map, enclave_info)):
        errmsg("Error processing experiment testbed topology file: %s" %
               fq_testbed_fn)
        exit(1)

    # Extract the information from the enclaves configuration file.
    enclave_cfg_fn = DEFAULT_ENCLAVE_CFG_FN
    if args.enclave_cfg_fn != '_DEFAULT_':
        enclave_cfg_fn = args.enclave_cfg_fn

    # Expand any '~' or '~user' in the base directory.
    enclave_cfg_fn = os.path.expanduser(enclave_cfg_fn)

    if (not process_enclave_map_file(enclave_cfg_fn,
                                     phy_enclave_map, enclave_map,
                                     enclave_info, node_map, base_dir)):
        errmsg("Error processing enclave configuration file: %s" %
               enclave_cfg_fn)
        exit(1)

    # Process all template configuration files in the base directory.
    if (not process_template_files(base_dir, phy_enclave_map, enclave_map,
                                   node_map)):
        errmsg("Error processing template configuration files in: %s" %
               base_dir)
        exit(1)

    return(0)

if __name__ == '__main__':
    sys.exit(main())
