#!/usr/bin/python

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

import argparse
import sys

#=============================================================================
def generate_mesh_conn_cfg_file(output_fn, num_nodes):
     """
     Generate the node connectivity configuration file for a full mesh
     topology.
     """

     # Open the output file.
     out_file = open(output_fn, 'w')

     # For each node in the mesh topology, create the enclave
     # connectivity output file.
     for i in range(1, int(num_nodes) + 1):
          nbrs = []
          for j in range(1, int(num_nodes) + 1):
               if i != j:
                    nbrs.append(j)
          out_file.write("%s:%s\n" \
                         % (str(i), " ".join(str(x) for x in nbrs)))

     # Close the output file.
     out_file.close()

     return [int(num_nodes), 0]

#=============================================================================
def get_node_nbrs_for_grid_topo(rows, columns, x, y):
     """
     Get the neighbor nodes for the node in the x'th row and y'th
     column in a rows x columns grid topology.
     """
     nbrs = [(x + a[0], y + a[1]) for a in
             [(-1,0), (1,0), (0,-1), (0,1)]
             if ((0 <= x + a[0] < rows) and (0 <= y + a[1] < columns))]
     return nbrs

#=============================================================================
def generate_reordering_dict(rows, columns):
     """
     Reorders a grid topology so that the enclave ids are consecutive
     around the perimeter of the grid. A grid with the following enclave ids:

     1 2 3
     4 5 6
     7 8 9

     will be "reordered" to look like:

     1 2 3
     8 9 4
     7 6 5

     The reordered values will be returned as a dictionary:

     {1: 1, 2: 2, 3: 3, 4: 8, 5: 9, 6: 4, 7: 7, 8: 6, 9: 5}
     """

     enc_id_dict = {}
     incval = 0

     ilower = 0
     iupper = columns

     jlower = 0
     jupper = rows

     nRings = (min(rows, columns) + 1) / 2;

     for r in range(0, nRings):

          # Iterate across the top of the current rectangle
          for i in range(ilower, iupper):
               enc_id_dict[(jlower * columns) + i] = incval
               incval += 1

          # Iterate down the right side of the current rectangle
          for j in range(jlower + 1, jupper):
               enc_id_dict[(j * columns) + iupper - 1] = incval
               incval += 1

          # Iterate back across the bottom of the current rectangle
          if ((jupper - jlower) > 1):
               for i in range(iupper - 2, ilower - 1, -1):
                    enc_id_dict[((jupper - 1) * columns) + i] = incval
                    incval += 1

          # Iterate up the left side of the current rectangle
          if ((iupper - ilower) > 1):
               for j in range(jupper - 2, jlower, -1):
                    enc_id_dict[(j * columns) + ilower] = incval
                    incval += 1

          if ((ilower + 1) < iupper - 1):
               ilower += 1
          if ((iupper - 1) > ilower):
               iupper -= 1
          if ((jlower + 1) < jupper - 1):
               jlower += 1
          if ((jupper - 1) > jlower):
               jupper -= 1

     # We need the dictionary values to be 1-based instead of 0-based,
     # so create a new dictionary containing the values to be
     # returned.
     new_enc_id_dict={}
     for i in range(0, rows * columns):
          new_enc_id_dict[i + 1] = enc_id_dict[i] + 1

     return new_enc_id_dict

#=============================================================================
def generate_grid_conn_cfg_file(output_fn, grid_size_str, has_int_nodes):
     """
     Generate the node connectivity configuration file for an MxN grid
     topology or an MxN hollow grid topology. In a hollow grid
     topology, all nodes that are not on the perimeter of the grid are
     interior nodes.
     """

     if not "x" in grid_size_str:
          sys.stderr.write( "Error in grid size specification: " + \
                            grid_size_str + ", aborting...\n")
          return [0, 0]

     rows    = int(grid_size_str.split("x")[0])
     columns = int(grid_size_str.split("x")[1])

     # Create the list of lists (2-dimensional array) that stores the
     # enclave ids for the grid topology.
     #
     # Currently, the grid is assigned enclave ids as follows:
     #
     # 1 2 3
     # 4 5 6
     # 7 8 9
     #
     # The grid values are stored in the 2-dimensional nodes variable
     # as:
     #
     # [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
     #
     # If we are generating the experiment for a "hollow" grid, we
     # should "reorder" the above grid so the assigned enclave ids
     # are:
     #
     # 1 2 3
     # 8 9 4
     # 7 6 5
     #
     # keeping the enclave ids around the perimeter consecutively
     # numbered. If "reordering" occurs, the results are stored in the
     # node_id_dict dictionary as:
     #
     # {1: 1, 2: 2, 3: 3, 4: 8, 5: 9, 6: 4, 7: 7, 8: 6, 9: 5}
     #
     # When we determine the neighbors for a node we receive back
     # indexes into the 2-dimensional array of enclave ids. For a grid
     # topology, we simply look up the assigned enclave id from the
     # 2-dimensional nodes variable for each set of neighbor
     # indices. For a "hollow" grid topology, we do the same to get
     # the identifier of the enclave. We then look up the enclaves
     # "reordered" id using the node_id_dict dictionary.
     nodes = []
     for i in range(0, rows):
          nodes.append([])
          for j in range(0, columns):
               nodes[i].append((i * columns) + (j + 1))

     node_id_dict = {}
     if (has_int_nodes):
          node_id_dict = generate_reordering_dict(rows, columns)

     # Open the output file.
     out_file = open(output_fn, 'w')

     # For each node in the grid or hollow grid topology, get its
     # neighbors and create the enclave connectivity output file.
     for i in range(0, rows):
          nbrs = []
          for j in range(0, columns):
               nbrs = get_node_nbrs_for_grid_topo(rows, columns, i, j)
               nbr_node_ids = []
               if (not has_int_nodes):
                    for nbr in nbrs:
                         nbr_node_ids.append(nodes[nbr[0]][nbr[1]])
               else:
                    # Once we look up the nbr id, use the node_id_dict
                    # to look up the reordered nbr id.
                    for nbr in nbrs:
                         nbr_node_ids.append(
                              node_id_dict[nodes[nbr[0]][nbr[1]]])
               nbr_node_ids.sort()

               if (not has_int_nodes):
                    out_file.write("%s:%s\n" % \
                                   (str(nodes[i][j]),
                                    " ".join(str(x) for x in nbr_node_ids)))
               else:
                    # Again, here we need to use the node_id_dict to
                    # look up the reordered node id that we are
                    # currently output nbrs for.
                    out_file.write("%s:%s\n" % \
                                   (str(node_id_dict[nodes[i][j]]),
                                    " ".join(str(x) for x in nbr_node_ids)))

     # Close the output file.
     out_file.close()

     node_cnt     = rows * columns
     int_node_cnt = 0

     if (has_int_nodes):
          int_node_cnt = node_cnt - ((columns * 2) + ((rows - 2) * 2))

     if (int_node_cnt < 0):
          int_node_cnt = 0

     return [node_cnt, int_node_cnt]

#=============================================================================
def generate_ring_conn_cfg_file(output_fn, ring_size_str):
     """
     Generate the node connectivity configuration file for a MxNx...xZ ring
     topology.
     """

     import array

     if not "x" in ring_size_str:
          sys.stderr.write( "Error in ring size specification: " + \
                            ring_size_str + ", aborting...\n")
          return [0, 0]

     # Figure out how many rings we have, and the size of each ring

     nRingNodes = array.array('i')

     done      = 0
     nRings    = 0
     nNodes    = 0
     nIntNodes = 0
     while done == 0:
          try:
               val = int(ring_size_str.split("x")[nRings])
               nRingNodes.append(val)
               nNodes = nNodes + val
               if (nRings > 0):
                    nIntNodes = nIntNodes + val
          except:
               done = 1

          if done == 0:
               nRings = nRings + 1

     # print "Number of rings is: %d \n" % nRings
     # Check to see if the integer ratio requirements hold

     allOkay = 1
     ratios = array.array('i')
     if (nRings > 1):
          for i in range(nRings-1):
               # print ("Found %d %d " % (nNodes[i], nNodes[i+1]))
               ratios.append(int(nRingNodes[i] / nRingNodes[i+1]))
               delta = (ratios[i] * nRingNodes[i+1]) - nRingNodes[i]
               if (delta != 0):
                    allOkay = 0

     if (allOkay == 0):
          sys.stderr.write ("Ratio check failed in constructing ring of size " + \
                            ring_size_str + " aborting...\n")
          return [nNodes, nIntNodes]

     # Create the list of lists that stores the
     # enclave ids for the grid topology.
     nodes = []

     intCount = 0
     intStart = 0
     for i in range(nRings):
          nodes.append([])
          if (i == 0):
               for j in range(nRingNodes[i]):
                    nodes[i].append(j+1)
                    intStart = intStart + 1
          else:
               for j in range(nRingNodes[i]):
                    nodes[i].append(intStart + intCount + 1)
                    intCount = intCount + 1

     # Open the output file.
     out_file = open(output_fn, 'w')

     # For each node in the ring topology, get its neighbors and
     # create the enclave connectivity output file.

     for i in range(nRings):
          for j in range(nRingNodes[i]):

               nbrs = []

               # Get neighbors on the same ring
               if (nRingNodes[i] > 1):
                    nbrs.append(nodes[i][(j-1) % nRingNodes[i]])

               if (nRingNodes[i] > 2):
                    nbrs.append(nodes[i][(j+1) % nRingNodes[i]])

               # Get neighbors on the adjacent outer ring
               if (i > 0):
                    for k in range(ratios[i-1]):
                         index = j * ratios[i-1] + k
                         nbrs.append(nodes[i-1][index])

               # Get neighbors on the adjacent inner ring
               if (i < nRings-1):
                    index = j / ratios[i];
                    nbrs.append(nodes[i+1][index])

               # Sort the neghbor list to write them in order
               nbrs.sort()

               out_file.write("%s:%s\n" % \
                              (str(nodes[i][j]),
                               " ".join(str(x) for x in nbrs)))

     # Close the output file.
     out_file.close()

     return [nNodes, nIntNodes]

#=============================================================================
def main():
     """
     The main function.
     """

     # The default output filename.
     DEFAULT_OUTPUT_FN = '/tmp/enc_conn.cfg'

     parser = argparse.ArgumentParser()
     parser.add_argument("-G", "--grid", dest='grid_size_str',
                         metavar='GRID_SIZE_STR', default='_NONE_',
                         help='Desired topology is a grid with size MxN, '
                         'where M is the number of rows and N is the number '
                         'of columns in the grid.')
     parser.add_argument("-H", "--hollow-grid", dest='hollow_grid_size_str',
                         metavar='HOLLOW_GRID_SIZE_STR', default='_NONE_',
                         help='Desired topology is a grid with size MxN, '
                         'where M is the number of rows and N is the number '
                         'of columns in the grid. Any nodes not on the grid '
                         'perimeter are interior nodes.')
     parser.add_argument("-R", "--ring", dest='ring_size_str',
                         metavar='RING_SIZE_STR', default='_NONE_',
                         help='Desired topology is a set of concentric rings '
                         'with sizes MxNx...xZ, where M is the number of '
                         'edge nodes, N is the number of the nodes in the '
                         'outermost interior ring, ..., and Z is the number '
                         'of nodes in the innermost interior ring.')
     parser.add_argument("-M", "--mesh", dest='mesh_num_nodes',
                         metavar='NUM_NODES', default='_NONE_',
                         help='Desired topology is a full with with N nodes.')
     parser.add_argument("-o", "--output-file", dest='output_fn',
                         metavar='OUTPUT_FN', default='_DEFAULT_',
                         help='Name of the output file [default: %s'
                         % DEFAULT_OUTPUT_FN)

     args = parser.parse_args()

     output_fn = DEFAULT_OUTPUT_FN
     if args.output_fn != '_DEFAULT_':
          output_fn = args.output_fn

     counts = [0, 0]
     if args.mesh_num_nodes != '_NONE_':
          counts = generate_mesh_conn_cfg_file(output_fn, args.mesh_num_nodes)
     elif args.grid_size_str != '_NONE_':
          counts = generate_grid_conn_cfg_file(output_fn, args.grid_size_str, False)
     elif args.hollow_grid_size_str != '_NONE_':
          counts = generate_grid_conn_cfg_file(output_fn, args.hollow_grid_size_str, True)
     elif args.ring_size_str != '_NONE_':
          counts = generate_ring_conn_cfg_file(output_fn, args.ring_size_str)

     print("%d %d" % (counts[0],counts[1]));

if __name__ == '__main__':
    sys.exit(main())
