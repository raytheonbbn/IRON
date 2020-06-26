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

from priodict import PriorityDictionary

class ShortestPath(object):

  def __init__(self, debug=False):
    self.debug = debug


  # Dijkstra's algorithm for shortest paths

  # http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/117228

  def Dijkstra(self, graph, start, end=None):
    """
    Find shortest paths from the start vertex to all
    vertices nearer than or equal to the end.

    The input graph 'graph' is assumed to have the following
    representation: A vertex can be any object that can
    be used as an index into a dictionary.  graph is a
    dictionary, indexed by vertices.  For any vertex v,
    graph[v] is itself a dictionary, indexed by the neighbors
    of v.  For any edge v->w, graph[v][w] is the length of
    the edge.  This is related to the representation in
    <http://www.python.org/doc/essays/graphs.html>
    where Guido van Rossum suggests representing graphs
    as dictionaries mapping vertices to lists of neighbors,
    however dictionaries of edges have many advantages
    over lists: they can store extra information (here,
    the lengths), they support fast existence tests,
    and they allow easy modification of the graph by edge
    insertion and removal.  Such modifications are not
    needed here but are important in other graph algorithms.
    Since dictionaries obey iterator protocol, a graph
    represented as described here could be handed without
    modification to an algorithm using Guido's representation.

    Of course, graph and graph[v] need not be Python dict objects;
    they can be any other object that obeys dict protocol,
    for instance a wrapper in which vertices are URLs
    and a call to graph[v] loads the web page and finds its links.

    The output is a pair (d,p) where d[v] is the distance
    from start to v and p[v] is the predecessor of v along
    the shortest path from s to v.

    Dijkstra's algorithm is only guaranteed to work correctly
    when all edge lengths are positive. This code does not
    verify this property for all edges (only the edges seen
    before the end vertex is reached), but will correctly
    compute shortest paths even for some graphs with negative
    edges, and will raise an exception if it discovers that
    a negative edge has caused it to make a mistake.
    """

    d = {}  # dictionary of final distances
    p = {}  # dictionary of predecessors
    q = PriorityDictionary()   # est.dist. of non-final vert.
    q[start] = 0

    for v in q:
      d[v] = q[v]
      if v == end: break

      for w in graph[v]:
        vw_length = d[v] + graph[v][w]
        if w in d:
          if vw_length < d[w]:
            raise ValueError, \
              "Dijkstra: found better path to already-final vertex"

        elif w not in q or vw_length < q[w]:
          q[w] = vw_length
          p[w] = v

    return (d, p)

  def ComputeShortestPath(self, graph, start, end=None):
    """
    Find a single shortest path from the given start vertex
    to the given end vertex.
    The input has the same conventions as Dijkstra().
    The output is a list of the vertices in order along
    the shortest path.
    """

    d,p = self.Dijkstra(graph, start, end)
    path = []

    if not end:
      return path, d, p
      
    while 1:
      path.append(end)
      if end == start: break
      end = p[end]

    path.reverse()
    return path, d, p


  def ConvertConnectivityToGraph (self, connectivity, index_node_mapping):
    graph = {}
    for i in range(0, len(connectivity)):
      src_node_str = index_node_mapping[i]

      nbrs = {}
      for j in range(0, len(connectivity)):
        if connectivity[i, j] > 0:
          dst_node_str = index_node_mapping[j]
          nbrs[dst_node_str] = connectivity[i, j]

      graph[src_node_str] = nbrs

    return graph

 
