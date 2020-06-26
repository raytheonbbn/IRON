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

import sys
import time
import array as array
from graphillion import GraphSet
import graphillion.tutorial as tl
from random import *

def GeneratePaths(graph, src, dst_list, deadline, max_paths):

    universe = [(edge[0],edge[1]) for edge in graph]
    GraphSet.set_universe(universe)

    # Generate required data structures
    n = max(max(universe))
    L = len(graph)
 
    zero_or_two = [0,2]
    constraints = [(edge[0],edge[1],edge[2]) for edge in graph]
    degree_constraints = {}
    weights = {}
    link_list = {}

    for v in range(0, int(n)):
        degree_constraints[v] = zero_or_two

    index = 0
    for edge in graph:
        weights[(edge[0], edge[1])] = edge[2]
        link_list[(edge[0], edge[1])] = index
        link_list[(edge[1], edge[0])] = index + L
        index = index + 1

    r = array.array('I')
    for dst in dst_list:
        d = int(dst)
        
        degree_constraints[src] = 1
        degree_constraints[d]   = 1

        lc = []
        lc.append((constraints, (0,deadline)))

        vertex_groups = [[src,d]]

        t = time.clock()
        gs = GraphSet.graphs(vertex_groups=vertex_groups, degree_constraints=degree_constraints, no_loop=True, linear_constraints=lc)
        print('GraphSet took {} seconds'.format(time.clock()-t))
        t = time.clock()
        paths = array.array('I')
        num_paths = 0
        # if (max_paths <= 0)
        #     iter = gs.__iter__()
        # else
        #     iter = gs.rand_iter()
        # end
        for path in gs.__iter__():
            num_paths = num_paths + 1
            if((num_paths > max_paths) and (max_paths > 0)):
                break
            temp = array.array('I', [0 for x in range(2*L+2)])
            temp[0] = src
            temp[1] = dst
            node =  src
            while path:
                nl = next(x for x in path if node in x)
                path.remove(nl)
                if nl[0]!=node:
                    nl = nl[1::-1]
                node = nl[1]
                temp[link_list[nl]+2] = 1

            paths.extend(temp)

        print('GraphSet found {} paths to destination {}'.format(num_paths, d))
        r.extend(paths)
        print('Building A submatrix took {} seconds'.format(time.clock()-t))
        degree_constraints[src] = zero_or_two
        degree_constraints[dst] = zero_or_two

    return r

def CreateRandomGrid(N,Cmax,Dmax):
    import math
    n = math.ceil(math.sqrt(N))
    if (n**2 != N):
        print('N not square. Setting N =', n**2)
        N = n**2
    g = tl.grid(n-1)
    r = list()
    for edge in g:
        r.append((edge[0]-1,edge[1]-1,randrange(1,Dmax+1),randrange(1,Cmax+1)))
    return r

def CreateRandomGraph(N,L,Cmax,Dmax):
# N is number of nodes in graph
# L is number of links in graph
# Cmax is the maximum capacity of a link
# Dmax is the maximum delay of a link
    if L > (N-1)*N/2:
        print('L too large')

    if L < (N-1):
        print('L too small')

    results = numpy.zeros((L,4))

    # There are N(N-1)/2 links to randomly choose from
    # Use zero based indexing: nodes 0 through N-1
    
    unusedLinks = list(range(0,int(N*(N-1)/2)))
    usedLinks = list()
    
    # Assume node 0 is put into network. We'll add the remaining nodes
    # one at a time, making sure to add links that connect them to the
    # existing graph. Links are bi-directional so only add once.
    # RC is "row-column" and represents an entry in the lower triange of
    # a connectivity matrix. I is the index (count) into that list

    for i in range(1,N):       # 1<=i<N
        node = randrange(0,i)  # 0<=node<i
        index = RCtoI(i,node,N)
        unusedLinks.remove(index)
        usedLinks.append(index)

    # Now take a random selection of the remaining links - enough to have L total
    usedLinks.extend(sample(unusedLinks,L-N+1))

    graph = []
    universe = []
    for link in usedLinks:
        r,c = ItoRC(link,N)
        universe.append((r,c))
        graph.append((r,c,randrange(1,Dmax+1),randrange(1,Cmax+1)))
    return (graph, universe)

def RCtoI(R,C,N):
    if (R == C) | (R > N-1) | (C > N-1):
        print('ERROR.')
        return False
    if R < C:
        R,C = C,R
    return int((2*N-C-1)*(C)/2+R-C-1)

def ItoRC(I,N):
    C,R = 0,1
    for j in range(N-2,-1,-1):
        if I <= j:
            return (I+N-1-j,C)
        I,C = I-j-1,C+1

