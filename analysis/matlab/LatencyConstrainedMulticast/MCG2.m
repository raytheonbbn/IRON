% IRON: iron_headers
%
% Distribution A
%
% Approved for Public Release, Distribution Unlimited
%
% EdgeCT (IRON) Software Contract No.: HR0011-15-C-0097
% DCOMP (GNAT)  Software Contract No.: HR0011-17-C-0050
% Copyright (c) 2015-20 Raytheon BBN Technologies Corp.
%
% This material is based upon work supported by the Defense Advanced
% Research Projects Agency under Contracts No. HR0011-15-C-0097 and
% HR0011-17-C-0050. Any opinions, findings and conclusions or
% recommendations expressed in this material are those of the author(s)
% and do not necessarily reflect the views of the Defense Advanced
% Research Project Agency.
%
% Permission is hereby granted, free of charge, to any person obtaining a copy
% of this software and associated documentation files (the "Software"), to deal
% in the Software without restriction, including without limitation the rights
% to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
% copies of the Software, and to permit persons to whom the Software is
% furnished to do so, subject to the following conditions:
%
% The above copyright notice and this permission notice shall be included in all
% copies or substantial portions of the Software.
%
% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
% OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
% SOFTWARE.
%
% IRON: end

function [y, graph, r, listLink] = MCG2(topoFile, src,dst_list,Deadline,maxPaths)

% cd /Users/glauer/graphillion
% py.importlib.import_module('graphillion')
% cd ~/GNAT/git-GNAT/analysis/matlab/LatencyConstrainedMulticast

    numDsts = size(dst_list,2);
    
    totalCPU = cputime;
    
    % Read the topology file
    % First line is number of nodes
    % Each line after is [src, dst, latency, capacity]
    % Node IDs start at zero

    fid      = fopen(topoFile);
    N        = strread(fgetl(fid), '%d');

    i = 1;
    j = 1;
    tmp = fgetl(fid);
    while tmp > 0
        [g(i,1),g(i,2),g(i,3),g(i,4)] = strread(tmp, '%d %d %f %f');
        % add in 3 packets worth of serialization latency to account for
        % Copa2 over LinkEm
        g(i,3)=g(i,3)+30/g(i,4);
        i = i + 1;
        tmp = fgetl(fid);
    end
    fclose(fid);
    L = i-1;
    fprintf('Total of %i links\n', L);
    
    % Create a python data structure representing graph so we can pass it
    % to graphillion
    
    graph = py.list({});
    for i = 1:L
        graph.append(py.tuple({py.int(g(i,1)), py.int(g(i,2)), py.int(g(i,3)), py.int(g(i,4))}));
    end
    
    % Create arrays to map between two nodes and the link between them
    % Make sure to add both directions of link
    % These are used to build the A matrix and to parse the output from the
    % LP
    
    for i = 1:L
        linkList(g(i,1)+1,g(i,2)+1) = i;
        linkList(g(i,2)+1,g(i,1)+1) = i+L;
        listLink(i,:) = [g(i,1), g(i,2)];
        listLink(i+L,:) = [g(i,2), g(i,1)];
    end
    L = 2*L;
    
    % More python data structures
    
    s = py.int(src);
    d = py.list({});
    for dst = dst_list
        d.append(py.int(dst));
    end

    % r is a linear array representing the paths found by graphillion
    % (This is efficient for converting between python and matlab data
    % structures.)
    % These paths meet the Deadline
    % Return upto maxPaths
    
    r=py.GNAT.GeneratePaths(graph,s,d,Deadline,maxPaths);
    if (isempty(r))
        fprintf('No paths found')
        return
    end
    r = uint8(r);
    r = reshape(r, [(L+2),int32(size(r,2)/(L+2))]);
    totalPaths = size(r,2);

    % A matrix
    %
    %  [A1: LxP1] [0]        [0]        ...  [0]        [-I] [0]
    %  [1:  1xP1] [0]        [0]        ...  [0]        [0]   -1
    %   [0]       [A2: LxP2] [0]        ...  [0]        [-I] [0]
    %   [0]       [1:  1xP2] [0]        ...  [0]        [0]   -1
    %   [0]       [0]        [A3: LxP3] ...  [0]        [-I] [0]
    %   [0]       [0]        [1:  1xP2] ...  [0]        [0]   -1
    % ...
    %   [0]       [0]        [0]             [An: LxPn] [-I] [0]
    %   [0]       [0]        [0]             [1:  LxPn] [0]   -1
    %   [0]       [0]        [0]             [0]        [I]    0
    
    % Aj is a matrix of L rows (one for each link and Pj columns one for
    % each path to destination j. The variables associated with these
    % columns are the flow on that path to that destination
    % The variables associated with the -I matrix for those rows are the
    % flow on each link to each destination.
    % Each of these rows is set less-than-or-equal to zero,
    % which forces the link variables to be greater than or equal to the
    % flow on the links for ANY destination (taking the max flow over
    % destinations).
    % The I matrix in the lower right corner forces the flows on each link
    % to be less than the link capacity.
    % The row vector of '1' beneath each Aj matrix sums the flows over the
    % paths to a destination and thus computes the total flow to each
    % destination. The '-1' in the last column is the maximum over these
    % rates and is what's maximized by the LP
    
    A = sparse(numDsts*(L+1)+L, totalPaths+numDsts*L+1);
    t = cputime;
    col = 1;
    row = 1;
    numPaths=zeros(totalPaths,3);
    numPaths(:,1)=src;
    index=1;
    for d = dst_list
       subA = r(3:end,r(1,:)==src&r(2,:)==d);
       numPaths(index,2)=d;
       numPaths(index,3)=size(subA,2);
       index=index+1;
       A(row+(0:L-1),col+(0:size(subA,2)-1))=subA;
       A(row+L,col+(0:size(subA,2)-1))=1;
       row = row + L + 1;
       col = col + size(subA,2);
    end
          
    % Columns for this matrix are the total flow on each link to each dest
    
    A(1:numDsts*(L+1),col+(0:(L-1))) = repmat([-eye(L);zeros(1,L)],numDsts,1);
    
    % This matrix is used to ensure that flows on links are less than
    % capacity. Note that we're implicitly taking the max of the
    % information flows by making sure that the info flow for each
    % destination is less than capacity
    
    A(numDsts*(L+1)+(1:L),col+(0:(L-1))) = eye(L);
    
    % Add up info flows on links and compare to capacity
    temp = zeros(L+1,1);
    temp(end,1) = -1;

    A(1:numDsts*(L+1),end) = repmat(temp, numDsts, 1);
    fprintf('Building A matrix (%i, %i) took %f seconds\n', size(A,1),size(A,2),cputime-t);
    
    % Setup constraints
    
    buc = zeros(numDsts*(L+1)+L,1);
    for i = 1:size(graph,2)
        link = g(i,:);
        node1 = link(1)+1;
        node2 = link(2)+1;
        offset = linkList(node1,node2);
        buc(numDsts*(L+1)+offset) = g(i,4);
        offset = linkList(node2,node1);
        buc(numDsts*(L+1)+offset) = g(i,4);
    end
    
    temp = -Inf(L+1,1);
    temp(end,1) = 0;
    blc  = [repmat(temp,numDsts,1);zeros(L,1)];
    bux = Inf(size(A,2),1);
    blx = zeros(size(A,2),1);
    f   = zeros(size(A,2),1);
    f(end,1) = 1;
    
    lo1.sense = 'max';
    lo1.c     = f;
    lo1.a     = A;
    lo1.blc   = blc;
    lo1.buc   = buc;
    lo1.blx   = blx;
    lo1.bux   = bux;
    t=cputime;
    [y, status]= mosekAdapter(lo1,true,false,false);
    x=y.sol.itr.xx;
    index = 1;
    row = 1;
%     for i = dst_list
%         fprintf('Dst = %i\n', i);
%         NP = numPaths((numPaths(:,1)==src)&(numPaths(:,2)==i),3);
%         for j = 1:NP
%             if x(index) > 0
%                 fprintf('Rate on path is %f\n',x(index));
%                 k = find(A(row+(0:L-1),index));
%                 fprintf('Path is:\n');
%                 listLink(k,:)-1
%             end
%             index = index + 1;
%         end
%         row = row + L + 1;
%     end
    fprintf('Solving LP took %f seconds\n', cputime-t);
    fprintf('Total time to solve multicast problem was %f seconds\n', cputime-totalCPU);
    fprintf('Src = %i\n', src);
    fprintf('Multicast rate is %f\n',y.sol.itr.xx(end));
end


