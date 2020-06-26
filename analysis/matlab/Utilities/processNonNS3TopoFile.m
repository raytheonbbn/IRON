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

%
%
% Process Non-NS3 style topology file
%
%

function topo = processNonNS3TopoFile(file)
fid      = fopen(file);
if fid == -1
    error('Topology file %s not found', file);
end

[line, ferror] = getNextLine(fid);
if ferror
    error('Empty topology file.');
end
nums = textscan(line, '%d');
topo.nNodes   = nums{1};
topo.nBpf     = nums{1};
topo.nRouters = 0;
topo.routers  = [];
topo.phyLinks = zeros(topo.nNodes,4);

i = 1;
while true
    [line, ferror] = getNextLine(fid);
    if ferror
        break;
    end
    nums = textscan(line,'%d %d %d %d');
    topo.phyLinks(i,1:3) = double(cell2mat(nums(1:3)));
    if ~isempty(nums{4})
        % Latency is optional
        topo.phyLinks(i,4) = double(nums{4});
    end
    i = i + 1;
end
nLinks = i - 1;

% Figure out what nodes are implicitly specified by links

topo.bpfs = union(topo.phyLinks(:,1),topo.phyLinks(:,2));
if size(topo.bpfs,1) ~= topo.nNodes
    error('Number of nodes specified in topo file is wrong');
end

% Now insert reverse links for any one-way links

for j = 1:nLinks
    src = topo.phyLinks(j,1);
    dst = topo.phyLinks(j,2);
    if isempty(topo.phyLinks((topo.phyLinks(:,1)==dst & topo.phyLinks(:,2)==src),:))
        topo.phyLinks(i,1:4) = [dst, src, topo.phyLinks(j,3:4)];
        i = i + 1;
    end
end
nLinks = i - 1;

% Now create virtual link data structure
topo.virLinks = topo.phyLinks;
topo.nVirLinks = nLinks;
topo.nPhyLinks = nLinks;

fclose(fid);

end
