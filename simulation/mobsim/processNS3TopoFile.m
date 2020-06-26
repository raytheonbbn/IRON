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
% Process NS3 style topology file
%
%

function topo = processNS3TopoFile(file)
fid      = fopen(file);
if fid == -1
    error('Topology file %s not found', file);
end

[line, ferror] = getNextLine(fid);
if ferror
    error('Empty topology file.');
end

nums = textscan(line,'%u %u %u');
nNodes = double(nums{1});
nLinks = double(nums{2});
nVirLinks = double(nums{3});

if (nNodes == 0 || isempty(nNodes) || isempty(nLinks) || isempty(nVirLinks))
    error('Problem with topology file');
end

% Collect info about which nodes are bpf and which aren't
nBpf     = 0;
nRouters = 0;
for n = 1:nNodes
    [line, ferror] = getNextLine(fid);
    if ferror
        error('Topo file too short');
    end
    info = textscan(line,'%u %u %u %s');
    if char(info{4}) == '+'
        nBpf = nBpf + 1;
        bpf(nBpf) = info{1};
    elseif char(info{4}) == '-'
        nRouters = nRouters + 1;
        routers(nRouters) = info{1};
    else
        error('Trouble distinguising BPF from router in topo file (no + or -)');
    end
end

topo.nNodes = nBpf;
if nRouters == 0
    routers = [];
end

% Get physical link info
% src dst capacity (latency)
% Note that links are specified only once and are assumed bi-directional
phyLinks = zeros(2*nLinks,4);
for i = 1:nLinks
    [line, ferror] = getNextLine(fid);
    if ferror
        error('Topo file too short');
    end
    nums = textscan(line,'%u %u %u %u');
    phyLinks(2*i-1,:) = cell2mat(nums(1:4));
    phyLinks(2*i,:) = phyLinks(2*i-1,[2,1,3,4]);
end
nLinks = 2*nLinks;

% Get virtual link info
% src dst

virLinks = zeros(2*nVirLinks,2);
for i = 1:nVirLinks
    [line, ferror] = getNextLine(fid);
    if ferror
        error('Topo file too short');
    end
    nums = textscan(line,'%u %u');
    virLinks(2*i-1,:) = cell2mat(nums);
    virLinks(2*i,:) = virLinks(2*i-1,[2,1]);
end
nVirLinks = 2*nVirLinks;

topo.bpfs       = sort(bpf);
topo.routers    = sort(routers);
topo.nPhyLinks  = double(nLinks);
topo.nVirLinks  = double(nVirLinks);
topo.virLinks   = virLinks;
topo.phyLinks   = phyLinks;
topo.nRouters   = nRouters;
topo.nBpf       = nBpf;
fclose(fid);

topo            = updateVirTopology(topo);
end

