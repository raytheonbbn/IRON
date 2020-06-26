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
% Process traffic file
%
%
function traff = processTraffFile(file, topo)
fid      = fopen(file);
if fid == -1
    error('Topology file %s not found', file);
end

nGrps  = 0;
nFlows = 0;
nNodes = topo.nNodes;

% mcastDests holds group destinations
% groups can be reused for sending from multiple sources

mcastDests = zeros(1,nNodes);
mcastFlows = zeros(1,4);
[line, ferror] = getNextLine(fid);
if ferror
    error('Short traffic file');
end

while true
    info = textscan(line,'%u %s %*[^\n]');
    if char(info{2}{1}(1)) == '['
        % Multicast group description
        nGrps = nGrps + 1;
        % Loop over destinations
        % dsts = extractBetween(line, '[',']');        
        bi = strfind(line,'[');
        ei = strfind(line,']');
        dsts = cellstr(line(bi+1:ei-1));        
        for dst = cell2mat(textscan(dsts{1}, '%u'))'
            dstNo = find(topo.bpfs(:)==dst);
            mcastDests(nGrps, dstNo) = 1;
        end
    elseif char(info{2}{1}(1)) == 'm'
        nFlows = nFlows + 1;
        % Multicast flow description
        info = textscan(line,'%u m%u %f %f %*s %*u %*u %*u %*u %u %*u');
        mcastFlows(nFlows, 1) = info{1}; % Source
        mcastFlows(nFlows, 2) = info{2}; % Multicast group
        mcastFlows(nFlows, 3) = info{3}; % Start time
        mcastFlows(nFlows, 4) = info{4}; % Finish time
        mcastFlows(nFlows, 5) = info{5}; % Priority
    end
    [line, ferror] = getNextLine(fid);
    if ferror
        break;
    end
end
if (nFlows == 0) || (nGrps == 0)
    error('Short traffic file');
end
traff.nFlows = nFlows;
traff.nGrps  = nGrps;
traff.mcastDests = mcastDests;
traff.mcastFlows = mcastFlows;
end
