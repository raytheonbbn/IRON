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
% Update the overlay (virtual) topology
%
%

function t = updateVirTopology(topo)

t = topo;

% Shortcut - assume that there's at most one router between BPF nodes
% Makes it easy to compute virtual link capacity

for i = 1:t.nVirLinks
    src = t.virLinks(i,1);
    dst = t.virLinks(i,2);
    % Are they directly connected?
    link = t.phyLinks(t.phyLinks(:,1)==src&t.phyLinks(:,2)==dst,:);
    if ~isempty(link)
        t.virLinks(i,3)=link(3);
        t.virLinks(i,4)=link(4);
    else
        % Not directly connected, so look for a router
        foundIt = false;
        for j = 1:t.nRouters
            link1 = t.phyLinks(t.phyLinks(:,1)==src & t.phyLinks(:,2)==t.routers(j),:);
            link2 = t.phyLinks(t.phyLinks(:,1)==t.routers(j) & t.phyLinks(:,2)==dst,:);
            if ~isempty(link1) && ~isempty(link2)
                cap = min(link1(3),link2(3));
                t.virLinks(i,3) = cap;
                t.virLinks(i,4) = link1(4) + link2(4);
                foundIt = true;
                break;
            end
        end
        if ~foundIt
            error('Could not connect virtual nodes %d and %d', src, dst);
        end
    end
end

end
