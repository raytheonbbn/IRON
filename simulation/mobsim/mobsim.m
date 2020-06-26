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

function [] = mobsim()

% Multicast Over Backpressure Simulator

clear; % Make sure to discard any cruft from previous runs

topoFile   = 'topo.txt';
trafFile   = 'traff.txt';
impairFile = 'imp.txt';  % Set to '' to disable impairments
% impairFile = '';  % Set to '' to disable impairments

% Simulation parameters

% Define the simulation calibration constant
% For this simulation, a 4Mbps channel uses 3 clock ticks per packet
% For 10,000 bit pkts, this yields 400 pkts/s * 3 ticks/pkt = 1200 ticks/s

ticsPerSec = 1200;
endTime    = 40; % 150        % Seconds
maxTicks   = endTime * ticsPerSec;

% Initialize the simulation-wide clock object
clock = Clock(ticsPerSec);

% Specify dequeueing algorithm to use
% dqa = DequeueAlg.fifo;
% dqa = DequeueAlg.lifo;
% dqa = DequeueAlg.netcoded;
dqa = DequeueAlg.groupbest;

% Boolean indicating whether or not we use opportunistic forwarding
% Opportunistic fowarding will include destinations with negative
% gradients if the selected packet (which has positive gradients to
% other destinations) is more likely to be sent to the same neighbor in
% the near future than any other neighbor

ofwd = true;
% ofwd = false;

% Opportunistic forwarding will not consider negative gradients less
% than this value
offloor = -1;

% Hysteresis is used to inhibit circulation. To disable, set to 0
hysteresis = 2;    % Hysteresis is measured in packets

% Specify if the physical gradient calculation should only include those
% destinations for which there are physical packets enqueued locally.
% This is really only a consideration if we are using virtual queues
gradReqPhyPkts = true;

% Specify which VQ algorithm to use
% vqType = VQDefs.none;
vqType = VQDefs.zlr;
% vqType = VQDefs.dualgrad;

% Specify the zlr configuration
%
% zlroption = VQDefs.zlr_zdq_base;
zlroption = VQDefs.zlr_zdq_alt1;

% Note: true baseline zlr requires setting gradReqPhyPkts to false, and
% the alt1 zlr alg requires setting gradReqPhyPkts to true. That said,
% the code will still work without overriding the gradReqPhyPkts value, 
% so the following may be commented out. This just helps with
% separating the base ZLR algorithm from the alt version

if (vqType == VQDefs.zlr)
    if (zlroption == VQDefs.zlr_zdq_base)
        gradReqPhyPkts = false;
    elseif (zlroption == VQDefs.zlr_zdq_alt1)
        gradReqPhyPkts = true;
    end
end

% Specify the dual gradient configuration
%
% Specify the dual gradient algorithm virtual queue estimation interval
% vqUpdateInterval in clock tics
vqUpdateInterval = 12;

% Specify which dual gradient algorithm to use
% dgoption = VQDefs.dg_base;
dgoption = VQDefs.dg_alt1;

% Specify which admission control reporting algorithm to use
% acra = ACDefs.sum;
acra = ACDefs.max;
% acra = ACDefs.avg;

% Specify the rest of the sim configuration parameters

maxQueueDepth = 300;   % Max number of packets we'll enqueue at a node
maxLinkDepth  = 6;     % Max number of packets "in flight" in a link
kVal          = 5000;  % Celebrated constant in packets^2/sec use w "max"
% kVal        = 20000; % Celebrated constant in packets^2/sec use w "sum"

%     graphLinkUsage = false;
%     graphDelays    = false;
%     graphPktCounts = false;

graphLinkUsage = false;
graphDelays    = true;
graphPktCounts = true;

% Parameters controlling how samples are grouped together for plots
aggNum      = 10;  % Number of sample values aggregated together
aggInterval = 120; % Agg interval is aggNum x 12 tick period (= 0.1 s)
nIntervals  = maxTicks/aggInterval;

% Change these if you want to plot a specific subsection of the run
plotStartTime = 0;
%     plotStartTime = 35;
plotEndTime   = endTime;

% Process the topology file
topo = processTopoFile(topoFile);

% Convert from capacity to linkPeriods
topo.virLinks(:,3) = 12e6./topo.virLinks(:,3);

nNodes = topo.nBpf;
nDest  = nNodes;  % Every node can be a destination
nLinks = topo.nVirLinks;

% Parse the traffic file next. We do this to find out the number
% of multicast/unicast groups, as needed to size various arrays

traff = processTraffFile(trafFile,topo);
nGrps = traff.nGrps;

% Node array is in order of node_id (nid) which is not the same as the
% configuration file node id

node(nNodes) = Node();
for n = 1:nNodes
    nodeName = strcat('Node-', int2str(topo.bpfs(n)));
    node(n).Initialize(clock,n,topo.bpfs(n),nodeName,nGrps,...
        maxQueueDepth,nDest,dqa,ofwd,offloor,hysteresis,...
        gradReqPhyPkts,vqType,zlroption);
end

% Link array is in same order as the virtual links read in from the
% config file. We use this when configuring the period of the link.

link(nLinks) = Link();
for i=1:nLinks
    % Map from config file node numbers to node numbers used here
    
    src = topo.virLinks(i,1);
    dst = topo.virLinks(i,2);
    
    srcNo = find(topo.bpfs(:)==src);
    dstNo = topo.bpfs(:)==dst;
    
    linkName = strcat('Link-', int2str(src), '-', int2str(dst));
    
    link(i).Initialize(clock,i,linkName,node(dstNo),...
        maxLinkDepth,nDest,src,dst,topo.virLinks(i,3));
    
    % Connect the source node to this link
    node(srcNo).link = [node(srcNo).link link(i)];
end

% Compute forwarding bias (Note: link argument is a call by reference)
computeFbias(link, topo);

% Read in src->mcastGroup info and create admission controllers

nAdmCtls = traff.nFlows;
admctl(nAdmCtls) = AdmCtrl();

groupNames{nAdmCtls} = '';
for i = 1:nAdmCtls
    src = traff.mcastFlows(i,1);
    grp = traff.mcastFlows(i,2);
    pri = traff.mcastFlows(i,5);
    
    srcNo = find(topo.bpfs(:)==src,1);
    dstNo = find(topo.bpfs(:)==dst,1);
    
    if isempty(srcNo) || isempty(dstNo)
        error('Admission control problem');
    end
    
    admctl(i).Initialize(clock,i,strcat('ac',int2str(src)),...
        node(srcNo),i,traff.mcastDests(grp+1,:),kVal,acra,pri);
    
    % Set grpName
    groupNames{i} = ...
        strcat('Node-',int2str(src),'-to-Multicast-Group-',int2str(grp));
end

% Setup start and end times for flows
for i = 1:traff.nFlows
    start  = traff.mcastFlows(i,3);
    finish = traff.mcastFlows(i,4);
    admctl(i).strt = start*ticsPerSec;
    admctl(i).fnsh = finish*ticsPerSec;
end

% Process impairment file
if ~isempty(impairFile)
    impair = processImpairFile(impairFile);
    
    for i = 1:size(impair,2)
        impair(i).time = impair(i).time * ticsPerSec;
    end
else
    impair = [];
end

% Initialize statistics tracking arrays
nodeEnqueues = zeros(1,nDest);
pktsSent     = zeros(nGrps,1);

% Setup mechanism to detect if the system ever deadlocks
stallCount = 0;

hasStalledPeriod = 13;

% Setup to rcord when packets arrive at the terminal nodes
nodeArrival  = zeros(maxTicks,nDest,nGrps);

% Setup to record how many packets are in each node at any given time
if (graphPktCounts)
    packetCounts = zeros(maxTicks,nNodes,nGrps);
end

% Setup to record how long packets spent traversing the network
if (graphDelays)
    arrivalDelay = zeros(maxTicks,nDest,nGrps);
end

% Track how many packets of each group cross each link
if (graphLinkUsage)
    flow    = zeros(maxTicks,nLinks,nGrps);
    flowDst = zeros(maxTicks,nLinks,nGrps,nDest);
end

maxDepth = 0;
maxSpan  = 0;

while clock.tics <= maxTicks
    
    %%%%%%% Stage 0: update the topology (modify link speeds)
    
    % This code assumes impairments are sorted by timestamp
    updateTopology = false;
    while ~isempty(impair) && clock.tics >= impair(1).time
        
        % Flag that there is something to do
        updateTopology = true;
        
        src  = impair(1).src;
        dst  = impair(1).dst;
        rate = impair(1).rate;
        lat  = impair(1).lat;
        % loss = impair(1).loss; % Currently unused
        
        % Update physical link characteristics
        index = find(topo.phyLinks(:,1)==src & topo.phyLinks(:,2)==dst);
        topo.phyLinks(index,3) = rate;
        topo.phyLinks(index,4) = lat;
        
        % Take care of reverse direction
        index = find(topo.phyLinks(:,1)==dst & topo.phyLinks(:,2)==src);
        topo.phyLinks(index,3) = rate;
        topo.phyLinks(index,4) = lat;
        
        % Pop the stack of impairments
        impair(1) = [];
        
        if isempty(impair)
            break;
        end
    end
    
    if updateTopology
        % Now update the virtual (overlay) topology
        topo = updateVirTopology(topo);
        
        % Update links (only period for now)
        for i = 1:nLinks
            link(i).period = 12e6/topo.virLinks(i,3);
        end
    end
    
    %%%%%%% Stage 1: Admit zero or more pkts to the various source queues
    
    for i=1:nAdmCtls
        [nSent, grp] = admctl(i).admit();
        if (nSent > 0)
            pktsSent(grp) = pktsSent(grp) + nSent;
            stallCount = 0;
        end
    end
    
    %%%%%%% Stage 2: Model the exchange of queue depth information
    
    for i=1:nNodes
        node(i).advertise();
    end
    
    %%%%%%% Stage 3: Compute queue differentials and stage packets for
    %%%%%%%          forwarding
    
    for i=1:nNodes
        [resetStall, tmpDepth, tmpSpan] = node(i).forward();
        if (resetStall)
            stallCount = 0;
        end
        if (tmpDepth > maxDepth)
            maxDepth = tmpDepth;
        end
        if (tmpSpan > maxSpan)
            maxSpan = tmpSpan;
        end
    end
    
    %%%%%%% Stage 4: transmit packets over the links
    
    for i=1:nLinks
        [resetStall, nid, pkt] = link(i).transmit();
        % The transmit call may or may not return a pkt
        if (~isempty(pkt))
            grp = pkt.grp;
        end
        if (graphLinkUsage)
            if (~isempty(pkt))
                % count packets crossing the link by group.
                flow(clock.tics,i,grp) = flow(clock.tics,i,grp) + 1;
                % count packets crossing the link by group and dest
                % Packets may be counted multiple times.
                for dst=1:nDest
                    % Note: when the receiving node is a member of the
                    % destination vector, that node will be removed
                    % from the destination vector within the transmit
                    % method and the returned node id will be non-zero
                    % Hence the "or" expression below
                    if pkt.mdst(dst) || (dst == nid)
                        flowDst(clock.tics,i,grp,dst) = ...
                            flowDst(clock.tics,i,grp,dst) + 1;
                    end
                end
            end
        end
        if (resetStall)
            stallCount = 0;
        end
        if (nid ~= 0) % nid is only non-zero if a pkt was transmitted to it
            nodeArrival(clock.tics,nid,grp) = ...
                nodeArrival(clock.tics,nid,grp) + 1;
            if (graphDelays)
                scale = nodeArrival(clock.tics,nid,grp);
                arrivalDelay(clock.tics,nid,grp) = ((scale - 1) * ...
                    arrivalDelay(clock.tics,nid,grp) + ...
                    (clock.tics - pkt.injtime)) / scale;
            end
        end
        
    end
    
    %%%%%%% Stage 5: Update the virtual queues if using dual gradients
    
    if (vqType == VQDefs.dualgrad)
        
        % Wait startupTime/1200 seconds for things to settle out
        startupTime = 0;
        
        if (clock.tics == startupTime)
            for i=1:nNodes
                node(i).startVQupdates();
            end
        end
        
        if (clock.tics >= startupTime + vqUpdateInterval)
            for i=1:nNodes
                node(i).estimateVQs(dgoption);
            end
            
            for i=1:nNodes
                node(i).updateVQs();
            end
        end
        
    end
    
    %%%%%% Analysis support: collect packet counts from each node
    if (graphPktCounts)
        for i=1:nNodes
            for j=1:nGrps
                packetCounts(clock.tics,i,j) = node(i).count(j);
            end
        end
    end
    
    % See if we are deadlocked and are no longer able to do anything
    stallCount = stallCount + 1;
    if (stallCount > hasStalledPeriod)
        % dump the various queue depths and break out of the loop
        % fprintf('Forwarding operations have deadlocked\n');
        %break;
    end
    
    fprintf('.');
    if (mod(clock.tics,100) == 0)
        fprintf(' %d\n',clock.tics);
    end
    
    % Advance the simulation clock
    clock.doTic();
    
end

%%%% Report the results
for grp = 1:nGrps
    
    fprintf('************** Begin Group %d ********************\n\n',grp);
    fprintf('     %s\n\n',groupNames{grp});
    
    nt = 0;
    for n = 1:nNodes
        nodeEnqueues(n) = node(n).nrcvd(grp);
        nt = nt + node(n).depth(grp);
    end
    lt = 0;
    for i = 1:nLinks
        lt = lt + link(i).depth(grp);
    end
    systemTotal = nt + lt + nodeEnqueues;
    
    fprintf('Total multicast packets sent: %d\n',pktsSent(grp));
    fprintf('Total multicast packets received: [');
    fprintf('%5d ',nodeEnqueues);
    fprintf(']\n');
    
    fprintf('Packet totals across all queues:  [');
    fprintf('%5d ',systemTotal);
    fprintf(']\n\n');
    
    fprintf('         Destination Node:   ');
    fprintf('%3d ',[node(:).cid]);
    fprintf('\n');
    
    
    fprintf('   Node totals:             [');
    fprintf('%3d ',nt);
    fprintf(']\n');
    
    for srcNode = 1:nNodes
        fprintf('      Queue depth node %3d: [', node(srcNode).cid);
        fprintf('%3d ',node(srcNode).depth(grp));
        fprintf(']\n');
    end
    
    fprintf('   Link totals:             [');
    fprintf('%3d ',lt);
    fprintf(']\n');
    
    fprintf('Max search depth: %d\n',maxDepth);
    if (dqa==DequeueAlg.netcoded)
        fprintf('Max NC span: %d\n',maxSpan);
    end
    fprintf('\n');
    
    if (vqType ~= VQDefs.none)
        
        vqnt = 0;
        for n = 1:nNodes
            vqnt = vqnt + node(n).vq(grp,:);
        end
        
        fprintf('      Destination Node:   ');
        fprintf('%3d ',[node(:).cid]);
        fprintf('\n');
        
        
        fprintf('   Node VQ totals:          [');
        fprintf('%3d ',ceil(vqnt));
        fprintf(']\n');
        
        for srcNode = 1:nNodes
            fprintf('      VQ depth at node %3d: [', node(srcNode).cid);
            fprintf('%3d ',ceil(node(srcNode).vq(grp,:)));
            fprintf(']\n');
        end
        
    end
    
    fprintf('************** End Group %d ********************\n\n\n',grp);
    
end

% Compile timelines and generate per-multicast group plots
xaxis = 0:0.1:(nIntervals/10)-0.1;

for grp=1:nGrps
    
    nodeThruput = zeros(nIntervals,1);
    plotLabels  = cell(nDest,1);
    
    kk = 0;
    for k=1:nDest
        if (sum(nodeArrival(:,k,grp)) > 0)
            
            kk   = kk + 1;
            j    = 1;
            jacc = 0.0;
            
            for i=1:maxTicks
                jacc = jacc + nodeArrival(i,k,grp);
                if (mod(i,aggInterval) == 0)
                    nodeThruput(j)    = jacc/aggNum;
                    j                 = j + 1;
                    jacc              = 0.0;
                end
            end
            
            % Looks like we have something to plot. If first time
            % through, start a new figure
            if (kk == 1)
                figure;
            end
            plot(xaxis,nodeThruput);
            plotLabels{kk} = node(k).name;
            hold on;
        end
    end
    
    if (kk > 0)
        
        xlim([plotStartTime,plotEndTime]);
        ylim([0,5]);
        legend(plotLabels(1:kk),'location','northeast');
        xlabel('Seconds');
        ylabel('Mbps');
        title(['Group throughput: ' groupNames{grp}]);
        
    end
    
    hold off;
end

% Compile timelines and generate per-receiver throughput plots

for dest=1:nDest
    
    nodeThruput    = zeros(nIntervals,1);
    aggNodeThruput = zeros(nIntervals,1);
    plotLabels     = cell(nGrps+1,1);
    
    kk = 0;
    for k=1:nGrps
        if (sum(nodeArrival(:,dest,k)) > 0)
            
            kk   = kk + 1;
            j    = 1;
            jacc = 0.0;
            
            for i=1:maxTicks
                jacc = jacc + nodeArrival(i,dest,k);
                if (mod(i,aggInterval) == 0)
                    nodeThruput(j)    = jacc/aggNum;
                    j                 = j + 1;
                    jacc              = 0.0;
                end
            end
            
            % Looks like we have something to plot. If first time
            % through, start a new figure
            if (kk == 1)
                figure;
            end
            plot(xaxis,nodeThruput);
            plotLabels{kk} = groupNames{k};
            hold on;
            aggNodeThruput = aggNodeThruput + nodeThruput;
        end
    end
    
    if (kk > 0)
        plot(xaxis,aggNodeThruput);
        plotLabels(kk+1) = {'Aggregate'};
        xlim([plotStartTime,plotEndTime]);
        ylim([0,5]);
        legend(plotLabels(1:kk+1),'location','east');
        xlabel('Seconds');
        ylabel('Mbps');
        title(['Traffic reaching ' node(dest).name]);
    end
    
    hold off;
end

% Compile timelines and generate per-receiver delay plots
if (graphDelays)
    for dest=1:nDest
        
        flowDelays = zeros(nIntervals,1);
        plotLabels = cell(nGrps+1,1);
        
        kk = 0;
        for k=1:nGrps
            % Must have packets for this group at this node
            if (sum(nodeArrival(:,dest,k)) > 0)
                
                kk   = kk + 1;
                j    = 1;
                jacc = 0.0;
                dacc = 0.0;
                for i=1:maxTicks
                    jacc = jacc + nodeArrival(i,dest,k);
                    dacc = dacc + arrivalDelay(i,dest,k);
                    if (mod(i,aggInterval) == 0)
                        if (jacc > 0)
                            flowDelays(j) = dacc/jacc;
                        else
                            flowDelays(j) = 0.0;
                        end
                        j                 = j + 1;
                        jacc              = 0.0;
                        dacc              = 0.0;
                    end
                end
                
                % Looks like we have something to plot. If first time
                % through, start a new figure
                if (kk == 1)
                    figure;
                end
                % Convert from clock tics to msec
                flowDelays = (1000 / ticsPerSec) * flowDelays;
                plot(xaxis,flowDelays);
                plotLabels{kk} = groupNames{k};
                hold on;
            end
        end
        
        if (kk > 0)
            xlim([plotStartTime,plotEndTime]);
            % pin the lower limit to 0, in case its not
            limsy=get(gca,'YLim');
            set(gca,'Ylim',[0 limsy(2)]);
            xlim([plotStartTime,plotEndTime]);
            legend(plotLabels(1:kk),'location','east');
            xlabel('Seconds');
            ylabel('msec');
            title(['End-to-end delay to ' node(dest).name]);
        end
        
        hold off;
    end
end

% Compile timelines and generate node packet counts

if (graphPktCounts)
    for nodeID=1:nNodes
        
        pktCnts    = zeros(nIntervals,1);
        plotLabels = cell(nGrps+1,1);
        
        kk = 0;
        for k=1:nGrps
            
            % Must have packets for this group at this node
            if (sum(packetCounts(:,nodeID,k)) > 0)
                
                kk   = kk + 1;
                j    = 1;
                jacc = 0.0;
                for i=1:maxTicks
                    jacc = jacc + packetCounts(i,nodeID,k);
                    if (mod(i,aggInterval) == 0)
                        pktCnts(j) = jacc/aggInterval;
                        j          = j + 1;
                        jacc       = 0.0;
                    end
                end
                % Looks like we have something to plot. If first time
                % through, start a new figure
                if (kk == 1)
                    figure;
                end
                plot(xaxis,pktCnts);
                plotLabels{kk} = groupNames{k};
                hold on;
            end
        end
        
        if (kk > 0)
            xlim([plotStartTime,plotEndTime]);
            % pin the lower limit to 0, in case its not
            limsy=get(gca,'YLim');
            set(gca,'Ylim',[0 limsy(2)]);
            xlim([plotStartTime,plotEndTime]);
            legend(plotLabels(1:kk),'location','east');
            xlabel('Seconds');
            ylabel('Packets');
            title(['Per group physical packets enqueued at ' ...
                node(nodeID).name]);
        end
        
        hold off;
    end
end

% per link, per group flow
if (graphLinkUsage)
    for lnk=1:nLinks
        
        linkThruput = zeros(nIntervals,1);
        plotLabels  = cell(nGrps,1);
        
        kk = 0;
        for grp=1:nGrps
            if (sum(flow(:,lnk,grp)) > 0)
                kk   = kk + 1;
                j    = 1;
                jacc = 0.0;
                
                for i=1:maxTicks
                    jacc = jacc + flow(i,lnk,grp);
                    if (mod(i,aggInterval) == 0)
                        linkThruput(j)    = jacc/aggNum;
                        j                 = j + 1;
                        jacc              = 0.0;
                    end
                end
                
                % Looks like we have something to plot.
                % If first time through, start a new figure
                if (kk == 1)
                    figure;
                end
                
                % add a tiny bit to the total throughput to get separation
                % if the line overlaps one of the destinations.
                plot(xaxis,linkThruput + 0.001);
                plotLabels{kk} = groupNames{grp};
                hold on;
                for dst=1:nDest
                    linkDestThruput = zeros(nIntervals,1);
                    if (sum(flowDst(:,lnk,grp,dst)) > 0)
                        kk = kk + 1;
                        graphIndex = 1;
                        tempTotal = 0.0;
                        for i=1:maxTicks
                            tempTotal = tempTotal + flowDst(i,lnk,grp,dst);
                            if (mod(i,aggInterval) == 0)
                                linkDestThruput(graphIndex) = ...
                                    tempTotal/aggNum;
                                graphIndex = graphIndex + 1;
                                tempTotal = 0.0;
                            end
                        end
                        
                        plot(xaxis,linkDestThruput);
                        plotLabels{kk} = sprintf('%d:%s, dest %d (%s)',...
                            grp, groupNames{grp}, dst, node(dst).name);
                        hold on;
                    end
                end
            end
        end
        
        if (kk > 0)
            xlim([plotStartTime,plotEndTime]);
            ylim([0,5]);
            legend(plotLabels(1:kk),'location','northeast');
            xlabel('Seconds');
            ylabel('Mbps');
            %title(['Link usage for ' linkNames{lnk}.name]);
            title(['Link usage for ' link(lnk).name]);
        end
        
        hold off;
    end
end

end

%
% Compute forwarding bias
%

function [] = computeFbias(link, topo)

nNodes = topo.nNodes;
nLinks = topo.nVirLinks;

% Setup the forwarding bias terms
hm = 0.5; % Hop count multiplier
d  = 1e6; % Deadend hop count value: essentially "do not send this way"

% Compute connectivity matrix
connMatrix = eye(topo.nNodes);

for i = 1:nLinks
    src = topo.virLinks(i,1);
    dst = topo.virLinks(i,2);
    
    srcNo = find(topo.bpfs(:)==src);
    dstNo = find(topo.bpfs(:)==dst);
    
    connMatrix(srcNo,dstNo) = 1;
    connMatrix(dstNo,srcNo) = 1;
end

for i = 1:nLinks
    % Compute the min dist to each destination using breadth-first search
    % from the head of the link
    src = link(i).src;
    srcNo = find(topo.bpfs(:)==src);
    
    % Inf entry means no path <= j hops between col and row nodes
    tmp = Inf * ones(nNodes);
    for j = 1:nLinks
        tmp1 = connMatrix^j;
        tmp1(tmp1==0) = Inf;
        tmp1(tmp1<Inf) = j;
        tmp2 = min(tmp, tmp1);
        % Check if all the entries are the same, if so then done
        if sum(sum(tmp2 == tmp))==nNodes^2
            break;
        end
        tmp = tmp2;
    end
    head2dests = tmp(srcNo,:);
    head2dests(srcNo) = 0;
    
    % Compute the min dist to each destination from the tail of the link
    % excluding use of the node at the head of the link
    adjConn = connMatrix;
    adjConn(srcNo,:) = 0;
    adjConn(:,srcNo) = 0;
    tmp = Inf * ones(nNodes);
    for j = 1:nLinks
        tmp1 = adjConn^j;
        tmp1(tmp1==0) = Inf;
        tmp1(tmp1<Inf) = j;
        tmp2 = min(tmp, tmp1);
        if sum(sum(tmp2 == tmp))==nNodes
            break;
        end
        tmp = tmp2;
    end
    dst = link(i).dst;
    dstNo = find(topo.bpfs(:)==dst);
    tail2dests = tmp(dstNo,:);
    tail2dests(dstNo) = 0;
    tail2dests(tail2dests==Inf) = d;
    
    % Difference is the gradient
    link(i).fbias = hm * (head2dests-tail2dests);
end
end
