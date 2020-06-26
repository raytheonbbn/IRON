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

classdef Node < handle
    properties
        clock  % Pointer to simulation-wide clock object
        nid    % Node ID (consecutive starting at 1)
        cid    % Node ID (from config file)
        name   % Node name (based on config node number)
        ngrps  % Number of multicast groups
        ndest  % Number of destinations
        maxq   % Maximum queue size
        pq     % Array of multicast physical packet queues, one per group
        vq     % Array of multicast virtual queue depths, one per group
        pqadv  % Advertisements (snapshot of the physical queue depths)
        vqadv  % VQ Advertisements (snapshot of the virtual queue depths)
        link   % Array of outbound links
        nrcvd  % Number of multicast packets received (node is destination)
        dqalg  % Dequeueing algorithm to use
        ofwd   % Boolean on whether to use opportunistic forwarding
        offlr  % Opportunistic forwarding floor
        hyst   % Hysteresis
        grpp   % gradient requires physical packets
        vqtype % Specifies the type of VQ alg being used (may be none)
        zlropt % ZLR packet selection/dequeueing option
        
        %      The following object array is for the ZLR VQ alg
        zlr    % Zombie Latency Reduction instances
        
        %        The following are parameters for the dual gradient VQ alg
        mu     % Weight between physical queues and virtual queues
        bigT   % Virtual queue update interval
        nbrD   % Used to remember what has been virtually sent to each nbr
        nuT    % Update averaging parameter
        inj    % Keep track of pkts injected during each VQ update interval
    end
    methods
        function [ obj ] = Node ()
            obj = obj@handle();
        end
        
        function [] = Initialize (obj,clock,nodeID,configID,nodeName,...
                nGrps,maxQueueDepth,nDest,dqa,of,flr,hysteresis,...
                grpp,vqtype,zlroption)
            
            obj.clock  = clock;
            obj.nid    = nodeID;
            obj.cid    = configID;
            obj.name   = nodeName;
            obj.ngrps  = nGrps;
            obj.ndest  = nDest;
            obj.maxq   = maxQueueDepth;
            obj.pq = [];
            for i=1:obj.ngrps
                obj.pq = [obj.pq, Pktmqueue(maxQueueDepth,nDest)];
            end
            
            obj.vq     = zeros(obj.ngrps,obj.ndest);
            obj.pqadv  = zeros(obj.ngrps,obj.ndest);
            obj.vqadv  = zeros(obj.ngrps,obj.ndest);
            obj.nrcvd  = zeros(obj.ngrps,1);
            obj.dqalg  = dqa;
            obj.ofwd   = of;
            obj.offlr  = flr;
            obj.hyst   = hysteresis;
            obj.grpp   = grpp;
            obj.vqtype = vqtype;
            obj.zlropt = zlroption;
            obj.inj    = zeros(obj.ngrps,obj.ndest);
            
            if (obj.vqtype == VQDefs.dualgrad)
                obj.mu = 0.2;
            else
                obj.mu = 1.0;
            end
            
            if (obj.vqtype == VQDefs.zlr)
                % Setup for the ZLR VQ alg
                
                z(obj.ngrps) = ZombieLatencyReduction();
                obj.zlr = z;
                
                for i=1:obj.ngrps
                    obj.zlr(i).Initialize(obj.clock, obj, i);
                end
            end
            
            if (obj.vqtype == VQDefs.dualgrad)
                % Default settings for the dual gradient VQ alg
                obj.bigT  = 12; % clock tics
                obj.nbrD  = zeros(1,1);
                obj.nuT   = 1;
            end
        end
        
        function [ value ] = isempty(obj,grp)
            value = obj.pq(grp).isempty;
        end
        
        function [ qd ] = depth(obj,grp)
            qd = obj.pq(grp).depth;
        end
        
        function [ cnt ] = count(obj,grp)
            cnt = obj.pq(grp).count;
        end
        
        function [] = advertise(obj)
            for grp=1:obj.ngrps
                obj.pqadv(grp,:) = obj.pq(grp).depth;
                obj.vqadv(grp,:) = obj.vq(grp,:);
            end
        end
        
        function [ md ] = maxdepth(obj,grp)
            md = max(obj.vq(grp,:) + obj.mu * obj.pq(grp).depth);
        end
        
        function [ sd ] = sumdepth(obj,grp)
            sd = sum(obj.vq(grp,:) + obj.mu * obj.pq(grp).depth);
        end
        
        % This method is called by link objects delivering a packet to a
        % node
        function [ rcvd ] = rcvenqueue(obj,pkt)
            
            rcvd = false;
            
            % ZLR-specific operations -- if we receive a zombie we
            % just drop it
            if (pkt.isZombie)
                return;
            end
            
            % See if pkt has this node as a destination
            % If so "receive" this packet and remove it as a destination
            
            if (pkt.mdst(obj.nid))
                pkt.mdst(obj.nid) = 0;
                % Record that this node received a packet
                obj.nrcvd(pkt.grp) = obj.nrcvd(pkt.grp) + 1;
                rcvd               = true;
            end
            
            % If remaining packet header is not empty, enqueue
            if (sum(pkt.mdst) ~= 0)
                obj.pq(pkt.grp).enqueue(pkt);
            end
        end
        
        % This method is only called by admission controllers
        function enqueue(obj,pkt)
            obj.pq(pkt.grp).enqueue(pkt);
            % Also, remember what was injected this round for VQ updating
            obj.inj(pkt.grp,:) = obj.inj(pkt.grp,:) + pkt.mdst;
        end
        
        function [ pkt, success ] = ...
                indexedPartialDequeue(obj, grp, index, grad)
            [pkt, success] = obj.pq(grp).indexedPartialDequeue(index,grad);
        end
        
        function [ pkt, success, index ] = peekHead(obj,grp)
            [pkt, success,index] = obj.pq(grp).peekHead();
        end
        
        function [ pkt, success, index, depth, span ] = ...
                peekBest(obj,grp,grad)
            [ pkt, success, index, depth, span ] = ...
                obj.pq(grp).peekBest(grad,obj.dqalg);
        end
        
        function [resetStall, maxDepth, maxSpan] = forward(obj)
            resetStall = false;
            maxDepth   = 0;
            maxSpan    = 0;
            
            done = false;
            while (~done)
                
                grad     = zeros(1,obj.ndest);
                bestGrad = 0;
                bestGrp  = 0;
                isZombie = false;
                
                %%%% Consider all groups
                for grp = 1:obj.ngrps
                    
                    %%%% Compute gradients for all outbound links
                    for lnk = 1:size(obj.link,2)
                        
                        % Only consider links that are 'available'
                        if (~obj.link(lnk).isfull)
                            
                            % delta = max((obj.pq(grp).depth - ...
                            %    obj.link(lnk).node.pqadv(grp,:) + ...
                            %    obj.link(lnk).fbias),0);
                            
                            % Observation: if opportunistic forwarding is
                            % not enabled, then using the above expression
                            % rather than the one below improves the
                            % performance of the groupBest algorithm
                            %
                            % --  Why? No real insights yet....
                            %
                            % The difference between the two is that the
                            % formulation below requires that there be
                            % actual pkts to send to a given destination
                            % within that group whereas the expression
                            % above can choose a grp based on the
                            % gradient contributions for each destination
                            % even if there are no packets to send for a
                            % given destination -- e.g., even when the
                            % gradient contribution for one or more
                            % destination(s) is only due to the forwarding
                            % bias terms
                            
                            % Non-vq implementation
                            % delta = max((obj.pq(grp).depth - ...
                            %    obj.link(lnk).node.pqadv(grp,:) + ...
                            %    obj.link(lnk).fbias),0) .* ...
                            %   (obj.pq(grp).depth > 0);
                            
                            deltabase = max((obj.vq(grp,:) + ...
                                obj.mu * obj.pq(grp).depth - ...
                                (obj.link(lnk).node.vqadv(grp,:) + ...
                                obj.mu * obj.link(lnk).node.pqadv(grp,:)) + ...
                                obj.link(lnk).fbias),0);
                            
                            if (obj.grpp)
                                delta = deltabase .* ...
                                    (obj.pq(grp).depth >  0);
                            else
                                delta = deltabase;
                            end
                            
                            passZombie = false;
                            if (obj.vqtype == VQDefs.zlr)
                                if (obj.zlropt == VQDefs.zlr_zdq_base)
                                    % If there are no physical pkts
                                    % supporting the positive gradient
                                    % terms, declare this candidate a 
                                    % zombie
                                    if (sum((delta .* obj.pq(grp).depth > 0)) == 0)
                                        passZombie = true;
                                    end
                                else
                                    % Construct gradient using only
                                    % destinations without physical pkts
                                    % but with virtual queues
                                    deltavq = deltabase .* ...
                                        (obj.pq(grp).depth <= 0) .* ...
                                        (obj.vq(grp,:) > 0);
                                    if (sum(deltavq) > sum(delta))
                                        passZombie = true;
                                        delta = deltavq;
                                    end
                                end
                            end
                            
                            % Apply hysteresis test, but only to
                            % non-zombie packets
                            if (passZombie == false)
                                delta = delta .* (delta > obj.hyst);
                            end
                            
                            testGrad = sum(delta);
                            % testGrad = max(delta);
                            if (testGrad > bestGrad)
                                isZombie = passZombie;
                                bestGrad = testGrad;
                                grad     = delta;
                                bestGrp  = grp;
                                tli      = lnk;
                            end
                        end
                    end
                end
                
                if (bestGrp == 0)
                    done = true; % Nothing available, all done
                end
                
                if (~done)
                    
                    grp  = bestGrp;
                    
                    if (isZombie) % Only true if using zlr
                        
                        % Make sure that we don't include destinations
                        % that don't have any zombies locally
                        grad = grad .* (obj.pq(grp).depth <= 0) .* ...
                            (obj.vq(grp,:) > 0);
                        
                        % Create a zombie packet to forward
                        pkt          = Packet();
                        pkt.mdst     = (grad > 0);
                        pkt.grp      = grp;
                        pkt.isZombie = true;
                        
                        % (Partially) dequeue a zombie
                        obj.vq(grp,:) = obj.vq(grp,:) - pkt.mdst;
                        
                        found = true;
                        
                    else
                        
                        % Make sure that we don't include destinations
                        % that don't have physical pkts enqueued
                        grad = grad .* (obj.pq(grp).depth > 0);
                        
                        % If opportunistic forwarding is enabled, see if
                        % any destinations with negative gradients can be
                        % included
                        
                        if (obj.ofwd)
                            
                            lnkdelta = zeros(size(obj.link,2),obj.ndest);
                            
                            %%%% Compute gradients for this group on
                            %%%% all outbound links, not just those that
                            %%%% are currently available
                            
                            for lnk = 1:size(obj.link,2)
                                
                                lnkdelta(lnk,:) = ((obj.vq(grp,:) + ...
                                    obj.mu * obj.pq(grp).depth) - ...
                                    (obj.link(lnk).node.vqadv(grp,:) + ...
                                    obj.mu * obj.link(lnk).node.pqadv(grp,:)) + ...
                                    obj.link(lnk).fbias);
                            end
                            
                            maxdelta = max(max(lnkdelta,[],1),obj.offlr);
                            
                            adjgrad  = (lnkdelta(tli,:) >= maxdelta) .* ...
                                (obj.pq(grp).depth > 0);
                            
                            ofwdset = (adjgrad > (grad > 0));
                            if (sum(ofwdset) > 0)
                                grad = grad + 0.01 * ofwdset;
                            end
                        end
                        
                        % Grab a copy of the destination header for the pkt
                        % that best supports the gradient
                        [pkt, found, index, tmpDepth, tmpSpan] = ...
                            obj.peekBest(grp, grad);
                        
                        if (found)
                            
                            % Sanity check: verify we don't have a pkt w/o
                            % destinations
                            if (sum(pkt.mdst) == 0)
                                fprintf('Bogus packet header at %s\n',...
                                    obj.name);
                            end
                            
                            % Exclude values for which the pkt is not destined
                            grad = grad .* pkt.mdst;
                            
                            % (Partially) dequeue the packet
                            pkt = obj.indexedPartialDequeue(grp,index,grad);
                            
                            if (tmpDepth > maxDepth)
                                maxDepth = tmpDepth;
                            end
                            
                            if (tmpSpan > maxSpan)
                                maxSpan = tmpSpan;
                            end
                        end
                        
                    end
                    
                    if (found)
                        
                        % Push the packet into the link
                        obj.link(tli).enqueue(pkt);
                        
                        if (obj.vqtype == VQDefs.zlr)
                            obj.zlr(pkt.grp).DoZLRDequeueProcessing(pkt.mdst,isZombie);
                        end
                        
                        resetStall = true;
                        
                    else
                        done = true;
                    end
                end
            end
        end
        
        function [] = estimateVQs(obj,dgoption)
            
            if (obj.vqtype ~= VQDefs.dualgrad)
                return;
            end
            
            % Only execute if its the end of the sampling interval
            if (mod(obj.clock.tics,obj.bigT) ~= 0)
                return;
            end
            
            % Clear the 'neighbor delta' matrix. We use this to remember
            % what will be (virtually) sent to each neighbor
            obj.nbrD = zeros(size(obj.link,2),obj.ngrps,obj.ndest);
            
            % Figure out how many packets *could* be sent on each link
            % given the (currently known) link rates and the length of
            % time between VQ updates (i.e., bigT)
            
            pktsAvailable = zeros(size(obj.link,2),1);
            for lnk = 1:size(obj.link,2)
                pktsAvailable(lnk) = obj.bigT / obj.link(lnk).period;
            end
            
            % Take a snapshot of the current virtual queue depths, as we'll
            % need this to keep track of packets that are (virtually)
            % dequeued
            
            vqcpy = obj.vq;
            
            done = false;
            while (~done)
                
                grad     = zeros(1,obj.ndest);
                bestGrad = 0;
                bestGrp  = 0;
                
                %%%% Consider all groups
                for grp = 1:obj.ngrps
                    
                    %%%% Compute gradients for all outbound links
                    for lnk = 1:size(obj.link,2)
                        
                        % Make sure this link has capacity available
                        if (pktsAvailable(lnk) > 0)
                            
                            % Compute the basic gradient, including the
                            % forwarding bias term
                            delta = vqcpy(grp,:) - ...
                                obj.link(lnk).node.vqadv(grp,:) +...
                                obj.link(lnk).fbias;
                            
                            % Make sure we have something to send, as the
                            % forwarding bias can create positive gradients
                            % without having anything to actually send
                            delta = delta .* (vqcpy(grp,:) > 0);
                            
                            % Only consider positive gradients
                            delta = max(delta,0);
                            
                            % Only consider forwarding virtual queues that
                            % are at least 1/mu times the physical queue
                            if (dgoption == VQDefs.dg_alt1)
                                delta = delta .* ...
                                    (vqcpy(grp,:) > (obj.pq(grp).depth /obj.mu));
                            end
                            
                            % Apply the hysteresis test
                            delta = delta .* (delta > obj.hyst);
                            
                            % Make sure the gradient values aren't too
                            % small. There seems to be a loss of precision
                            % somewhere in this process...
                            
                            testGrad = sum(delta);
                            if (testGrad > 1e-4)
                                
                                % See if this is the best gradient so far
                                if (testGrad > bestGrad)
                                    bestGrad = testGrad;
                                    grad     = delta;
                                    bestGrp  = grp;
                                    tli      = lnk;
                                end
                            end
                        end
                    end
                end
                
                if (bestGrp == 0)
                    done = true; % Nothing available, all done
                end
                
                if (~done)
                    
                    grp  = bestGrp;
                    
                    % Make sure we have the capacity to send this much
                    % on this link
                    pkt = min(grad,pktsAvailable(tli));
                    
                    % We don't have an actual packet queue so we can't do
                    % a dequeue. Instead, we just use a 'net-coding' model
                    % that allows us to grab a 'perfect' packet, skipping
                    % any group-best-packet search or similar operations
                    
                    % make sure we don't try to dequeue virtual packets
                    % we don't have
                    pkt = min(pkt,vqcpy(grp,:));
                    
                    % Now good to go. Remove the packet contributions
                    % from the queue
                    vqcpy(grp,:) = vqcpy(grp,:) - pkt;
                    
                    % Mimic the consumption of resources on the
                    % selected link
                    pktsAvailable(tli) = pktsAvailable(tli) - max(pkt);
                    
                    % Accumulate the contributions into a matrix we'll
                    % use to update the virtual queue depths when we're
                    % done with all of the nodes
                    
                    for k=1:size(pkt,2)
                        obj.nbrD(tli,grp,k) = ...
                            obj.nbrD(tli,grp,k) + pkt(1,k);
                    end
                end
            end
        end
        
        function [] = updateVQs(obj)
            
            if (obj.vqtype ~= VQDefs.dualgrad)
                return;
            end
            
            % Only execute if it's the end of the sampling interval
            if (mod(obj.clock.tics,obj.bigT) ~= 0)
                return;
            end
            
            % This loop captures the local injection of offered load (c_t)
            % plus the 'drain' aspects due to transmission of (virtual)
            % packets to nbr nodes
            
            % Add up what was sent from this node to all neighbors
            nsent = zeros(obj.ngrps,obj.ndest);
            for lnk = 1:size(obj.link,2)
                for grp=1:obj.ngrps
                    for dst=1:obj.ndest
                        nsent(grp,dst) = nsent(grp,dst) + ...
                            obj.nbrD(lnk,grp,dst);
                    end
                end
            end
            
            % Add in what was injected into this node, and subtract off
            % what was sent from this node to its neighbors -- scaled
            % by nu
            for grp=1:obj.ngrps
                obj.vq(grp,:) = obj.vq(grp,:) + ...
                    obj.nuT * (obj.inj(grp,:) - nsent(grp,:));
            end
            
            % obj.vq(grp,:) = max(obj.vq(grp,:),0);
            
            % This loop captures the inbound aspects of pseudo forwarding
            % by adding (virtually) forwarded packets to other nodes
            
            for lnk = 1:size(obj.link,2)
                nbr = obj.link(lnk).node;
                for grp=1:obj.ngrps
                    
                    % Exclude the neighbor from the set of destinations
                    % This models the receive process where the
                    % neighbor node consumes a copy of the packet,
                    % thereby removing itself from the destination list
                    
                    obj.nbrD(lnk,grp,nbr.nid) = 0;
                    
                    for dst=1:obj.ndest
                        nbr.vq(grp,dst) = nbr.vq(grp,dst) + ...
                            obj.nuT * obj.nbrD(lnk,grp,dst);
                    end
                    
                end
            end
            
            % Update combining parameter "nu". This will be the same at
            % all nodes once all nodes are processed: this is a local copy
            
            % if (clock > 120)
            %     obj.nuT = 1.0 / sqrt((1.0/obj.nuT^2) + 1.0);
            %     obj.nuT = 1.0 / sqrt(clock/120);
            % end
            
            %if (obj.clock.tics > 12000)
            if (obj.clock.tics > 12000)
                obj.nuT = 1.0 / sqrt((1.0/obj.nuT^2) + 1.0);
            end
            
            % Reset the injected packet count for the next vq update round
            obj.inj = zeros(obj.ngrps,obj.ndest);
            
            % Make sure the combining parameter is set for use of VQs
            % obj.mu  = 0.2;
        end
        
        % Initialize the injected pkt count for the next set of vq updates
        function [] = startVQupdates(obj)
            if (obj.vqtype == VQDefs.dualgrad)
                obj.inj = zeros(obj.ngrps,obj.ndest);
            end
        end
        
    end
end
