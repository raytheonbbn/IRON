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

classdef Pktmqueue < handle
    properties
        queue % Holds the pkt headers for a multicast group
        head  % Holds the head of the queue
        tail  % Holds the tail of the queue
        qlen  % Maximum length of the queue
        vlen  % Number of nodes (number of destinations)
        depth % Running accumulator of multicast queue depths
    end
    methods
        function [ obj ] = Pktmqueue (npkts, ndest)
            obj       = obj@handle();
            obj.qlen  = npkts;
            obj.vlen  = ndest;
            temp(obj.qlen) = Packet();
            obj.queue = temp;
            for i=1:obj.qlen
                obj.queue(i).init(0,zeros(1,obj.vlen),0, 0);
            end
            obj.head  = 1;
            obj.tail  = 1;
            obj.depth = zeros(1,obj.vlen);
        end
        
        function [ value ] = isempty(obj)
            if (obj.head == obj.tail)
                value = true;
            else
                value = false;
            end
        end
        
        function [ pq ] = count(obj)
            pq = obj.tail - obj.head;
            if (pq < 0)
                pq = pq + obj.qlen;
            end
        end
        
        function enqueue(obj,pkt)
            
            obj.queue(obj.tail) = pkt;
            obj.tail = obj.tail + 1;
            
            if (obj.tail > obj.qlen)
                obj.tail = 1;
            end
            
            if (obj.tail == obj.head)
                error('Circular buffer failure\n');
            end
            
            obj.depth = obj.depth + pkt.mdst;
        end
        
        function [ pkt, success ] = dequeue(obj)
            
            if (obj.head == obj.tail)
                % Initialize the return variables
                pkt     = [];
                success = false;
                return;
            end
            
            % Grab the packet at the head
            success = true;
            %            pkt     = obj.queue(obj.head).copy();
            pkt     = obj.queue(obj.head);
            
            %             % Clear the packet currently at the head
            %             obj.queue(obj.head).mdst = zeros(1,obj.vlen);
            
            % Advance the head index
            obj.head = obj.head + 1;
            if (obj.head > obj.qlen)
                obj.head = 1;
            end
            
            obj.depth = obj.depth - pkt.mdst;
            
        end
        
        function [ pkt, success ] = indexedDequeue(obj, index)
            fullGrad       = ones(1,obj.vlen);
            [pkt, success] = indexedPartialDequeue(obj, index, fullGrad);
        end
        
        % Note: partial dequeues and peeks alway return copies of the pkts
        % This is because Packet objects are store as pointers, so we
        % want to be careful we don't end up indavertently modifying a
        % packet in a way that affects other parts of the code.
        
        function [ pkt, success ] = indexedPartialDequeue(obj, indexSet, grad)
            
            % Only do this if we have a packet enqueued
            if (obj.head == obj.tail)
                % Assign sensical return variables for a failure
                pkt     = [];
                success = false;
                return;
            end
            
            % Prep the gradient
            grad = grad > 0;
            
            % We need to walk the indexSet in the same order it was created
            % If we consume a packet, we need to adjust the indexSet values
            
            nConsumed = 0;
            
            % Determine how many packets we are combining using net coding
            nPkts = sum(indexSet > 0);
            for j=1:nPkts
                
                index = indexSet(j) - nConsumed;
                if (index < 1)
                    index = index + obj.qlen;
                end
                
                % First a simple sanity check on the index
                if ((index < 1) || (index > obj.qlen))
                    error('Major failure 1 in indexedPartialDequeueNC\n');
                end
                
                % Now make sure the index is between the head and the tail
                % accounting for circular buffer indexing
                
                %  1 ------------------------------------------------ qlen
                %    not okay -- Head ---- okay ---- Tail -- not okay
                %        okay -- Tail -- not okay -- Head -- okay
                
                if ((obj.head < obj.tail) && ...
                        ((index < obj.head) || (index >= obj.tail))) || ...
                        ((obj.head > obj.tail) && ...
                        ((index < obj.head) && (index >= obj.tail)))
                    error('Major failure 2 in indexedPartialDequeueNC\n');
                end
                
                % If this is the first packet from the index set, make a
                % copy to use as the return object, (this also grabs
                % the injection time for the oldest packet)
                
                if (j == 1)
                    pkt      = obj.queue(index).copy();
                    pkt.mdst = zeros(1,obj.vlen);
                end
                
                % Can now (partially) pull the pkt
                success   = true;
                intersect = grad & obj.queue(index).mdst;
                pkt.mdst  = pkt.mdst | intersect;
                grad      = grad - intersect;
                
                % Trim the enqueued packet based on what we're pulling
                obj.queue(index).mdst = obj.queue(index).mdst - intersect;
                
                % If this consumes the packet, pull it from the queue.
                if (sum(obj.queue(index).mdst) == 0)
                    
                    % If index is equal to the head, simply move the head
                    if (index == obj.head)
                        obj.head = obj.head + 1;
                        if (obj.head > obj.qlen)
                            obj.head = 1;
                        end
                        
                        % Otherwise bubble out the removed pkt towards the tail
                        % (could be even more efficient, but this should be
                        % plenty fast enough as-is since we're just copying
                        % pointers)
                        
                    else
                        % Update the number consumed tracker as needed to
                        % correct the indexSet indices. This is only needed
                        % if we bubble a packet out of the middle
                        nConsumed = nConsumed + 1;
                        
                        if (index == obj.tail)
                            % just need to update the tail
                            
                        elseif (index < obj.tail)
                            % tail hasn't wrapped, so a simple copy works
                            obj.queue(index:obj.tail-1) = obj.queue(index+1:obj.tail);
                            
                        else
                            % tail has wrapped, need to do this in 3 steps
                            obj.queue(index:obj.qlen-1) = obj.queue(index+1:obj.qlen);
                            obj.queue(obj.qlen)         = obj.queue(1);
                            if (obj.tail > 1)
                                obj.queue(1:obj.tail-1) = obj.queue(2:obj.tail);
                            end
                        end
                        
                        % In all bubble out cases, update the tail index
                        obj.tail = obj.tail - 1;
                        if (obj.tail == 0)
                            obj.tail = obj.qlen;
                        end
                        
                    end
                end
            end
            
            obj.depth = obj.depth - pkt.mdst;
        end
        
        function [ pkt, success, index ] = peekHead(obj)
            if (obj.head ~= obj.tail)
                pkt     = obj.queue(obj.head).copy();
                success = true;
                index   = obj.head;
            else
                pkt     = [];
                success = false;
                index   = 0;
            end
        end
        
        function [ pkt, success, index, depth, span ] = peekBest(obj,grad,dqa)
            if (dqa == DequeueAlg.fifo)
                [ pkt, success, index, depth, span ] = peekBestFifo(obj,grad);
            elseif (dqa == DequeueAlg.lifo)
                [ pkt, success, index, depth, span ] = peekBestLifo(obj,grad);
            elseif (dqa == DequeueAlg.netcoded)
                [ pkt, success, index, depth, span ] = peekBestNetCoded(obj,grad);
            elseif ((dqa == DequeueAlg.groupbest) || ...
                    (dqa == DequeueAlg.groupbestplus))
                [ pkt, success, index, depth, span ] = peekBestGroupBest(obj,grad);
            else
                fprintf('Unknown peek method\n');
            end
        end
        
        function [ pkt, success, indexSet, depth, span ] = peekBestFifo(obj,grad)
            
            % Span and depth will always be zero with this method
            depth    = 0;
            span     = 0;
            
            % Only do this if we have a packet enqueued
            if (obj.head == obj.tail)
                
                % Finish assigning the remaining return variables
                pkt      = [];
                success  = false;
                indexSet = zeros(1,obj.vlen);
                
                return;
            end
            
            % Initial setup
            
            % Get the number of packets queued
            npq  = obj.tail - obj.head;
            % Handle circular buffer properly
            if (npq < 0) % Handle circular buffer properly
                npq = npq + obj.qlen;
            end
            
            % Clip the gradient to only look for non-negative transfers
            grad = max(grad,0);
            
            setPos = 0;
            
            % Search through the queue from head to tail looking for the
            % first intersection
            for i=1:npq
                
                j = obj.head + i - 1;
                % Handle wrap around
                if (j > obj.qlen)
                    j = j - obj.qlen;
                end
                
                intersect = grad & obj.queue(j).mdst;
                if (sum(intersect) > 0)
                    
                    % If we are here, we have a packet with at least one
                    % of the target destinations
                    success = true;
                    
                    % Remember the packet index for this intersection
                    setPos           = setPos + 1;
                    indexSet(setPos) = j;
                    
                    % Define the packet we return
                    pkt      = obj.queue(j).copy();
                    pkt.mdst = intersect;
                    
                    break;
                    
                end
            end
        end
        
        function [ pkt, success, indexSet, depth, span ] = peekBestLifo(obj,grad)
            
            % Span and depth will always be zero with this method
            depth = 0;
            span  = 0;
            
            % Only do this if we have a packet enqueued
            if (obj.head == obj.tail)
                
                % Finish assigning the remaining return variables
                pkt      = [];
                success  = false;
                indexSet = zeros(1,obj.vlen);
                
                return;
            end
            
            % Initial setup
            
            % Get the number of packets queued
            npq  = obj.tail - obj.head;
            % Handle circular buffer properly
            if (npq < 0) % Handle circular buffer properly
                npq = npq + obj.qlen;
            end
            
            % Clip the gradient to only look for non-negative transfers
            grad = max(grad,0);
            
            setPos = 0;
            
            % Search through the queue from tail to head looking for the
            % first intersection
            for i=1:npq
                
                j = obj.tail - i;
                % Handle wrap around
                if (j < 1)
                    j = j + obj.qlen;
                end
                
                intersect = grad & obj.queue(j).mdst;
                if (sum(intersect) > 0)
                    
                    % If we are here, we have a packet with at least one
                    % of the target destinations
                    success = true;
                    
                    % Remember the packet index for this intersection
                    setPos           = setPos + 1;
                    indexSet(setPos) = j;
                    
                    % Define the packet we return
                    pkt      = obj.queue(j).copy();
                    pkt.mdst = intersect;
                    
                    break;
                    
                end
            end
            
        end
        
        function [ pkt, success, indexSet, depth, span ] = peekBestNetCoded(obj,grad)
            
            % Span and depth may be non-zero with this method
            depth = 0;
            span  = 0;
            
            % Only do this if we have packets enqueued
            if (obj.head == obj.tail)
                % Finish assigning return variables
                pkt      = [];
                indexSet = zeros(1,obj.vlen);
                success  = false;
                return;
            end
            
            % Do the rest of the setup
            
            % Get the number of packets in the queue
            npq = obj.tail - obj.head;
            % Handle circular buffer properly
            if (npq < 0) % Handle circular buffer indexing
                npq = npq + obj.qlen;
            end
            
            % Clip the gradient to only look for non-negative transfers
            grad = grad > 0;
            
            setPos = 0;
            
            % Search through the queue looking for a covering
            for i=1:npq
                
                j = obj.head + i - 1;
                % Handle wrap around
                if (j > obj.qlen)
                    j = j - obj.qlen;
                end
                
                intersect = grad & obj.queue(j).mdst;
                if (sum(intersect) > 0)
                    
                    % If we are here, we have at least one supporting packet
                    success = true;
                    
                    % Remember the packet index for this intersection
                    setPos           = setPos + 1;
                    indexSet(setPos) = j;
                    
                    if (setPos == 1)
                        pkt = obj.queue(j).copy();
                    end
                    
                    % Add the intersection to the net coded packet we return
                    pkt.mdst = pkt.mdst | intersect;
                    
                    % Remove this intersection from the gradient
                    grad = grad - intersect;
                    
                    % If nothing left, we are done
                    if sum(grad) == 0
                        break;
                    end
                    
                end
            end
            
            if (setPos > 0)
                depth = indexSet(setPos) - obj.head;
                if (depth < 0)
                    depth = depth + obj.qlen;
                end
                span = indexSet(setPos) - indexSet(1);
                if (span < 0)
                    span = span + obj.qlen;
                end
            end
        end
        
        function [ pkt, success, indexSet, depth, span ] = peekBestGroupBest(obj,grad)
            
            % Assigning return variables in case we fail, either
            % immediately or after the search
            pkt      = [];
            success  = false;
            indexSet = zeros(1,obj.vlen);
            depth    = 0;
            span     = 0;
            
            % Only do this if we have a packet enqueued
            if (obj.head == obj.tail)
                
                return;
            end
            
            % Initial setup
            
            % Get the number of packets queued
            npq  = obj.tail - obj.head;
            % Handle circular buffer properly
            if (npq < 0) % Handle circular buffer properly
                npq = npq + obj.qlen;
            end
            
            % Clip the gradient to only look for non-negative transfers
            grad = max(grad,0);
            % grad = grad > 0; % Uncomment this to use simple count
            
            % Search through the queue looking for the best match
            bestMatch = 0;
            bestIndex = 0;
            
            for i=1:npq
                j = obj.head + i - 1;
                % Handle wrap around
                if (j > obj.qlen)
                    j = j - obj.qlen;
                end
                
                % Match metric is a dot product. This allows weighting
                % packet selection based on gradient pressure
                thisMatch = grad * obj.queue(j).mdst';
                if (thisMatch > bestMatch)
                    bestMatch = thisMatch;
                    bestIndex = j;
                end
            end
            
            if (bestIndex > 0)
                pkt         = obj.queue(bestIndex).copy();
                pkt.mdst    = (grad > 0) .* pkt.mdst;
                success     = true;
                indexSet(1) = bestIndex;
                depth       = bestIndex - obj.head;
                if (depth < 0)
                    depth = depth + obj.qlen;
                end
                span        = 1;
            else
                return;
            end
        end
        
    end
end
