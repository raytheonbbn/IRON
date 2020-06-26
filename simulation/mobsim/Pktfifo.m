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

classdef Pktfifo < handle
    properties
        fifo
        head
        tail
        vlen
        qlen
    end
    methods
        function [ obj ] = Pktfifo (npkts, ndest)
            obj      = obj@handle();
            obj.head = 1;
            obj.tail = 1;
            obj.qlen = npkts+1; % Bump this so tail is an empty slot
            obj.vlen = ndest;
            % two step assignment needed to preallocate array of Packets
            temp(obj.qlen) = Packet();
            obj.fifo = temp;
            for i=1:obj.qlen
                obj.fifo(i).init(0,zeros(1,obj.vlen),0,0);
            end
        end
        
        function [ value ] = isempty(obj)
            if (obj.head == obj.tail)
                value = true;
            else
                value = false;
            end
        end
        
        function [ value ] = isfull(obj)
            if (obj.count >= obj.qlen-1)
                value = true;
            else
                value = false;
            end
        end
        
        function [ qd ] = depth(obj, grp)
            qd = zeros(1,obj.vlen);
            if (obj.head <= obj.tail)
                for i=obj.head:obj.tail-1
                    if (obj.fifo(i).grp == grp)
                        qd = qd + obj.fifo(i).mdst;
                    end
                end
            else
                for i=obj.head:obj.qlen
                    if (obj.fifo(i).grp == grp)
                        qd = qd + obj.fifo(i).mdst;
                    end
                end
                for i=1:obj.tail-1
                    if (obj.fifo(i).grp == grp)
                        qd = qd + obj.fifo(i).mdst;
                    end
                end
            end
        end
        
        function [ pq ] = count(obj)
            pq = obj.tail - obj.head;
            if (pq < 0)
                pq = pq + obj.qlen;
            end
        end
        
        function enqueue(obj,pkt)
            
            % Store the pkt
            obj.fifo(obj.tail) = pkt;
            
            % Update the fifo internal state
            obj.tail = obj.tail + 1;
            if (obj.tail > obj.qlen)
                obj.tail = 1;
            end
            
            % Throw an error if we've wrapped around
            if (obj.tail == obj.head)
                error('Circular buffer failure\n');
            end
        end
        
        function [ pkt,success ] = dequeue(obj)
            
            if (obj.head == obj.tail)
                % Initialize the return variables
                pkt     = [];
                success = false;
                return;
            end
            
            % Retrieve the packet
            pkt     = obj.fifo(obj.head);
            success = true;
            
            % Update the internal fifo state
            % obj.fifo(obj.head).init(0,zeros(1,obj.vlen),0);
            obj.head = obj.head + 1;
            if (obj.head > obj.qlen)
                obj.head = 1;
            end
        end
        
    end
end


