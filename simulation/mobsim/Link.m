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

classdef Link < handle
    properties
        clock  % pointer to simulation-wide clock object
        lid    % Link ID
        src    % Link source node number from config file
        dst    % Link destination node number from config file
        name   % Link name
        node   % receiving node
        fifo   % fifo, only one
        tick   % Number of ticks left in current period
        period % Number of ticks between pkt releases to Node
        fbias  % forwarding bias
        nDest  % num destinations
    end
    methods
        function [ obj ] = Link ()
            obj = obj@handle();
        end
        
        function [] = Initialize (obj,clock,linkid,linkName,rcvnode,...
                maxFifoDepth,nDest,src,dst,startperiod)
            obj.clock  = clock;
            obj.lid    = linkid;
            obj.name   = linkName;
            obj.node   = rcvnode;
            obj.tick   = 0;
            obj.period = 0;
            obj.fifo   = Pktfifo(maxFifoDepth,nDest);
            obj.fbias  = zeros(1,nDest);
            obj.nDest  = nDest;
            obj.src    = src;
            obj.dst    = dst;
            obj.period = startperiod;
        end
        
        function [ value ] = isempty(obj)
            value = obj.fifo.isempty;
        end
        
        function [ value ] = isfull(obj)
            value = obj.fifo.isfull();
        end
        
        function [ qd ] = depth(obj,grp)
            qd = obj.fifo.depth(grp);
        end
        
        function [ pq ] = count(obj)
            pq = obj.fifo.count;
        end
        
        function enqueue(obj,pkt)
            obj.fifo.enqueue(pkt);
        end
        
        function [ pkt,success ] = dequeue(obj)
            [ pkt, success ] = obj.fifo.dequeue();
        end
        
        function [ resetStall, nid, pkt ] = transmit(obj)
            resetStall = false;
            nid        = 0;
            pkt        = [];
            obj.tick   = obj.tick - 1;
            if (obj.tick <= 0)
                % Move a packet from the link to its receiving node
                if (~obj.isempty())
                    pkt = obj.dequeue();
                    % Sent a packet reset tick, accounting for breakage
                    obj.tick = obj.tick + obj.period;
                    if (obj.node.rcvenqueue(pkt))
                        nid = obj.node.nid;
                    end
                    resetStall = true;
                else
                    % Didn't send packet, so increase tick by one
                    obj.tick = obj.tick + 1;
                end
            end
        end
        
    end
end


