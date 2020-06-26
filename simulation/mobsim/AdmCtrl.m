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

classdef AdmCtrl < handle
    properties
        clock % simulation wide clock
        cid   % Controller ID
        name  % Controller name
        node  % node into which multicast packet are to be injected
        grp   % multicast group
        mdst  % multicast header specifying destinations
        kval  % K
        maxr  % Maximum transmission rate
        next  % next admission control time
        strt  % admission control start time
        fnsh  % admission control finish time
        acra  % admission control reporting algorithm
        pri   % flow priority
        seq   % sequence number
    end
    methods
        function [ obj ] = AdmCtrl()
            obj = obj@handle();
        end
        
        function [] = Initialize (obj, clock, ctlid, ctlName, node, grpid, ...
                dhdr, K, acra, pri)
            obj.clock = clock;
            obj.cid   = ctlid;
            obj.name  = ctlName;
            obj.node  = node;
            obj.grp   = grpid;
            obj.mdst  = dhdr;
            obj.kval  = K;
            obj.maxr  = sqrt(K) * obj.clock.tps; % Max rate
            obj.acra  = acra;
            obj.next  = 0;
            obj.pri   = pri;
            obj.seq   = 1;
        end
        
        function [ pktsSent, grp ] = admit(obj)
            
            pktsSent = 0;
            grp      = 0;
            
            if (obj.clock.tics < obj.strt) || (obj.clock.tics > obj.fnsh)
                return;
            end
            
            % If we haven't initialized the next starting time, do so now
            if (obj.next == 0)
                obj.next = obj.clock.tics;
            end
            
            % If the next time to send is before the next clock period
            % See if we can send pkts to the specified multicast group
            
            if (obj.next <= (obj.clock.tics + 1))
                
                % If we've already slipped, make sure the next transmission
                % time is now
                if (obj.next < obj.clock.tics)
                    obj.next = obj.clock.tics;
                end
                
                % Retrieve the queue depth parameter
                if (obj.acra == ACDefs.max)
                    % Use maximum virtual queue depth
                    Q = obj.node.maxdepth(obj.grp);
                elseif (obj.acra == ACDefs.sum)
                    % Use sum of virtual queue depths
                    Q = obj.node.sumdepth(obj.grp);
                else % if (obj.acra == ACDefs.avg)
                    % Use average of non-zero virtual queue depths
                    Q = obj.node.avgdepth(obj.grp);
                end
                
                % Determine a send rate. kval is in units of
                % pkts^2 / second. Send rate is in units of
                % pkts/sec
                
                if (Q > 0)
                    sendRate = floor(obj.pri * obj.kval / Q);
                else
                    sendRate = obj.maxr;
                end
                
                % Test code: limit the dynamics
                % if (sendRate > 1200)
                % 	  sendRate = 1200;
                % end
                
                % Determine the delay between packets at the specified rate
                xmitDelay = obj.clock.tps / sendRate;
                
                % Want to send just enough packets to get us past
                % the next time to send (clock + 1)
                pktsToSend = ceil(((obj.clock.tics + 1) - obj.next ) / xmitDelay);
                if (pktsToSend >= 1)
                    for i=1:pktsToSend
                        pkt = Packet();
                        pkt.init(obj.grp,obj.mdst,obj.clock.tics,obj.seq);
                        obj.node.enqueue(pkt);
                        obj.seq = obj.seq + 1;
                        obj.next = obj.next + xmitDelay;
                    end
                end
                
                pktsSent = pktsToSend;
                grp      = obj.grp;
                
            end
        end
    end
end

