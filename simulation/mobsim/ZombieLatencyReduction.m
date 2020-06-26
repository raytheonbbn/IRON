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

classdef ZombieLatencyReduction < handle
    properties
        clock         % Pointer to the simulation clock object
        node          % The parent node that holds the actual VQ arrays
        grp           % The unicast/multicast grp managed by this instance
        ndest % Number of backpressure destinations in the topology
        dynamics      % queue depth dynamics object for this instance
        fast_recovery % fast recovery object support this ZLR instance
        zlr_high_water_mark_pkts % Key operating parameters
        zlr_low_water_mark_pkts  % Key
        zlr_q_change_min_thresh_pkts_per_s %
        
    end
    methods
        function [ obj ] = ZombieLatencyReduction ()
            
            obj          = obj@handle();
            
            % Items that need to wait for initialization
            obj.grp           = 1;
            obj.ndest         = 1;
            obj.dynamics      = [];
            obj.fast_recovery = [];
            
            % Values that can be set now
            obj.zlr_high_water_mark_pkts           = ...
                ZLRDefs.kZLRHighWaterMarkPkts;
            obj.zlr_low_water_mark_pkts            = ...
                ZLRDefs.kZLRLowWaterMarkPkts;
            obj.zlr_q_change_min_thresh_pkts_per_s = ...
                ZLRDefs.kDefaultZLRQChangeMinThreshPktPerS;
        end
        
        function [] = Initialize(obj, clock, node, group)
            
            obj.clock = clock;      % Simulation wide clock
            obj.node  = node;       % Parent node, holding vq vectors
            obj.grp   = group;      % Group this instance supports
            obj.ndest = node.ndest; % For convenience
            
            dyn(obj.ndest) = QueueDepthDynamics();
            obj.dynamics = dyn;
            
            for i=1:obj.ndest
                obj.dynamics(i).Initialize(obj.clock,...
                    ZLRDefs.kDefaultZLRDynamicWindow,...
                    ZLRDefs.kDefaultDynamicWindowInitialSecs,...
                    ZLRDefs.kDefaultDynamicWindowLowerBoundSecs,...
                    ZLRDefs.kDefaultDynamicWindowUpperBoundSecs);
            end
            
            frec(obj.ndest) = FastRecovery();
            obj.fast_recovery = frec;
            for i=1:obj.ndest
                obj.fast_recovery(i).Initialize(obj.clock);
            end
            
        end
        
        function [] = DoZLREnqueueProcessing(obj, destlist, isZombie)
            for dest=1:obj.ndest
                if destlist(dest)
                    obj.DoPerBinEnqueueProcessing(dest, isZombie);
                end
            end
        end
        
        function [] = DoPerBinEnqueueProcessing(obj, dest, isZombie)
            % Get the number of pkts in the physical queue
            zlr_depth_pkts = obj.node.pq(obj.grp).depth(dest);
            
            if (ZLRDefs.kFastRecovery)
                obj.UpdateFastRecoveryStateOnEnqueue(dest, ...
                    zlr_depth_pkts);
            end
            obj.dynamics(dest).ProcessPktAdded(zlr_depth_pkts);
            % Note: the current algorithm doesn't enqueue zombies
            % since they are discarded in the BPF. Hence the code below
            % will never get called. Kept for historic purposes
            if (isZombie)
                obj.dynamics(dest).ProcessZombiePktAdded();
            end
            
        end
        
        function [] = UpdateFastRecoveryStateOnEnqueue(obj, ...
                dest, zlr_depth_pkts)
            
            if (obj.dynamics(dest).GetChangeRatePktsPerSec() > ...
                    obj.zlr_q_change_min_thresh_pkts_per_s)
                obj.fast_recovery(dest).deq_pkts = 0;
            end
            
            if (obj.fast_recovery(dest).fast_recovery_state == ...
                    FRDefs.QUEUE_DEPTH_DIP)
                if (zlr_depth_pkts > ...
                        ZLRDfs.kFastRecoveryStartThreshPkts)
                    obj.fast_recovery(dest).recovery_state = ...
                        FRDefs.RECOVERY;
                end
            end
            
        end
        
        function [] = DoZLRDequeueProcessing(obj, destlist, IsZombie)
            for dest=1:obj.ndest
                if destlist(dest)
                    obj.DoPerBinDequeueProcessing(dest, IsZombie);
                end
            end
        end
        
        function [] = DoPerBinDequeueProcessing(obj, dest, IsZombie)
            % Get the number of pkts in the physical queue
            zlr_depth_pkts = obj.node.pq(obj.grp).depth(dest);
            if (ZLRDefs.kFastRecovery)
                obj.UpdateFastRecoveryStateOnDequeue(dest);
            end
            obj.dynamics(dest).PktRemoved(zlr_depth_pkts);
            obj.DoZombieLatencyReduction(dest, IsZombie);
        end
        
        function [] = UpdateFastRecoveryStateOnDequeue(obj, ...
                dest, zlr_depth_bytes, IsZombie)
            
            % Get the number of pkts in the virtual queue
            zombie_depth_pkts = obj.node.vq(obj.grp,dest);
            
            % First see if it is time to reset the fast recovery state
            % machine to STEADY_STATE due to the "reset_time" amount having
            % passed since the last state change.
            
            if ((obj.fast_recovery(dest).recovery_state ~= ...
                    FRDefs.STEADY_STATE) && ...
                    ((obj.clock.now - obj.fast_recovery(dest).recovery_start_time) > ...
                    ZLRDefs.kFastRecoveryResetTime))
                obj.fast_recovery(dest).recovery_state = FRDefs.STEADY_STATE;
            end
            
            % If we are in steady state and this is the potential beginning
            % of a queue depth dip (our dequeue counter is 0), record the
            % time that this dip started (if it turns out to be a dip) and
            % the number of zombies present at the start o fthe potential
            % dip. Add to the count of dequeued bytes. The dequeued byte
            % and dequeue start time values will be usedto determine
            % whether this is a dip. The recovery zombie depth bytes will
            % be used as a part o fthe recovering should fast recoverykick
            % in aftre this dip.
            
            if ((obj.fast_recovery(dest).deq_pkts == 0) && ...
                    (obj.fast_recovery(dest).recovery_state == ...
                    FRDefs.STEADY_STATE))
                obj.fast_recovery(dest).deq_start_time = obj.clock.now;
                obj.fast_recovery(dest).recovery_zombie_depth_pkts = ...
                    zombie_depth_pkts;
            end
            obj.fast_recovery(dest).deq_pkts = ...
                obj.fast_recovery(dest).deq_pkts + 1;
            
            % If we're dequeueng a zombie, that's an indication to
            % assess whether we're now in a dip state (fast recovery won't
            % do anything if we haven't dequeued any zombies, so no need to
            % change the state unless/until we dequeue a zombie). If we are
            % in a dip (dequeue pkts is big enough over a small enough
            % dequeue time), then update the state machine accordingly. If
            % this was the first dip out of steady state, move to
            % the QUEUE_DEPTH_DIP state (from which we'll use fast
            % recovery). If we're alreday recovering or recovered from a
            % dip, then a second (or later) dip before a reset means we
            % want to consider this oscillatory -- i.e., no fast recovery
            % and increase the dynamic observation window
            
            if (IsZombie)
                if (((obj.clock.now - obj.fast_recovery(dest).deq_start_time) ...
                        < ZLRDefs.kFastRcoveryDipTheshTime) && ...
                        (obj.fast_recovery(dest).deq_pkts > ...
                        ZLRDefs.kFastRecoveryDipThreshPkts))
                    if (obj.fast_recovery(dest).recovery_state == ...
                            FRDefs.STEADY_STATE)
                        obj.fast_recovery(dest).recovery_state = ...
                            FRDefs.QUEUE_DEPTH_DIP;
                        obj.fast_recovery(dest).fast_recovery_start_time = ...
                            obj.clock.now;
                    elseif (obj.fast_recovery(dest).recovery_state >= ...
                            FRDefs.RECOVERY)
                        obj.fast_recovery(dest).recovery_state = ...
                            FRDefs.OSCILLATORY;
                        obj.fast_recovery(dest).fast_recovery_start_time = ...
                            obj.clock.now;
                    end
                end
            end
            
            % If we are not in fast recovery mode, adjust the ZLR floor
            % window -- i.e., the over how long into the past we should
            % look for the sake of ignoring queue depth spikes
            %
            % If we dequeued a zombie packet or have few non-zombies left,
            % then our observation window is probably too small. If we
            % haven't dequeued a zombie in a while, then we can probe a
            % smaller window.
            
            if (((obj.fast_recovery(dest).recovery_state == ...
                    FRDefs.STEADY_STATE) || ...
                    (obj.fast_recovery(dest).recovery_state == ...
                    FRDefs.SOSCILLATORY)) && ...
                    (zombie_depth_pkts > 0) && ...
                    (IsZombie || ...
                    (zlr_depth_bytes < obj.zlr_low_water_mark_pkts)))
                
                obj.dynamics(dest).IncrementMinPktsResetPeriod();
            end
            
            % Whenever we dequeue a non-zombie packet, check whether it's
            % time to shrink the observation window. Logic to determine
            % whether it's time and by how much to shrink the window is
            % inside the DecrementMinPktsResetPeriod
            
            if (~IsZombie)
                
                obj.dynamics(dest).DecrementMinPktsResetPeriod();
                if ((obj.fast_recovery(dest).recovery_state == ...
                        FRDefs.RECOVERY) && ...
                        (zombie_depth_pkts > ...
                        obj.fast_recovery(dest).recovery_zombie_depth_pkts))
                    obj.fast_recovery(dest).recovery_state = ...
                        FRDefs.RECOVERED;
                end
            end
        end
        
        function [] = DoZombieLatencyReduction(obj, dest, IsZombie)
            
            % Get the number of pkts in the physical queue
            zlr_depth_pkts = obj.node.pq(obj.grp).depth(dest);
            
            change_rate    = obj.dynamics(dest).GetChangeRatePktsPerSec();
            min_depth_pkts = obj.dynamics(dest).GetMinQueueDepthPkts();
            
            if (~IsZombie)
                if (((ZLRDefs.kFastRecovery) && ...
                        (obj.fastRecovery(dest).recovery_state == ...
                        FRDefs.RECOVERY) && ...
                        (zlr_depth_pkts >= obj.zlr_high_water_mark_pkts)) || ...
                        ((min_depth_pkts > obj.zlr_high_water_mark_pkts) ...
                        && (change_rate >= obj.zlr_q_change_min_thresh_pkts_per_s)))
                    % 1) this is not a zombie packet, 2) the non-zombie
                    % queue is long enough, and 3) the queue change rate
                    % is high enough -- so we add a zombie packet.
                    % Note that the triggering packet has already
                    % been dequeued
                    obj.node.vq(obj.grp,dest) = obj.node.vq(obj.grp,dest) + 1;
                end
            end
        end
    end
end
