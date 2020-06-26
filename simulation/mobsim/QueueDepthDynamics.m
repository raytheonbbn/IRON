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

classdef QueueDepthDynamics < handle
    properties
        min_pkts_reset_period             %
        min_pkts_rotate_period            %
        last_changed_min_pkts_period      %
        zombie_pkts_last_added            %
        dynamic_min_depths_window         %
        min_pkts_reset_period_lower_bound %
        min_pkts_reset_period_upper_bound %
        net_pkts                          %
        min_pkts                          %
        zombie_pkts_added                 %
        last_reset_net                    %
        last_reset_min                    %
        current_idx_net                   %
        current_idx_min                   %
        initializing_net                  %
        net_sum                           %
        overall_min                       %
        total_zombies_added               %
        clock                             % pointer to the sim clock
    end
    methods
        function [ obj ] = QueueDepthDynamics ()
            
            nSegs = QDDDefs.kNumQDDSegments; %
            
            obj                                   = obj@handle();
            obj.min_pkts_reset_period             = 0;
            obj.min_pkts_rotate_period            = 0;
            obj.last_changed_min_pkts_period      = 0;
            obj.zombie_pkts_last_added            = 0;
            obj.dynamic_min_depths_window         = false;
            obj.min_pkts_reset_period_lower_bound = 0;
            obj.min_pkts_reset_period_upper_bound = 0;
            obj.net_pkts                          = zeros(nSegs,1);
            obj.min_pkts                          = double(intmax('int32')) * ones(nSegs,1);
            obj.zombie_pkts_added                 = zeros(nSegs,1);
            obj.last_reset_net                    = zeros(nSegs,1);
            obj.last_reset_min                    = 0;
            obj.current_idx_net                   = 1; % Adjusted for 1 ref
            obj.current_idx_min                   = 1; % Adjusted for 1 ref
            obj.initializing_net                  = true;
            obj.net_sum                           = 0;
            obj.overall_min                       = 0;
            obj.total_zombies_added               = 0;
        end
        
        function [] = Initialize(obj, clock, dynamic_window, ...
                initial_window_secs, window_lower_bound, ...
                window_upper_bound)
            
            obj.clock                             = clock;
            obj.dynamic_min_depths_window         = dynamic_window;
            obj.min_pkts_reset_period             = initial_window_secs;
            obj.min_pkts_reset_period_lower_bound = window_lower_bound;
            obj.min_pkts_reset_period_upper_bound = window_upper_bound;
            obj.last_changed_min_pkts_period      = obj.clock.now;
            obj.zombie_pkts_last_added            = obj.clock.now;
        end
        
        function [] = ProcessPktAdded(obj, new_depth)
            obj.CheckReset();
            if ((intmax('int32') - 1) < obj.net_pkts(obj.current_idx_net))
                % Just leave it at the max rate to avoid overflow
                obj.net_pkts(obj.current_idx_net) = intmax('int32');
            else
                obj.net_pkts(obj.current_idx_net) = ...
                    obj.net_pkts(obj.current_idx_net) + 1;
            end
            
            if (new_depth < obj.min_pkts(obj.current_idx_min))
                obj.min_pkts(obj.current_idx_min) = new_depth;
            end
        end
        
        function [] = ProcessZombiePktAdded(obj)
            if ((intmax('int32') - 1) < ...
                    obj.zombie_pkts_added_pkts(obj.curr_idx_min))
                % Just leave it at the max to avoid overflow
                obj.zombie_pkts_added(obj.curr_idx_min) = intmax('int32');
            else
                obj.zombie_pkts_added(obj.curr_idx_min) = ...
                    obj.zombie_pkts_added(obj.curr_idx_min) + 1;
            end
            obj.zombie_pkts_last_added = obj.clock.now;
        end
        
        function [] = PktRemoved(obj, new_depth)
            obj.CheckReset();
            if ((intmin('int32') + 1) > obj.net_pkts(obj.current_idx_net))
                % Just leave it at the min rate to avoid wrap around
                obj.net_pkts(obj.current_idx_net) = intmin('int32');
            else
                obj.net_pkts(obj.current_idx_net) = ...
                    obj.net_pkts(obj.current_idx_net) - 1;
            end
            
            if (new_depth < obj.min_pkts(obj.current_idx_min))
                obj.min_pkts(obj.current_idx_min) = new_depth;
            end
        end
        
        function [rate] = GetChangeRatePktsPerSec(obj)
            
            if (obj.initializing_net)
                rate = intmax('int32');
                return;
            end
            
            % Compute the change rate, which is the net pkts over all
            % segments (all except the current segment is already cached in
            % net_sum) divided by the time over whihc these values are
            % valid
            
            % The next index in the buffer is currently the oldest
            oldest = obj.last_reset_net(obj.NextQDDIndex(obj.current_idx_net));
            if (obj.clock.now <= oldest)
                % This is highly unlikely if not impossible, since we will
                % be in the "initializing_net" period for a full
                % kChangeRateResetPeriod. However, this extra check removes
                % any possibility of a divide by 0 error
                intmax('int32');
                return;
            end
            
            rate = (obj.net_sum - obj.net_pkts(obj.current_idx_net)) ...
                / (obj.clock.now - oldest);
        end
        
        function [min] = GetMinQueueDepthPkts(obj)
            min = obj.overall_min;
            if (obj.min_pkts(obj.current_idx_min) < obj.overall_min)
                min = obj.min_pkts(obj.current_idx_min);
            end
            if (min < (obj.total_zombies_added + ...
                    obj.zombie_pkts_added(obj.current_idx_min)))
                min = 0;
            else
                min = min - obj.total_zombies_added;
                min = min - obj.zombie_pkts_added(obj.current_idx_min);
            end
        end
        
        function [] = IncrementMinPktsResetPeriod(obj)
            if ((~obj.dynamic_min_depths_window) || ...
                    ((obj.clock.now - obj.last_changed_min_pkts_period) < ...
                    QDDDefs.kIncrMinPktsPeriod))
                return;
            end
            if ((obj.min_pkts_reset_period + ...
                    QDDDefs.kIncrMinPktsPeriodDelta) >= ...
                    obj.min_pkts_reset_period_upper_bound)
                obj.min_pkts_reset_period = ...
                    obj.min_pkts_reset_period_upper_bound;
            else
                obj.min_pkts_reset_period = obj.min_pkts_reset_period + ...
                    QDDDefs.kMinPktsResetPeriodDelta;
            end
            obj.min_pkts_rotate_period = min_bytes_reset_period ...
                / QDDDefs.kNumQDDSegments;
            obj.last_changed_min_pkts_period = obj.clock.now;
        end
        
        function [] = DecrementMinPktsResetPeriod(obj)
            if (~obj.dynamic_min_depths_window)
                return;
            end
            if (((obj.clock.now - obj.last_changed_min_pkts_period) < ...
                    QDDDefs.kDecrMinPktsPeriod) || ...
                    ((obj.clock.now - obj.zombie_pkts_last_added) < ...
                    QDDDefs.kDecrMinPktsTimeSinceZombieSent))
                return;
            end
            
            if ((obj.min_pkts_reset_period - ...
                    QDDDefs.kMinPktsResetPeriodDelta) <= ...
                    obj.min_pkts_reset_period_lower_bound)
                obj.min_pkts_reset_period = obj.min_pkts_reset_period_lower_bound;
            else
                obj.min_pkts_reset_period = obj.min_pkts_reset_period - ...
                    QDDDefs.kMinPktsResetPeriodDelta;
            end
            
            obj.min_pkts_rotate_period = min_bytes_reset_period ...
                / QDDDefs.kNumQDDSegments;
            obj.last_changed_min_pkts_period = obj.clock.now;
        end
        
        function [] = CheckReset(obj)
            % Reset and move the circular buffer along once every
            % 1/kNumQDDSegments seconds
            
            if ((obj.clock.now - obj.last_reset_net(obj.current_idx_net)) > ...
                    QDDDefs.kChangeRateRotatePeriod)
                if (obj.current_idx_net == QDDDefs.kNumQDDSegments)
                    % We've now filled an entire buffer. We have sufficient
                    % data to start returning it
                    obj.initializing_net = false;
                end
                
                next_idx = obj.NextQDDIndex(obj.current_idx_net);
                
                obj.net_sum = obj.net_sum + obj.net_pkts(obj.current_idx_net) - ...
                    obj.net_pkts(next_idx);
                obj.current_idx_net = next_idx;
                
                obj.net_pkts(obj.current_idx_net) = 0;
                obj.last_reset_net(obj.current_idx_net) = obj.clock.now;
            end
            
            if ((obj.clock.now - obj.last_reset_min) > ...
                    obj.min_pkts_rotate_period)
                next_idx = obj.NextQDDIndex(obj.current_idx_min);
                % Update the cached sum, since we'll have a new current
                % segment to be excluded
                obj.total_zombies_added = ...
                    obj.total_zombies_added + ...
                    obj.zombie_pkts_added(obj.current_idx_min) - ...
                    obj.zombie_pkts_added(next_idx);
                
                obj.current_idx_min = next_idx;
                obj.min_pkts(obj.current_idx_min) = intmax('int32');
                obj.zombie_pkts_added(obj.current_idx_min) = 0;
                
                % Update the cached minimum, since we'll have a new current
                % segment to be excluded
                
                obj.overall_min = intmax('int32');
                % Loop goes here
                idx = obj.NextQDDIndex(obj.current_idx_min);
                while (idx ~= obj.current_idx_min)
                    if (obj.min_pkts(idx) < obj.overall_min)
                        obj.overall_min = obj.min_pkts(idx);
                    end
                    idx = obj.NextQDDIndex(idx);
                end
                
                obj.last_reset_min = obj.clock.now;
            end
        end
        
        function [next] = NextQDDIndex(~,arg)
            next = mod(arg,QDDDefs.kNumQDDSegments) + 1;
        end
        
    end
end
