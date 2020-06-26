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

function best = MDPCARQ_K(p,k,n,target_eps)
% p is probability of packet loss
% k is number of systematic packets
% n is number of rounds
% target_eps is target loss rate

t_max = ceil(log(target_eps)/log(p)*k);

% value is dynamic programming cost-to-go
% second and third dimensions are number of systematic and coded packets

value = zeros(n+1,k+1,k+1);
optT  = zeros(n+1,k+1,k+1);

% Values at end time are function of loss rate

loss = zeros(k+1);
for sys = 0:k-1
    sys_index = sys + 1;
    loss(sys_index,1:(k-sys)) = 1-sys/k;
end

best_eff = 0;
% figure out what weight is correct to get desired epsilon

low_weight = 0;
high_weight_found = false;
weight = 52.084;

done = false;

while (~done)
    value(n+1,:,:) = weight*loss;
    
    % iterate backward over stages, choosing optimal T for each step
    % cost to go function can have one of three shapes:
    %  - goes up (so optimal solution is at t=0)
    %  - goes down and then up (so solution is in the "valley")
    %  - goes up, down and then up (so solution is in "valley")
    
    for stage = n:-1:1
        for sys = 0:k-1
            for coded = 0:k-1-sys
                over_hump = false;
                prev_val = inf;
                for t = 0:t_max
                    prob = OneStepProb(p,k,sys,coded,t);
                    test_val = sum(sum(prob.*squeeze(value(stage+1,:,:))))+t;
                    if (t==0)  % initialize
                        value(stage,sys+1,coded+1) = test_val;
                        optT(stage,sys+1,coded+1)  = t;
                        prev_val = test_val;
                    elseif (test_val >= prev_val) && ~over_hump  % going up and not over hump (if one exists)
                        prev_val = test_val;
                    else   % over the hump (includes case where there is no hump)
                        over_hump = true;
                        prev_val = test_val;
                    end
                    if over_hump  
                        if (test_val < value(stage,sys+1,coded+1))  % new solution is best so far
                            value(stage,sys+1,coded+1) = test_val;
                            optT(stage,sys+1,coded+1)  = t;
                        elseif test_val <= prev_val  % over the hump and heading down but solution is not as good as t=0
                            prev_val = test_val;
                        else  % heading up again, so stop
                            break;
                        end
                    end
                end
                if t == t_max
%                    fprintf('t=%d\n',t_max);
                end
            end
        end
    end
    
    % iterate forward to compute probabilities at each stage assuming you start
    % in state (0,0).
    jp = zeros(k+1);
    jp(1,1) = 1;
    
    % loop through transmit rounds
    pkts_sent = 0;
    
    pkts = zeros(n,1);
    pkts_rcvd = zeros(n,1);
    for r = 1:n
        T = squeeze(optT(r,:,:));
        pkts(r) = sum(sum(T.*jp));
        pkts_sent = pkts_sent + pkts(r);
        jp = UpdateProbs(jp,T,p);
        pkts_rcvd(r) = sum(sum(jp,2).*(0:k)');
    end
    
    eps = 1-pkts_rcvd(n)/k;
    eff = pkts_rcvd(n)/pkts_sent/(1-p);
%    fprintf('weight = %f, eps = %f, eff = %f ', weight, eps, eff);
%    fprintf('round 1 send %d packets\n', optT(1,1,1));
    % adjust weight
    
    if ~high_weight_found
        if eps < target_eps
            high_weight_found = true;
        else
            low_weight = weight;
            weight = weight*2;
        end
        if weight > 10^6
            fprintf('Aborting. Weight = %f\n',weight);
            return;
        end
    end
    if high_weight_found
        if (eps < target_eps)
            % weight might be too high
            high_weight = weight;
            if eff > best_eff
                best_eff = eff;
                best.eff = eff;
                best.k = k;
                best.p = p;
                best.rounds = n;
                best.target_eps = target_eps;
                best.weight = weight;
                best.pkts_sent = pkts;
                best.pkts_rcvd = pkts_rcvd;
                best.eps = eps;
                best.T = optT;
                best.val = value;
            end
        else
            % weight too low
            low_weight = weight;
        end
        weight = (high_weight-low_weight)/2+low_weight;
        if ((high_weight - low_weight)/high_weight < 0.0001) && (high_weight - low_weight) < 0.01
            done = true;
%             fprintf('End hunt for weights. hi=%i, lo=%i\n',high_weight,low_weight);
        end
    end
    optT  = zeros(n+1,k+1,k+1);
    value = zeros(n+1,k+1,k+1);
end
%fprintf('k = %i, weight = %i, eps = %f, eff = %f\n',best.k,best.weight,best.eps,best.eff);

end


function joint_probs = OneStepProb(p,K,sys,coded,total_sent)
joint_probs = zeros(K+1+total_sent,K+1+total_sent);
sys_col = sys+1;
coded_col = coded+1;
% Figure out number of systematic and coded packets sent
sys_sent = min(K-sys,total_sent);
coded_sent = total_sent - sys_sent;
sys_prob = zeros(sys_sent+1,1);
coded_prob = zeros(coded_sent+1,1);
% sys_prob(i) is probability i-1 systematic packets
% compute binomial probability distribution of receiving
% k packets, given (i-1) sent. Note that we cannot just use
% the choose function as we have numerical issues for large
% K. Instead we iteratively compute the probabilities by
% using the following relation:
%   prob_receive_(i+1) =
%   prob_receive_(i)*(no_sent-i)/i*(1-p)/p
sys_prob(1) = p^sys_sent;
rcvd = 1;
while rcvd<=sys_sent
    sys_prob(rcvd+1) = sys_prob(rcvd)*(sys_sent+1-rcvd)/rcvd*(1-p)/p;
    rcvd = rcvd+1;
end
if (sum(sys_prob)<=.999)
    sys_prob(sys_sent+1) = (1-p)^sys_sent;
    rcvd = sys_sent-1;
    while rcvd >=1
        sys_prob(rcvd) = sys_prob(rcvd+1)*rcvd/(sys_sent+1-rcvd)*p/(1-p);
        rcvd = rcvd -1;
    end
    if sum(sys_prob)<.999
        fprintf('Error computing systematic probabilities from top down. Sum = %f\n', sum(sys_prob));
    end
end
coded_prob(1) = p^coded_sent;
rcvd = 1;
while rcvd<=coded_sent
    coded_prob(rcvd+1) = coded_prob(rcvd)*(coded_sent+1-rcvd)/rcvd*(1-p)/p;
    rcvd = rcvd+1;
end
if (sum(coded_prob)<=.999)
    sys_prob(sys_sent+1) = (1-p)^sys_sent;
    rcvd = sys_sent-1;
    while rcvd >=1
        sys_prob(rcvd) = sys_prob(rcvd+1)*rcvd/(sys_sent+1-rcvd)*p/(1-p);
        rcvd = rcvd -1;
    end
    if sum(sys_prob)<.999
        fprintf('Error computing coded probabilities from top down. Sum = %f\n', sum(sys_prob));
    end
end
% The probability of receiving being in state (k,l) when starting in state (s,c)
% is probability of receiving s-k systematic packets and l-c coded packets

joint_probs(sys_col+(0:sys_sent),coded_col+(0:coded_sent)) = sys_prob*coded_prob';

% Now need to "sweep" up the probability that receiver has >=K DOFs and
% zero those states out and add the probability to the (K,0) state
% This funky expression generates a matrix that is "1" where (j,k)
% satisfies j+k>=K
full_rank = logical(rot90(tril(ones(K+1+total_sent),total_sent)));
% Add up probabilities of K+ DOFs
p_full = sum(sum(joint_probs(full_rank)));
% Zero out those states
joint_probs(logical(full_rank))=0;
% Add to (K,0) [Note that matlab is 1 based array, so store in (K+1,1)
joint_probs(K+1,1)=p_full;
% Now shrink the joint_probs array to (K+1)x(K+1)
if total_sent > 0
    joint_probs(K+2:end,:)=[];
    joint_probs(:,K+2:end)=[];
end

end