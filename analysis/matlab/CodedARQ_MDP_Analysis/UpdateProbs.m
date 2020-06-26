function joint_probs = UpdateProbs(jp, T, p)
    % Take a distribution over receiver state (i systematic packets and j
    % coded packets and determine the new distribution if T(i,j) packets
    % are sent by sender for the (i,j) state
    % Note that you cannot have more than K degrees of freedom at receiver,
    % since K DOFs means you can decode everything
    % Computation occurs in two steps:
    % - first, determine distribution for number of systematic and coded
    %   packets at receiver (this can be more than K). Do this by iterating
    %   over possible receiver states (i,j) and adding [probability of
    %   getting (k,l) packets][probability of being in (i,j)] to the
    %   (i+k,j+l) state 
    % - second, "sweep" up the probability of having more than K DOFs and
    %   add that to the probability of having K systematic packets
    %   (everything decoded)
    K = size(T,1)-1;
    Tmax = max(max(T));
    joint_probs = zeros(K+1+Tmax,K+1+Tmax);
    for sys = 0:K
        sys_col = sys+1;
        for coded = 0:K
            coded_col = coded+1;
            total_sent = T(sys_col,coded_col);
            if (jp(sys_col, coded_col)>0)
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
                if (p > 0)
                    while rcvd<=sys_sent
                        sys_prob(rcvd+1) = sys_prob(rcvd)*(sys_sent+1-rcvd)/rcvd*(1-p)/p;
                        rcvd = rcvd+1;
                    end
                end
                if (sum(sys_prob)<=.999) | (p == 0)
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
                % The probability of receiving (k,l) packets is product of
                % receiving k systematic and l coded packets
                update = jp(sys_col,coded_col)*sys_prob*coded_prob';
                joint_probs(sys_col+(0:sys_sent),coded_col+(0:coded_sent)) = joint_probs(sys_col+(0:sys_sent),coded_col+(0:coded_sent)) + update;
            end
        end
    end
    % Now need to "sweep" up the probability that receiver has >=K DOFs and
    % zero those states out and add the probability to the (K,0) state
    % This funky expression generates a matrix that is "1" where (j,k)
    % satisfies j+k>=K
    full_rank = logical(rot90(tril(ones(K+1+Tmax),Tmax)));
    % Add up probabilities of K+ DOFs
    p_full = sum(sum(joint_probs(full_rank)));
    % Zero out those states
    joint_probs(logical(full_rank))=0;
    % Add to (K,0) [Note that matlab is 1 based array, so store in (K+1,1)
    joint_probs(K+1,1)=p_full;
    % Now shrink the joint_probs array to (K+1)x(K+1)
    if Tmax > 0
        joint_probs(K+2:end,:)=[];
        joint_probs(:,K+2:end)=[];
    end
end
                    