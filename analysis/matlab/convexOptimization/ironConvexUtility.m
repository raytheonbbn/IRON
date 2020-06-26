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

function [r,linkFlows]=ironConvexUtility(topoFile, traffFile)

Overhead = 0.0;

% Read the topology file

    fid      = fopen(topoFile);
    N        = strread(fgetl(fid), '%d');

    i = 1;
    tmp = fgetl(fid);
    while tmp > 0
        [linkSrc(i,1), linkDst(i,1), linkBw(i,1)] = strread(tmp, '%d %d %f');
        linkBw(i,1) = linkBw(i,1)*(1-Overhead);
        i = i + 1;
        tmp = fgetl(fid);
    end
    fclose(fid);

    links    = [linkSrc, linkDst, linkBw];

    L        = size(links,1);
    fprintf('Total of %i unidirectional links\n', L);

    % Read the traffic file
    % Format is SRC, DST, LOG, Priority
    % U(X) = Priority*LOG(X)
    % or SRC, DST, INE, Rate

    logIndex = 0;
    ineIndex = 0;
    fid = fopen(traffFile);
    tmp = fgetl(fid);
    ineFlowSrc = [];
    ineFlowDst = [];
    while tmp > 0
        if contains(tmp,'LOG')
            logIndex = logIndex + 1;
            [logFlowSrc(logIndex,1),logFlowDst(logIndex,1),fn(logIndex),pri(logIndex)] = strread(tmp, '%d %d %s %f', 1);
        else
            ineIndex = ineIndex + 1;
            [ineFlowSrc(ineIndex,1),ineFlowDst(ineIndex,1),fn(ineIndex),rate(ineIndex)] = strread(tmp, '%d %d %s %f', 1);
        end
        tmp = fgetl(fid);
    end
    fclose(fid);
    
    logFlows = [logFlowSrc, logFlowDst];
    logF = size(logFlows,1);
    F = logF;
    ineF = 0;
    if (size(ineFlowSrc,1)>0)
        ineFlows = [ineFlowSrc, ineFlowDst];
        ineF = size(ineFlows,1);
        F = logF+ineF;
    end

    % Now build the flow matrix.
    % F groups of N rows for node conservation
    % Then an additional L rows for capacity constraints.
    % Then an additional F columns for flow variables.
    
    numRows = F*N + L;
    numCols = F*L + logF;
    nnzA = 1e4;
    A = sparse([], [], [], numRows, numCols, nnzA);
    fprintf('numRows = %d, numCols = %d\n', numRows, numCols);
    
    % Build flow conservation (sub)matrix
    % Each row corresponds to a node and has +1 for links to that node,
    % -1 for links from that node 

    Asub = sparse(N,L);
    for k = 1:N
        Asub(k,1:L) = ((links(:,2) == k) - (links(:,1) == k))';
    end

    % logFlowSrc and logFlowDst are the source and destination for log flows

    for k = 1:logF
        % Modify the Asub matrix to get rid of links flowing into source /
        % out of destination nodes 
        Atemp = Asub;
        % Remove inbound links to source
        Atemp(:, (links(:,2) == logFlowSrc(k))') = 0;
        % Remove outbound links from destination
        Atemp(:, (links(:,1) == logFlowDst(k))') = 0;
        % Jam it into flow matrix
        A(((k-1)*N+1):k*N,((k-1)*L+1):k*L) = Atemp;
        % Flow in at source node is positive
        A((k-1)*N+logFlowSrc(k), F*L+k) = 1;
        % Flow out at destination node is negative
        A((k-1)*N+logFlowDst(k), F*L+k) = -1;
    end
    
    % Now add in the inelastic flows. Set the flow to the specified rate.
    % Mosek uses constraint lower and upper bounds
    % Equalities for log flow constraints buc=blc=0
    % Rate for inelastic flows
    
    buc = zeros(numRows,1);
    blc = zeros(numRows,1);

    for k = logF+(1:ineF)
        % Modify the Asub matrix to get rid of links flowing into source /
        % out of destination nodes
        Atemp = Asub;
        % Remove inbound links to source
        Atemp(:, (links(:,2) == ineFlowSrc(k-logF))') = 0;
        % Remove outbound links from destination
        Atemp(:, (links(:,1) == ineFlowDst(k-logF))') = 0;
        % Jam it into flow matrix
        A(((k-1)*N+1):k*N,((k-1)*L+1):k*L) = Atemp;
        % Flow out at source node is negative
        buc((k-1)*N+ineFlowSrc(k-logF)) = -rate(k-logF);
        blc((k-1)*N+ineFlowSrc(k-logF)) = -rate(k-logF);
        % Flow in at destination node is positive
        buc((k-1)*N+ineFlowDst(k-logF)) = rate(k-logF);
        blc((k-1)*N+ineFlowDst(k-logF)) = rate(k-logF);
    end

    % Now enforce link capacity constraints
    A(F*N+(1:L),1:F*L) = repmat(speye(L),1,F);
  
    % Mosek uses both lower and upper bounds on variables
    
    bux = inf(numCols,1);
    blx = zeros(numCols,1);
    
    % Link capacity for sum of flow constraints
    rowIndex = F*N;
    buc(rowIndex+(1:L)) = linkBw;
    
    % objective is to maximize prioritized sum of utilities
    
    colIndex = F*L;
    for i = 1:logF
        opr(i,1:3) = 'log';
        opri(i,1)  = 0;
        oprj(i,1)  = colIndex + i;
        oprf(i,1)  = pri(i);
        oprg(i,1)  = 0;
    end

    t = tic();

    clear -v lo1;
    f = zeros(1,numCols);
    
    lo1.sense = 'max';
    lo1.c     = f;
    lo1.a     = A;
    lo1.blc   = blc;
    lo1.buc   = buc;
    lo1.blx   = blx;
    lo1.bux   = bux;
    lo1.opr   = opr;
    lo1.opri  = opri;
    lo1.oprj  = oprj;
    lo1.oprf  = oprf;
    lo1.oprg  = oprg;

    % args: problem, maximize, cache
    [r, status]= mskscoptAdapter(lo1,true,false);
    
    if (status.response.code == 0)
        linkFlows = [];
        fprintf('LP took %5.2f seconds\n', toc(t));
        flows = r.sol.itr.xx(F*L+(1:logF));
        optFlows = [logFlowSrc, logFlowDst, pri', flows];
        fprintf('Log Flows\n');
        fprintf(' S  D   P    F\n');
        for n = 1:size(flows,1)
            fprintf('%2d %2d %4.2f %4.2f\n', optFlows(n,:));
            x = r.sol.itr.xx((n-1)*L+(1:L));
            index = x > 1e-3;
            lf = [links(index,1:2),x(index)];
            for m = 1:size(lf,1)
                fprintf('  %2d %2d %4.2f\n', lf(m,1:3));
            end
            temp = zeros(size(lf,1),size(lf,2)+2);
            temp(:,1) = logFlowSrc(n);
            temp(:,2) = logFlowDst(n);
            temp(:,3:5) = lf;
            linkFlows = [linkFlows; temp];
        end
        if (ineF > 0)
            fprintf('Inelastic Flows\n');
            fprintf(' S  D    F\n');
            for n = 1:ineF
                fprintf('%2d %2d %4.2f\n', ineFlowSrc(n), ineFlowDst(n), rate(n));
            end
        end
    else
        fprintf('MOSEK error: %s\n', status.response.msg);
    end
end
