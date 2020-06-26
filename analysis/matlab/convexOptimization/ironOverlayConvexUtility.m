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

function r=ironOverlayConvexUtility(topoFile, traffFile)

% Read the topology file

    fid      = fopen(topoFile);
    N        = strread(fgetl(fid), '%d');
    numNodes = strread(fgetl(fid), '%d');

    i = 1;
    tmp = fgetl(fid);
    while tmp > 0
        [linkSrc(i,1), linkDst(i,1), linkBw(i,1)] = strread(tmp, '%d %d %d');
        i = i + 1;
        tmp = fgetl(fid);
    end
    fclose(fid);
    fprintf('Total of %i links\n', (i-1)/2);

    links    = [linkSrc, linkDst, linkBw];

    enclaves = [1:N]';
    L        = size(links,1);

    % Read the traffic file
    % Format is SRC, DST, Function, Priority, B, (optionally A)
    % Function can be 'LOG', 'POW' or 'LIN'
    % If 'LOG', U(X) = Priority*LOG(1+B*X)
    % If 'POW', utility is "alpha fair" function
    %    U(X) = Priority*(B*X)^(1-A)/(1-A) if A~=1
    % If 'LIN', U(X) = Priority*X
    % If 'NMD', U(x) = Priority - Priority * B *(X+B)^-1
    
    
    i = 1;
    fid = fopen(traffFile);
    tmp = fgetl(fid);
    while tmp > 0
        if isempty(strfind(tmp, 'POW'))
            [flowSrc(i,1),flowDst(i,1),fn(i),pri(i),b(i)] =...
                strread(tmp, '%d %d %s %f %f', 1);
            a(i) = 0;
        else
            [flowSrc(i,1),flowDst(i,1),fn(i),pri(i),b(i),a(i)] =...
                strread(tmp, '%d %d %s %f %f %f', 1);
            if a(i) == 1
                fprintf('POW utility function cannot have A==1\n');
                return;
            end
        end
        if ~(strcmp(fn(i),'POW')||strcmp(fn(i),'LIN')||...
                strcmp(fn(i),'LOG')||strcmp(fn(i),'NMD'))
            fprintf('Unknown utility function: %s\n', fn{i});
            return;
        end
        tmp = fgetl(fid);
        i = i + 1;
    end
    fclose(fid);
    
    flows = [flowSrc, flowDst];

    % Sanity tests
    % Flows use enclave nodes

    if (max(max(flowSrc), max(flowDst))) > N
        printf('Error\n');
        return
    end

    F = size(flows,1);

    % Full mesh of tunnels
    T = N*(N-1);

    tunnels = zeros(T,2);
    k = 1;
    for i = 1:N
        for j = 1:N
            if (i ~= j)
                tunnels(k,1) = i;
                tunnels(k,2) = j;
                k = k + 1;
            end
        end
    end

    % Now build the overlay flow matrix, accounting for enclave
    % sources and destinations.
    % F groups of N rows for enclave node conservation
    % FT columns containing the fraction of the Fth flow on the Tth overlay tunnel 
    % The FT+(1:F) columns are the flows that goes into/out of each enclave

    % Add up all the subflows on a tunnel, since they get treated
    % the same. That's an extra T columns and T rows.

    % Then write node flow conservation equations for the nodes
    % supporting each tunnel. This uses L*T "tunnel flow on a link"
    % variables (columns). There are numNodes * T equations (rows).

    % Then an additional L rows for capacity constraints.
    % Then an additional F rows/columns for the log auxilliary variables.
    % Then an additional F rows/columns for the nmd auxilliary variables.

    numRows = F*N + T + numNodes*T + L + F + F
    numCols = F*T + F + T + L*T + F + F
    nnzA = 1e4;
    A = sparse([], [], [], numRows, numCols, nnzA);
    fprintf('numRows = %d, numCols = %d\n', numRows, numCols);
    
    % Build flow conservation (sub)matrix
    % Each row corresponds to a node and has +1 for links to that node,
    % -1 for links from that node 

    Asub = sparse(N,T);
    for k = 1:N
        Asub(k,1:T) = ((tunnels(:,2) == k) - (tunnels(:,1) == k))';
    end

    % Assume that enclaves are the first N nodes
    % flowSrc and flowDst contain the source and destination enclave for
    % each flow

    for k = 1:F
        % Modify the Asub matrix to get rid of links flowing into source /
        % out of destination nodes 
        Atemp = Asub;
        % Remove inbound links to source
        Atemp(:, (tunnels(:,2) == flowSrc(k))') = 0;
        % Remove outbound links from destination
        Atemp(:, (tunnels(:,1) == flowDst(k))') = 0;
        % Jam it into flow matrix
        A((k-1)*N+1:k*N,(k-1)*T+1:k*T) = Atemp;
        % Flow in at source node is positive
        A((k-1)*N+flowSrc(k), F*T+k) = 1;
        % Flow out at destination node is negative
        A((k-1)*N+flowDst(k), F*T+k) = -1;
    end
    
    % Now add up the tunnel subflows
    rowIndex = F*N;
    colIndex = 0;

    A(rowIndex+(1:T),colIndex+(1:F*T)) = repmat(speye(T),1,F);
    colIndex = F*T+F;
    A(rowIndex+(1:T),colIndex+(1:T))   = -speye(T);
    
    % Maximum number of equal cost shortest paths to use
    kMax = 5;

    % Node conservation equations for each tunnel
    rowIndex = F*N + T;
    colIndex = F*T + F + T;
    for t = 1:T
        % Get nodes and links used by each tunnel
        [tunnelNodes, linkIndex] =...
            kShortestPaths(links, tunnels(t,1), tunnels(t,2), ...
                           kMax);
        % Zero out links that aren't used - zero is not a valid nodeId
        activeLinks = zeros(L,3);
        activeLinks(linkIndex,:) = links(linkIndex,:);
        Asub = sparse(numNodes, L);
        for k = 1:numNodes
            Asub(k,1:L) = ((activeLinks(:,2) == k)...
                           - (activeLinks(:,1) == k))';
            A(rowIndex+(1:numNodes), colIndex+(1:L)) = Asub;
            % Flow in/out is 1/-1 times aggregate tunnel load
            A(rowIndex+tunnels(t,1), F*T + F + t) = 1;
            A(rowIndex+tunnels(t,2), F*T + F + t) = -1;
        end
        rowIndex = rowIndex + numNodes;
        colIndex = colIndex + L;
    end

    % Now enforce link capacity constraints
    colIndex = F*T + F + T;
    A(rowIndex+(1:L),colIndex+(1:T*L)) = repmat(speye(L),1,T);

    % Compute the arguments to the logarithmic utility function p*log(1+bx)
    % x' = 1+bx or x' - bX = 1
    % We do this for all variables, but only use the ones for which
    % Fn = 'LOG'
    rowIndex = F*N + T + numNodes*T + L;
    colIndex = F*T + F + T + L*T;
    A(rowIndex+(1:F),colIndex+(1:F)) = speye(F);
    
    colIndex = F*T;
    A(rowIndex+(1:F),colIndex+(1:F)) = spdiags(-b',[0],F,F);
    
    % Compute the arguments to the NMD utility function 1-p*b/(x+b)
    % x' = b+x or x' - x = b
    % We do this for all variables, but only use the ones for which
    % Fn = 'NMD'
    rowIndex = F*N + T + numNodes*T + L + F;
    colIndex = F*T + F + T + L*T + F;
    A(rowIndex+(1:F),colIndex+(1:F)) = speye(F);    

    colIndex = F*T;
    A(rowIndex+(1:F),colIndex+(1:F)) = -speye(F);

    % Mosek uses constraint lower and upper bounds
    % Equalities for flow constraints buc=blc=0
    
    buc = zeros(numRows,1);
    blc = zeros(numRows,1);
    % Link capacity for sum of flow constraints
    rowIndex = F*N + T + numNodes*T;
    buc(rowIndex+(1:L)) = linkBw;
    % Block for logarithmic auxilliary variables
    rowIndex = F*N + T + numNodes*T + L;
    blc(rowIndex+(1:F)) = 1;
    buc(rowIndex+(1:F)) = 1;
    % Block for normalized minimum delay auxilliary variables
    rowIndex = F*N + T + numNodes*T + L + F;
    blc(rowIndex+(1:F)) = b;
    buc(rowIndex+(1:F)) = b;    
    
    % Mosek uses both lower and upper bounds on variables
    bux = inf(numCols,1);
    blx = zeros(numCols,1);

    % objective is to maximize prioritized sum of utilities
    % Linear term only where Fn = 'LIN'
    f = zeros(1,numCols);
    linIndex = find(strcmp(fn,'LIN'));
    if ~isempty(linIndex)
        colIndex = F*T+linIndex;
        f(1,colIndex) = pri(linIndex);
    end
    nonLinearObjective = false;
    
    % Init the utility function row tracking index
    j = 1;
    
    % Log utility term where Fn = 'LOG'
    colIndex = F*T + F + T + L*T;
    for i = 1:F
        if strcmp(fn{i},'LOG')
            ofn(j,1:3) = fn{i};
            opr(j,1:3) = 'log';
            opri(j,1)  = 0;
            oprj(j,1)  = colIndex + i;
            oprf(j,1)  = pri(i);
            oprg(j,1)  = 0;
            j = j + 1;
            nonLinearObjective = true;
        end
    end

    % Power utility term where Fn = 'POW'
    colIndex = F*T;
    for i = 1:F
        if strcmp(fn{i},'POW')
            ofn(j,1:3) = fn{i};
            opr(j,1:3) = 'pow';
            opri(j,1)  = 0;
            oprj(j,1)  = colIndex + i;
            oprf(j,1)  = pri(i)/(1-a(i));
            oprg(j,1)  = (1-a(i));
            j = j + 1;
            nonLinearObjective = true;
        end
    end

    % Normalized Minimum Delay utility term where Fn = 'NMD'
    colIndex = F*T + F + T + L*T + F;
    for i = 1:F
        if strcmp(fn{i},'NMD')
            ofn(j,1:3) = fn{i};
            opr(j,1:3) = 'pow';
            opri(j,1)  = 0;
            oprj(j,1)  = colIndex + i;
            oprf(j,1)  = - pri(i) * b(i);
            oprg(j,1)  = -1;
            j = j + 1;
            nonLinearObjective = true;
        end
    end
    
    % We don't bother to explicitly include the linear part of the
    % Normalized Minimum Delay utility term since the vector x that 
    % maximizes cx also maximizes cx+k where k is a constant
    
    % If there are no non-linear utilties, pass in empty matrices
    if ~nonLinearObjective
        opr  = [];
        opri = [];
        oprj = [];
        oprf = [];
        oprg = [];
    end
    
    fprintf('A matrix has %d non-zero entries\n', nnz(A));

    t = tic();

    clear -v lo1;
    
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
        fprintf('LP took %5.2f seconds\n', toc(t));
        flows = r.sol.itr.xx(F*T+(1:F));
        % First get linear utility - zero for LOG or POW
        utility = f(F*T+(1:F))'.*flows;
        % Now overwrite non-linear utility values
        if ~isempty(opr)
            % Process LOG utility functions
            index = find(strncmp(cellstr(ofn),'LOG',3));
            if ~isempty(index)
                % Retrieve the input indices 
                colIndex = F*T + F + T + L*T;
                inpIndex = oprj(index)-colIndex; 
                utility(inpIndex,1) = pri(inpIndex')'.* ...
                    log(r.sol.itr.xx(oprj(index)));
            end
            % Process POW utility functions
            index = find(strncmp(cellstr(ofn),'POW',3));
            if ~isempty(index)
                % Retrieve the input indices 
                colIndex = F*T;                
                inpIndex = oprj(index)-colIndex; 
                utility(inpIndex,1) = pri(inpIndex')'.* ...
                    (r.sol.itr.xx(oprj(index))).^(1-a(inpIndex)')./...
                    (1-a(inpIndex)');
            end
            % Process NMD utility functions
            index = find(strncmp(cellstr(ofn),'NMD',3));
            if ~isempty(index)
                % Retrieve the input indices 
                colIndex = F*T + F + T + L*T + F;
                inpIndex = oprj(index)-colIndex; 
                utility(inpIndex,1) = pri(inpIndex')'...
                     - pri(inpIndex')'.* b(inpIndex)' ./ ...
                    (r.sol.itr.xx(oprj(index)));
            end
        end
        optFlows = [flowSrc, flowDst, pri', flows, utility];
        fprintf(' S  D   P    F    U\n');
        for n = 1:size(flows,1)
            fprintf('%2d %2d %4.2f %4.2f %4.2f\n', optFlows(n,:));
        end

        fprintf('Total utility = %5.2f\n', sum(utility));
    else
        fprintf('MOSEK error: %s\n', status.response.msg);
    end
end
