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

function [r,links]=gnatConvexMCUtility(topoFile, traffFile, netCodedMC_arg)
    % Set true if we want detailed printouts
    debugPrints = false;
    % Default is network coded multicast
    netCodedMC = true;
    if (nargin > 2)
        netCodedMC = netCodedMC_arg;
    end
    
    % Read the topology file
    topo  = processTopoFile(topoFile);
    N     = double(topo.nNodes);
    links = topo.virLinks(:,1:3);
    maxCap = max(topo.virLinks(:,3));
    
    % Now map nodes so that they're from 1:N
    % and replace links entries appropriately
    
    configNodeIds = topo.bpfs;
    conseqNodeIds = 1:N;
    temp = links(:,1:2);
    [toreplace, bywhat] = ismember(temp, configNodeIds);
    temp(toreplace) = conseqNodeIds(bywhat(toreplace));
    links(:,1:2) = temp;
    
    L  = size(links,1);
    fprintf('Total of %i links\n', L);
    
    if (max(links(:,1)) > N) || (max(links(:,2)) > N)
        error('Node ID too big. N = %d, nodeId = %d found.', N, max(max(links(:,1:2))));
    end

    % Read the traffic file

    traffic = processTraffFile(traffFile, topo);
    
    % Process traffic into format used here
    
    i = 1;
    for flowId = 1:size(traffic.mcastFlows,1)
        srcNode = traffic.mcastFlows(flowId,1); % This is the config file src ID
        srcNode = find(configNodeIds==srcNode); % Translate to consecutive ID
        grp = traffic.mcastFlows(flowId,2);
        pri = traffic.mcastFlows(flowId,5);
        % mcastDests assumes that nodeIds are consecutive 1:N
        for j = find(traffic.mcastDests(flowId,:)==1)
            traff(i,1) = srcNode;
            traff(i,2) = j;
            traff(i,3) = flowId;
            traff(i,4) = pri;
            i = i + 1;
        end
    end
            
    % G is number of distinct multicast flows
    % F is the number of unicast flows contained in G
    
    F = size(traff,1);
    G = size(unique(traff(:,3)),1);

    fprintf('Total number of accepted flows is %d\n', G);
    fprintf('Total number of unicast components is %d\n', F);
    
    % Remap flows to ensure that flow ids are consecutive 1:G
    % and that all flows are together
    
    % Put all flows with same FID together
    traff = sortrows(traff,3);
    
    % Make sure that FIDs run from 1 to G
    oldFids = unique(traff(:,3));
    newFids = 1:G;
    [a,b] = ismember(traff(:,3),oldFids);
    traff(a,3) = newFids(b(a));
    
    % Now check that all flows with same FID have same priority
    fidPri = zeros(G,1);
    for g = 1:G
        tmp = unique(traff(traff(:,3)==g,4));
        if size(tmp,1) > 1
            error('Flows with FID %d have different priorities\n', oldFids(g));
        else
            fidPri(g) = tmp;
        end
    end
    
    % and that all flows with same FID have same source
    fidSrc = zeros(G,1);
    for g = 1:G
        tmp = unique(traff(traff(:,3)==g,1));
        if size(tmp,1) > 1
            error('Flows with FID %d have different sources\n', oldFids(g));
        else
            fidSrc(g) = tmp;
        end
    end
    
    % Set up some handy references for the various components in the
    % (now possibly reduced) traffic matrix

    src  = traff(:,1);
    dst  = traff(:,2);
    fid  = traff(:,3);
    
    % Now build the flow matrix.
    % F groups of N rows by L columns for node conservation
    %    (block diagonal --> 1:FN rows x 1:FL columns)
    
    % If we're using network coded multicast, then
    % F  distinct groups of L rows for network coding max flow constraints 
    %    (FN+1:FN+FL rows x 1:FL+GL columns)
    
    % If we're using repeated unicast, then we'll keep the same structure,
    % but simply have a "max" variable for each unicast flow per link. So
    % FL extra columns instead of GL extra columns
    %    (FN+1:FN+FL rows x 1:FL+FL columns)
    
    % Finally, L  rows for capacity constraints, one per link, summed over
    % all F blocks  

    % Then an additional G columns for flow variables.
    
    numRows = F*N + F*L + L;
    if netCodedMC
        numCols = F*L + G*L + G;
    else
        numCols = F*L + F*L + G;
    end
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
    
    % Flow variable offset
    if netCodedMC
        flowOffset = F*L+G*L;
    else
        flowOffset = F*L+F*L;
    end
        
    for k = 1:F
        Atemp = Asub;
        
        % Insert it into problem matrix
        A((k-1)*N+(1:N), (k-1)*L+(1:L)) = Atemp;
               
        % Flow in at source node is positive
        A((k-1)*N+src(k), flowOffset+fid(k)) =  1;
        
        % Flow out at destination node is negative
        A((k-1)*N+dst(k), flowOffset+fid(k)) = -1;
    end

    rowOffset = F*N;
    colOffset = 0;

    % Set up the part of the equations that adds in the unicast loads for 
    % each member of the group: hence the speye below

    A(rowOffset+(1:F*L), colOffset+(1:F*L))=speye(F*L);

    if netCodedMC
        
        % Now we set up the part of the equation where we subtract off the
        % 'multicast' load from each of the unicast loads in the group 
        % (hence the negative "speye" below)
        
        eyeL = -speye(L);
        
        % Assume flow IDs run 1:G
        
        for g = 1:G
            
            Atemp = sparse(F*L,L);
            index = find(fid(:)==g);
            
            for j = index'
                Atemp((j-1)*L+(1:L),1:L)=eyeL;
            end
            
            rowOffset = F*N;
            colOffset = F*L+(g-1)*L;
            
            A(rowOffset+(1:F*L), colOffset+(1:L)) = Atemp;
            
        end

        rowOffset = F*N+F*L;
        colOffset = F*L;
        
        % Now enforce link capacity constraints
        A(rowOffset+(1:L),colOffset+(1:G*L)) = repmat(speye(L),1,G);
        
    else
        
        % Using repeated unicast
        rowOffset = F*N;
        colOffset = F*L;
        A(rowOffset+(1:F*L), colOffset+(1:F*L))=-speye(F*L);
        
        rowOffset = F*N+F*L;
        colOffset = F*L;
        % Now enforce link capacity constraints
        A(rowOffset+(1:L),colOffset+(1:F*L)) = repmat(speye(L),1,F);
    end
  
    % Mosek uses both lower and upper bounds on variables
    
    bux = inf(numCols,1);
    blx = zeros(numCols,1);
    
    buc = zeros(numRows,1);
    blc = zeros(numRows,1);

    % Link capacity for sum of multicast flow constraints
    buc(rowOffset+(1:L)) = links(:,3);

    % Make lower bound for capacity constraints and for
    % unicast - multicast < 0 effectively unbounded

    blc(F*N+(1:F*L+L),1) = -inf;
    
    % objective is to maximize prioritized sum of utilities
    
    opr  = zeros(G,3);
    opri = zeros(G,1);
    oprj = zeros(G,1);
    oprf = zeros(G,1);
    oprg = zeros(G,1);
    
    for i = 1:G
        opr(i,1:3) = 'log';
        opri(i,1)  = 0;
        oprj(i,1)  = flowOffset + i;
        oprf(i,1)  = max(fidPri(i));
        oprg(i,1)  = 0;
    end

    t = tic();

    clear -v lo1;
    f = zeros(1,numCols);
    
    % Subtract a little from objective function for using link flows to
    % reduce circulation
    
% Commented out here to get Mosek to complete    
    if netCodedMC
        f(1:(F*L+G*L))= -0.001*log(maxCap)/maxCap/L;
    else
        f(1:(F*L+F*L))= -0.001*log(maxCap)/maxCap/L;
    end
    
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
        pobjval = r.sol.itr.pobjval;
        x = r.sol.itr.xx;
        penalty = -sum(f.*x');
        fprintf('Penalty value is %f. Objective is %f\n',penalty,pobjval);
        mcRates = x(flowOffset+(1:G));
        if netCodedMC
            fprintf('Using network coded multicast\n');
        else
            fprintf('Using repeated unicasts\n');
        end
        colOffset = 0;
        
        linkLoads = zeros(L,1);
        
        for g = 1:G
            % Print out multicast group src and destinations.
            % Make sure to convert back to original FIDs
            fidDsts = dst(fid==g);
            fprintf('Multicast (FID %d) from %d -> {%d',oldFids(g), configNodeIds(fidSrc(g)), configNodeIds(fidDsts(1)));
            for d = fidDsts(2:end)
                fprintf(', %d', configNodeIds(d));
            end
            
            fprintf('}. Priority = %5.2f, Flow = %5.2f\n', fidPri(g), mcRates(g));
            % Now print out load on each link in subgraph
            if debugPrints
                numF = sum(fid==g);
                if netCodedMC
                    mcastFlows = max(reshape(x(colOffset+(1:numF*L)),L,numF),[],2);
                else
                    mcastFlows = sum(reshape(x(colOffset+(1:numF*L)),L,numF),2);
                end
                linkLoads = linkLoads + mcastFlows;
                for l = 1:L
                    if mcastFlows(l) > .005
                        srcNode = configNodeIds(links(l,1));
                        dstNode = configNodeIds(links(l,2));
                        fprintf('   %d -> %d: %5.2f\n',srcNode,dstNode,mcastFlows(l));
                    end
                end
                
                % Now print out load on each link for each unicast in the
                % multicast
                for f = find(fid==g)'
                    srcNode = configNodeIds(src(f));
                    dstNode = configNodeIds(dst(f));
                    fprintf(' %d -> %d\n', srcNode, dstNode);
                    linkFlows = x(colOffset+(1:L));
                    for l = 1:L
                        if linkFlows(l) > .005
                            srcNode = configNodeIds(links(l,1));
                            dstNode = configNodeIds(links(l,2));
                            fprintf('   %d -> %d: %5.2f\n',srcNode,dstNode,linkFlows(l));
                        end
                    end
                    colOffset = colOffset + L;
                end
            end
        end
        % Now print out aggregate load on each link
        if debugPrints
            fprintf('\n\nAggregate Link Loads\n');
            for l = 1:L
                if linkLoads(l) > 0.005
                    srcNode = configNodeIds(links(l,1));
                    dstNode = configNodeIds(links(l,2));
                    fprintf('%d -> %d: %5.2f\n',srcNode,dstNode,linkLoads(l));
                end
            end
        end
    else
        fprintf('MOSEK error: %s\n', status.response.msg);
    end
end
