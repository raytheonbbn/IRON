clear; clc

% pervals = [0.1, 0.15, 0.2, 0.25, 0.3, ...
% 		      0.35, 0.4, 0.45, 0.5];
% 
% epsilon = [0.001, 0.002, 0.003, 0.004, ...
% 		   0.005,  0.010, 0.015, 0.020, 0.025,...
% 		   0.030,  0.035, 0.040, 0.045, 0.050];
       
pervals = [0.1, 0.2, 0.3, 0.4, 0.5];

epsilon = [0.005,  0.010, 0.015, 0.020, 0.025,...
		   0.030,  0.035, 0.040, 0.045, 0.050];       

NTGTPRECV  = length(epsilon);
NPERS      = length(pervals);
MAXSRCPKTS = 10;  
MAXROUNDS  = 7;

fid = fopen('mdpcarqresults.txt','w');

for currNumSrcPkts = 1:MAXSRCPKTS
    % fprintf(fid,'******* Number of Source Packets: %d *******\n',currNumSrcPkts);
    
    for perindex=1:NPERS  
        per = pervals(perindex); 
        
        for nRounds=1:MAXROUNDS
            
            for pr=1:NTGTPRECV
                tgtEps = epsilon(pr);
                
                r = MDPCARQ_K(per,currNumSrcPkts,nRounds,tgtEps);
                
                fprintf(fid,'%d %f %d %f %f %f\n',...
                    currNumSrcPkts,per,nRounds,tgtEps,r.eps,r.eff);
            end
        end
    end
end


                
