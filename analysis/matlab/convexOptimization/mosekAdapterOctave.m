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

function [r, status] = mosekAdapter(lo1, maximize, useSimplex, cacheLicense)

if (cacheLicense==true)
    lo1.iparam.MSK_IPAR_CACHE_LICENSE = 'MSK_ON';
else
    lo1.iparam.MSK_IPAR_CACHE_LICENSE = 'MSK_OFF';
end

if (useSimplex == true)
    lo1.iparam.MSK_IPAR_SIM_NETWORK_DETECT = 0;
    lo1.iparam.MSK_IPAR_OPTIMIZER = 'MSK_OPTIMIZER_FREE_SIMPLEX';
end

lo1.A = lo1.a;
lo1 = rmfield(lo1,'a');

clear -v options;
options.verbose = 0;

if (maximize==true)
    lo1.sense='max';
else
    lo1.sense='min';
end

r = mosek(lo1, options);

if (strcmp(r.response.msg, 'MSK_RES_OK: No error occurred.'))
    rc = 0;
else
    rc = -1;
end

status.response.code = rc;
status.response.msg  = r.response.msg;

end
