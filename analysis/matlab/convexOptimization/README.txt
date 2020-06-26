The main analysis executable is the MATLAB function 
ironOverlayConvexUtility (in ironConvexOverlayUtility.m). 

Given a network topology and set of flows and associated utility functions 
on that topology, it computes the set of flow rates that optimize the 
cumulative utility.

This code models the EdgeCT problem, where multiple red enclaves are 
interconnected over a black network via overlay tunnels. The code 
assumes that if there are multiple paths through the black
network, then they use the optimal strategy (multipath forwarding) -
but only on the links/nodes that are on shortest paths. The goal is
to provide an upper bound on performance.

Running this code requires the Mosek separable convex optimization 
package for MATLAB. Documentation for this package can be found here
http://docs.mosek.com/7.1/toolbox.pdf

The function takes two arguments, the name of a topology 
file and the name of a traffic file which specifies both flow 
starting and ending nodes and the associated utility function
and parameters for each flow.

------

The function is invoked as:

ironOverlayConvexUtility(topologyFileName, trafficFileName)

where topologyFileName and trafficFileName are strings. For example

ironOverlayConvexUtility('topo3','log3priority1');

The topology file format is as follows:

number_of_enclaves
total_number_of_red_and_black_nodes
src dst bw
src dst bw
...

with (src dst bw) defining the links in the network
The code assumes that the first N nodes are the enclaves

The traffic file format is as follows:

src dst function priority b
src dst function priority b
...

with src/dst being a node number
function being LOG, LIN, POW, or NMD

utility is defined as
LOG: priority*log(1+b*x)
LIN: priority*x
POW: priority*(b*x)^(1-a)/(1-a)
NMD: priority*(1 - b/(x+b))

where x is the rate of a flow

The POW utility implements the alpha-fair utility function where the
parameter 'a' is alpha

The NMD utility implements a special case of the POW utility function with 
alpha = 2, known as the minimum delay fairness utility. NMD normalizes 
the minimum delay fairness utility function by shifting it up and to the 
left so that the minimum utility is zero at x=0, and that the maximum 
utility is 'priority' at x=infinity

---

There are a few topology and traffic files available as examples.
Red enclaves are connected to the black nodes via links with capcity=10,
while black nodes have capcity=1 links connecting them. 

topo6 looks like:

    /--6--\
1--3       4--2
    \--5--/

This corresponds to a throughput of 2 in each direction, 
and is used to show that multipath in the black network is working.

topo3 is our triangle test (actually contains 6 nodes)

1--4-----6--3
    \   /
     \ /
      5
      |
      2

Results from various tests with 6 flows. 

LIN
With priority = 1 for all flows, we get the expected 6 units of flow.
With priority = 1 for flows between 1<->2 and 1<->3 but priority 4 for 2<->3
we get 2 units of flow between 2<->3 as expected.

LOG
For testing purposes, consider the following scenario using topo3. Priority = 1 for flows between 
1<->2 and 1<->3 but priority P for 2<->3.

We would expect 2<->3 to "hog" the capacity as P goes up. Let X be the bandwidth in excess of "1" for 2<->3.

The optimal solution is:
X = 0 if P<=2
X = 1 if P>=6
X = (2P-4)/(P+2) else

These results can be obtained using log3priority1 and log3priority1-4

POW
The optimal solution is:
X = 0 if C>=1
X = 1 if C<=0
X = (1-C)/(1+C) else

where C = (2/P)^(1/(1-a))

For a=0.9 and P=4, C=.463 and X=.37 which can be obtained using pow3priority1-4

NMD
With b set to 10, the utility functions behave nearly linearly.
With priority = 1 for all flows, we get the expected 6 units of flow, 
With priority = 1 for flows between 1<->2 and 1<->3 but priority 4 for 2<->3
we get 2 units of flow between 2<->3 as expected.

With b set to 0.1, the utility functions allow more proportionate sharing.
With priority = 1 for all flows, we still get the expected 6 units of flow, 
With priority = 1 for flows between 1<->2 and 1<->3 but priority 4 for 2<->3
we get ~1.2 units of flow between 2<->3 and ~0.8 units of flow between 1<->2 
and 1<->3 


ironConvexUtility

Similar to ironOverlayConvexUtility except it solves the optimization problem
only considering the connectivity between IRON nodes

Topo file format is
     num_iron_nodes
     src dst bw
     src dst bw
     ...
 - note that both directions of a link must be specified

Traffic file format is a series of lines specifying each flow as
     src dst [LOG|INE] [priority|bw]

LOG means that the flow in elastic and has utility p*log(r)
Note that there's no linear term in the utility function
Priority is specified by the 3rd term on the line

INE means that the flow is inelastic and has fixed bandwidth of bw

The program will determine the optimal flow rates for the elastic
flows while ensuring that the inelastic flows are accommodated.
If the linear program says the program is infeasible, likely the
inelastic flows are too large
