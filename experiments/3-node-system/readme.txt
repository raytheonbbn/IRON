3-node-system

This is a triangle test with three different-priority flows, and SLIQ CATs 
with LinkEm rate changes. It uses both the UDP proxy and TCP proxy. 

Topology:
    src                             dst
 en1.ap1 --- e1.i ------ e2.i --- en2.ap1
               \           /
                \         /
                 \       /
                  \     /
                   e3.i
                     |
                  en3.ap1

"en" stands for "enclave, "ap" stands for "app", and "i" standard for "iron"
The IRON nodes run bpf / udp proxy / tcp proxy / amp.

Traffic:

There are three MGEN flows from enclave1-app1 to enclave2-app1. 
- A udp flow with p=1 (3 Mbps)
- A tcp flow with p=1 (25 Mbps)
- A tcp flow with p=5 (25 Mbps)
Each flow has a LOG utility function, with the only difference being the
priorities.
Each link is initially 10Mbps.
At 20s, the direct link goes from 10Mbps to 0.
At 30s, the direct link is restored to 10Mbps.


Expected results:

The flows should stabilize to throughput ratios of about 5-to-1 (TCP to UDP).
The overhead of IP headers, UDP headers, tunnels, etc is about 10%, so the
aggregate throughput measured at the MGEN level should be about 18Mbps
until the direct link is severed.

The flow ratios should be maintained throughout the simulation, however the
TCP flow can suffer from head-of-the line blocking which means its throughput
typically varies more than that of the UDP throughput.

After 20s, the total network capacity is reduced to 10Mbps when the direct link
has its capacity set to zero. This will cause some packet loss, requiring more
retransmissions and more head-of-the-line blocking. This can manifests itself as
large changes in instantaneous MGEN throughput (i.e., no packets released while
waiting for a "hole" to be filled, followed by a release of a burst of packets
once the "hole" is filled).

Sample result plots are given in the results subdirectory.

Updated August 29, 2018
