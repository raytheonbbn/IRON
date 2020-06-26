This is a triangle test that demonstrates loss-based triage in AMP.


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

Initially, all links have capacity 10Mbps. The link between e1 and e2 has a
60ms delay, and the other links have 5 ms delay. 30 seconds into the
experiment, the link between e1 and e3 is reduced to 6Mbps. The link is restored
to 10Mbps after 20 seconds.

Traffic:

There are three MGEN flows from enclave1 to enclave2. 
- A tcp flow with p=1  with LOG utility.
- A udp flow with p=10 with STRAP utility, nominal rate = 3.5Mbps, deadline = 50ms
- A udp flow with p=20 with STRAP utility, nominal rate = 3.5Mbps, deadline = 50ms 


Source en1.ap1 sends two UDP flows, sourced at a rate of 3.5Mbps, with STRAP
inelastic utility and one TCP flow, sourced at 20 Mbps, with LOG utility. The
inelastic flows have a deadline of 50 ms.


Expected results:

Initially, all flows should fit and the inelastic flows should operate 
at 3.5Mbps. The elastic flow will use the remaining bandwidth (less bandwidth
used for overhead), which is about 10 Mbps. 

When the capacity is reduced, there is not enough bandwidth for both 
inelastic flows to deliver all packets on time. They will both experience
loss and the lower priority flow will eventually be triaged (explicit loss triage 
in AMP). When the flow will periodically probe and will resume when the capacity
is restored. 
