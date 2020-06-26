3-node-system-lat

This is a low-latency test with a three node topology.

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

There are two udp flows from enclave1 to enclave2:
1. A 5Mbps low-latency flow of priority 1 with a 70ms latency deadline,
2. A 10Mbps latency-insensitive flow of priority 5.

Each of the links is initially 10Mbps.
The direct path has a latency of 70ms while each hop on the indirect path has
latency of 1ms.
At 20s, the direct link goes from 10Mbps to 0.
at 30s, the direct link is restored to 10Mbps.

Expected Results:

Initially, the network is able handle the entire load including overhead. The
throughput will be very close to the rates of 10Mbps and 5Mbps. The low latency
flow takes the 2-hop path in order to meet the latency requirement.

During the outage, both flows must be served via the indirect, low-delay
10Mbps path.  Assuming 15% overhead and a 5:1 prioritization ratio, the low
priority latency-sensitive flow should get 1.4Mbps and the high priority
latency-insensitive flow should get 7Mbps. The packets of the low-latency flow
should be delivered within the latency bound.

Note that the BPF drops packets that will not make the deadline, so if queuing
delay is too high along the low-delay path to meet the latency sensitive
flow's deadline, the observed effect will be a lower goodput for the latency
sensitive flow.

Updated August 29, 2018
