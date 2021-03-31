The goal for the Intrinsically Resilient Overlay Network (IRON) and the
Generalized Network Assisted Transport (GNAT) projects is improving the
performance of networked applications that must exchange information over
wide-area networks (WANs). The earlier IRON project focused exclusively on
unicast applications; GNAT extended IRON to support multicast transports
applications as well as applications that are latency sensitive.

Our core approach leverages fully distributed computation both within the
network and at the edges that collectively works to continually maximize
Cumulative Network Utility (CNU). CNU optimization leverages a robust,
low-overhead, distributed optimization technique known as Backpressure,
which is known to be throughput optimal. This work extends Backpressure by
taking into account per-flow end-to-end throughput and latency requirements
to create a system that is throughput optimal subject to latency constraints.
The work is enhanced by the addition of a host of latency reduction techniques
including latency sensitive hop-by-hop error control, congestion control, and
a set of queuing delay reduction techniques to make end-to-end delays across
the network as small as possible.

Backpressure itself is comprised of a pair of complementary techniques: a
packet-forwarding algorithm that leverages queue differentials between
neighboring overlay nodes to continually move traffic along the least
congested paths; and a suite of admission control algorithms operating at the
entry points to the overlay network that regulate access of individual
application flows to the backpressure network.

The combined techniques work to continuously maximize network utility (and
hence CNU) without requiring global knowledge of traffic pattern, packet
priorities or network topology. Each GNAT node performs a local optimization
that, in cooperation with its peers, yields a global maximization of CNU.