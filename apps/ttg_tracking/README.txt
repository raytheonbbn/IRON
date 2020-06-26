To generate TTG plots:

1. Enable the "-DTTG_TRACKING" option in the iron/options.mk file.

2. Recompile all of IRON.

3. Run the experiment and wait for it to complete.

   Note that the TTG tracking log statements are all logged by the BPFs, and
   are logged using LogC().  Thus, it is not necessary to change the BPF
   logging levels in the experiment.

4. Determine which pair of nodes that you want the TTG plots for.  For each of
   these nodes, you will need the SLIQ CAT Number and the Connection Endpoint
   ID for the CATs connecting these two nodes.  The BPF log files will contain
   the following type of SLIQ CAT configuration logging for each SLIQ CAT:

     C [SliqCat::Initialize] SliqCat 0 configuration:
     C [SliqCat::Initialize] Type                         : SliqCat
     C [SliqCat::Initialize] Label                        :
     C [SliqCat::Initialize] Endpoints                    : 172.24.4.1:30300->172.24.4.2:30300
     C [SliqCat::Initialize] Connection Endpoint ID       : 4
     ...

   Use the listed Endpoints to determine which SLIQ CAT instance is the one
   that you are looking for.  Once the SLIQ CAT instances are found, note the
   SLIQ CAT Number (0 in the above case) and the Connection Endpoint ID (4 in
   the above case) for both nodes.

5. Generate the two plots using the following command from within this
   directory:

     cd apps/ttg_tracking
     ./show_plots.sh <sc1> <ce1> <path1/bpf.log> <sc2> <ce2> <path2/bpf.log>

   where:

     sc   - the SLIQ CAT Number
     ce   - the Connection Endpoint ID
     path - the path to the node's BPF log file

   The first plot displayed will be from the first BPF listed to the second.
   After closing the gnuplot window, press enter in the terminal to display
   the plot from the second BPF listed to the first.  After closing the
   gnuplot window, press enter in the terminal to clean up the temporary
   files.
