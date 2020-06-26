set   autoscale
unset log
unset label
set xtic auto
set ytic auto
set title "TTG Adjustments"
set xlabel "Time (s)"
set ylabel "Value (s)"
xmin = `head -n 1 input_hold.dat | awk '{print $1}'`
plot "input_hold.dat" using ($1-xmin):($2-$3) title 'TTG Reduction for BPF Hold Time' with linespoints, \
     "input_est_owd.dat" using ($1-xmin):2 title 'TTG Reduction for Packet One-Way Delay' with linespoints, \
     "input_act_owd.dat" using ($1-xmin):2 title 'Actual Packet One-Way Delay' with linespoints
