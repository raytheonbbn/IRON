This file attempts to explain how the various scripts call each other.

* variables

The scripts use variables to refer to various directories within an
experiment.  This is potentially confusing because there are at least
two, somtimes three, and perhaps more types of machines involved:

  staging host: on which run_exp runs
  results host: where results are put
  experiment nodes: N computers, on which the experiment is run

In local usage, typically, the experiments are run by a user (not
"iron") on a staging host which is also the results host.  The
experiment is staged, and then that is pushed to the experiment nodes
as user "iron".

\todo Explain how DETER is more complicated.

** STAGING_DIR

This is set to $HOME/iron_exp_staging in multiple places.  It refers
to a directory on the staging host, only.  (Sometimes this expansion
is open coded instead.)

** EXP_NAME

This is set to the name of the experiment and is used as a path
component in many contexts.

** USER_NAME

This is typically set to "iron" the -u flag to run_exp.sh.  It is used
as the username for activities on the results host and the experiment
nodes.

** EXP_BASE_DIR

This is set when an experiment is configured/staged.  It is set to
"/home/{$USER_NAME}".  It is used on experiment nodes.

** EXP_DIR

This is almost always ${EXP_BASE_DIR}/iron_exps.  It is sometimes open
coded and sometimes set as a variable.  It is used on experiment nodes.

** RES_LOC

This is typically $HOME/iron_results and is the path on the results
host where this experiment's results are stored.

* SH

quick_run_exp.sh
  run_exp.sh

run_exp.sh
  make.sh
  stage.sh
  validate_experiment.py
  configure.sh
  install.sh
  start_exp.sh
    common_start.sh
      run_gulp.sh
    StopLinkEm.sh
    StartLinkEm.sh
    start.sh
      common_start.sh
      run_iron.sh
        tune_os_params.sh
        run_pidstat.sh
      run_mgen.sh
      run_gst.sh
    stop.sh
      stop_mgen.sh
      stop_gst.sh
      stop_iron.sh
        restore_os_params.sh
      stop_gulp.sh
      StopLinkEm.sh
      process.sh
      move_core.sh
      get_perf_results.sh
        get_perf.sh
      stop_screen.sh

experiment-name/cfgs/process.cfg
  # This is a "config file", but process.sh reads it and runs commands
  # that are listed.  Many experiments run process_logs.sh and some
  # run gprof.sh
  process_logs.sh
  gprof.sh

** unreferenced

  findinf.sh
  kill.sh
  remotecmd.sh

* PYTHON

run_exp.sh
  validate_experiment.py
    file_reader.py

configure.sh
  generate_testbed_exp_cfg.py
  generate_traffic_input_files.py

install.sh
  testbed.py

** unreferenced

map_lost_udp_pkts.py

remote_packet_trace.py
  packet_trace.py

plot_bpf.py
plot_bpf_pkt_loss.py
plot_debug_stat.py
plot_k.py
plot_packets_owned.py
plot_udp_pkt_loss.py
plotSR.py
plotUtil.py
process_mgen.py
