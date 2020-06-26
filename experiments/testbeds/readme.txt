The utility

genTestbedCfg

can be used to create testbed configuration files for use with the
BBN GNAT testbed. This application requires three arguments, which are

 o the number of enclaves
 o the number of application hosts per enclave
 o the number of link emulatros per enclave

This application writes to stdout, hence the following command

genTestbedCfg 24 1 2 > mytestbedfile.cfg

will generate a testbed file called mytestbed.cfg with the same
topology as bbn_testbed.cfg.

At the moment,this utility *does not* attempt to generate ascii art
describing the topology; however, if it did it would look much like
the ascii art contained with bbn_testbed.cfg except with more or fewer
enclaves, more or fewer application nodes, or more or fewer link emulators.

