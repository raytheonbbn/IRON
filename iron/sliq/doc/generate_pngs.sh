#!/bin/sh

dot -Tpng -o sliq_conn_estab.png        sliq_conn_estab.dot
dot -Tpng -o sliq_conn_estab_direct.png sliq_conn_estab_direct.dot
dot -Tpng -o sliq_conn_term.png         sliq_conn_term.dot
dot -Tpng -o sliq_stream_estab.png      sliq_stream_estab.dot
dot -Tpng -o sliq_stream_term.png       sliq_stream_term.dot
dot -Tpng -o sliq_data_send.png         sliq_data_send.dot
dot -Tpng -o sliq_data_can_send.png     sliq_data_can_send.dot
dot -Tpng -o sliq_data_recv.png         sliq_data_recv.dot
dot -Tpng -o sliq_ack_recv.png          sliq_ack_recv.dot
dot -Tpng -o sliq_win_size.png          sliq_win_size.dot
dot -Tpng -o sliq_persist.png           sliq_persist.dot
dot -Tpng -o sliq_outage.png            sliq_outage.dot

dot -Tpng -o cubic_cansend.png                cubic_cansend.dot
dot -Tpng -o cubic_onackpktprocessingdone.png cubic_onackpktprocessingdone.dot
dot -Tpng -o cubic_onpacketnacked.png         cubic_onpacketnacked.dot
dot -Tpng -o cubic_onrttupdate.png            cubic_onrttupdate.dot

dot -Tpng -o copa_onackpktprocessingdone.png   copa_onackpktprocessingdone.dot
dot -Tpng -o copa_updatedelta.png              copa_updatedelta.dot
dot -Tpng -o copa_updateintersendtime.png      copa_updateintersendtime.dot
dot -Tpng -o copa_updatenextsendtime.png       copa_updatenextsendtime.dot
dot -Tpng -o copa_updateunackedrttestimate.png copa_updateunackedrttestimate.dot

dot -Tpng -o copa2_fsdonecallback.png       copa2_fsdonecallback.dot
dot -Tpng -o copa2_onpacketresent.png       copa2_onpacketresent.dot
dot -Tpng -o copa2_onpacketsent.png         copa2_onpacketsent.dot
dot -Tpng -o copa2_onrttupdate.png          copa2_onrttupdate.dot
dot -Tpng -o copa2_processccpkttrain.png    copa2_processccpkttrain.dot
dot -Tpng -o copa2_updateminrtttracking.png copa2_updateminrtttracking.dot
dot -Tpng -o copa2_updatenextsendtime.png   copa2_updatenextsendtime.dot
dot -Tpng -o copa2_updatevelocity.png       copa2_updatevelocity.dot

dot -Tpng -o copa3_dampercanupdatevelcwnd.png copa3_dampercanupdatevelcwnd.dot
dot -Tpng -o copa3_damperonpktsent.png        copa3_damperonpktsent.dot
dot -Tpng -o copa3_damperonrttupdate.png      copa3_damperonrttupdate.dot
dot -Tpng -o copa3_delaytrackerupdate.png     copa3_delaytrackerupdate.dot
dot -Tpng -o copa3_fsdonecallback.png         copa3_fsdonecallback.dot
dot -Tpng -o copa3_onrttupdate.png            copa3_onrttupdate.dot
dot -Tpng -o copa3_processccpkttrain.png      copa3_processccpkttrain.dot
dot -Tpng -o copa3_updatenextsendtime.png     copa3_updatenextsendtime.dot
dot -Tpng -o copa3_velocityreset.png          copa3_velocityreset.dot
dot -Tpng -o copa3_velocityupdate.png         copa3_velocityupdate.dot

exit 0
