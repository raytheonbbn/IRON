#include "normFlowController.h"

#include <cstring>

namespace
{
  /// Default flow control window size.
  const unsigned int  kDefaultWinSizePkts = 490;
}

//============================================================================
FlowController::FlowController()
    : oldest_tx_pkt_seq_num_(0),
      oldest_tx_pkt_seq_num_init_(false),
      last_tx_pkt_seq_num_(0),
      win_size_pkts_(kDefaultWinSizePkts),
      dup_win_info_cnt_(0),
      last_msg_rcv_seq_num_(0),
      last_msg_sent_seq_num_(0)
{
}

//============================================================================
FlowController::~FlowController()
{
  // Nothing to destroy.
}

//============================================================================
void FlowController::HandleFcMessage(NormFcMsg& msg)
{
  NormFcMsg::Flavor  flavor = msg.GetFlavor();

  switch (flavor)
  {
    case NormFcMsg::WIN_SIZE:
      win_size_pkts_ = static_cast<NormFcWinSizeMsg&>(msg).GetWindowSize();
      break;

    case NormFcMsg::WIN_UPDATE:
    {
      NormFcWinUpdateMsg  win_update_msg =
        static_cast<NormFcWinUpdateMsg&>(msg);

      win_size_pkts_           = win_update_msg.GetWindowSize();
      UINT16  msg_rcv_seq_num  = win_update_msg.GetWindowRcvSeqNum();
      UINT16  msg_sent_seq_num = win_update_msg.GetWindowSentSeqNum();

      RecordWindowUpdate(msg_rcv_seq_num, msg_sent_seq_num);
      break;
    }

    default:
      PLOG(PL_WARN, "Rcvd NORM FC Message, Unknown Flavor: %d\n", flavor);
      return;
  }
}

//============================================================================
void FlowController::RecordTx(unsigned short pkt_seq_num)
{
  // Log a warning if the transmited packet does not fit in the flow control
  // window.
  if (AvailableWindowPkts() == 0)
  {
    PLOG(PL_WARN, "Packet with sequence number %hu is outside of flow "
         "control window.\n", pkt_seq_num);
  }

  if (!oldest_tx_pkt_seq_num_init_)
  {
    oldest_tx_pkt_seq_num_      = pkt_seq_num;
    oldest_tx_pkt_seq_num_init_ = true;
  }

  last_tx_pkt_seq_num_ = pkt_seq_num;
}

//============================================================================
UINT16 FlowController::AvailableWindowPkts() const
{
  if (((last_tx_pkt_seq_num_ - oldest_tx_pkt_seq_num_) + 1) > win_size_pkts_)
  {
    return 0;
  }
  else
  {
    return win_size_pkts_ - ((last_tx_pkt_seq_num_ - oldest_tx_pkt_seq_num_) +
                             1);
  }
}

//============================================================================
void FlowController::RecordWindowUpdate(UINT16 rcv_seq_num,
                                        UINT16 sent_seq_num)
{
  oldest_tx_pkt_seq_num_ = sent_seq_num + 1;

  if ((rcv_seq_num == last_msg_rcv_seq_num_) &&
      (sent_seq_num == last_msg_sent_seq_num_))
  {
    dup_win_info_cnt_++;
    if (dup_win_info_cnt_ >= 3)
    {
      ResetWindowInfo();
    }
  }
  else
  {
    last_msg_rcv_seq_num_  = rcv_seq_num;
    last_msg_sent_seq_num_ = sent_seq_num;
    dup_win_info_cnt_      = 0;
  }
}

//============================================================================
void FlowController::ResetWindowInfo()
{
  oldest_tx_pkt_seq_num_      = 0;
  oldest_tx_pkt_seq_num_init_ = false;
  last_tx_pkt_seq_num_        = 0;
  last_msg_rcv_seq_num_       = 0;
  last_msg_sent_seq_num_      = 0;
  dup_win_info_cnt_           = 0;
}
