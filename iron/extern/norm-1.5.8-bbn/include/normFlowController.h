#ifndef FLOW_CONTROLLER_H
#define FLOW_CONTROLLER_H

#include "normMessage.h"

#include <climits>

/// \brief A flow control object that tracks the size of the flow control
///        window at the sender.
///
/// Each packet transmission is recorded as it occurs at the sender.
///
/// The edge node (the receiver) provides the following 2 pieces of
/// information:
///
///   1. Window Size packet: The size of the flow control window, in
///      packets. The sender MUST NOT exceed the size of the flow control
///      window. The edge node will drop all packets received outside of the
///      flow control window.
///   2. Window Update packet: Each time that the edge node admits a packet to
///      the network, it sends back an update message containing the receive
///      sequence number and the send sequence number. The receive sequence
///      number is the NORM sequence number of the most recently received
///      packet at the edge device. The sent sequnece number is the NORM
///      sequence number of the packet that has been admitted to the
///      network. Changes in the receive sequence number fill the flow control
///      window and changes in the sent sequence number drain the flow control
///      window.
///
/// The source of the flow uses the information provided in the Window Size
/// packet and Window Update packets to determine if a transmission falls
/// within the flow control window.
class FlowController
{
  public:

  /// \brief Default constructor.
  FlowController();

  /// \brief Destructor.
  virtual ~FlowController();

  /// \brief Handle a received GNAT flow control message.
  ///
  /// There are 2 "flavors" of flow control messages: 1) window size or 2)
  /// window update
  void HandleFcMessage(NormFcMsg& msg);

  /// \brief Record a packet transmission.
  ///
  /// \param  pkt_seq_num  The transmitted packet sequence number.
  /// \param  pkt_size     The transmitted packet size.
  void RecordTx(UINT16 pkt_seq_num);

  /// \brief Get the size of the currently available flow control window, in
  ///        bytes.
  ///
  /// \return The size of the currently available flow control window, in
  ///         bytes.
  UINT16 AvailableWindowPkts() const;

  private:

  /// \brief Copy constructor.
  FlowController(const FlowController& fc);

  /// \brief Assignment operator.
  FlowController& operator=(const FlowController& fc);

  /// \brief Record a flow control window update, reported by the edge node.
  ///
  /// \param  rcv_seq_num   The most currently received sequence
  ///                       number. Received sequence numbers fill the
  ///                       flow control window.
  /// \param  sent_seq_num  The most recent GNAT sent sequence number. Sent
  ///                       sequence numbers drain the flow control window.
  void RecordWindowUpdate(UINT16 rcv_seq_num,
                          UINT16 sent_seq_num);

  /// \brief Reset the flow control window information.
  void ResetWindowInfo();

  /// The sequence number of the oldest sent packet.
  UINT16  oldest_tx_pkt_seq_num_;

  /// Remembers if the oldest sent packet sequence number has been
  /// initialized.
  bool    oldest_tx_pkt_seq_num_init_;

  /// The sequence number of the last sent packet.
  UINT16  last_tx_pkt_seq_num_;

  /// The window size, in packets.
  UINT16  win_size_pkts_;

  /// Counts the number of window update messages that contain exactly the
  /// same sequence numbers. When this count exceeds 3, we will reset the
  /// window information. We do this so we the source and destination get out
  /// of sync to prevent the window from permanently staying closed if any
  /// messages do get lost.
  UINT8   dup_win_info_cnt_;

  /// The last receive sequence number extracted from a window update
  /// message.
  UINT16  last_msg_rcv_seq_num_;

  /// The last sent sequence number extracted from a window update
  /// message.
  UINT16  last_msg_sent_seq_num_;

}; // end class FlowController

#endif // FLOW_CONTROLLER_H
