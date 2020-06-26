// IRON: iron_headers
/*
 * Distribution A
 *
 * Approved for Public Release, Distribution Unlimited
 *
 * EdgeCT (IRON) Software Contract No.: HR0011-15-C-0097
 * DCOMP (GNAT)  Software Contract No.: HR0011-17-C-0050
 * Copyright (c) 2015-20 Raytheon BBN Technologies Corp.
 *
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contracts No. HR0011-15-C-0097 and
 * HR0011-17-C-0050. Any opinions, findings and conclusions or
 * recommendations expressed in this material are those of the author(s)
 * and do not necessarily reflect the views of the Defense Advanced
 * Research Project Agency.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/* IRON: end */

#ifndef IRON_UTIL_NFTP_NFTP_H
#define IRON_UTIL_NFTP_NFTP_H

#include "nftp_config_info.h"
#include "nftp_net_if.h"
#include "normApi.h"

#include <string>
#include <vector>

/// \brief NORM File Transfer Program (nftp) class.
class Nftp
{
  public:

  /// \brief Constructor.
  ///
  /// \param  net_if  Pointer to the network interface.
  Nftp(NftpNetIf* net_if);

  /// \brief Destructor.
  virtual ~Nftp();

  /// \brief Initialize the nftp.
  ///
  /// \param  config_info  The configuration information.
  ///
  /// \return True if successful, false otherwise.
  bool Initialize(ConfigInfo& config_info);

  /// \brief Start nftp.
  void Start();

  private:

  /// Contains the information relevant to a destination, including:
  ///
  ///   - Host name (or string representation of IP Address)
  ///   - Output path
  ///   - Host IP Address, in network byte order
  struct DstInfo
  {
    DstInfo()
    : name(),
      path(),
      ip_addr_nbo(0)
    { }

    std::string  name;
    std::string  path;
    UINT32       ip_addr_nbo;
  };

  /// Default constructor.
  Nftp();

  /// Copy constructor.
  Nftp(const Nftp& other);

  /// Copy operator.
  Nftp& operator=(const Nftp& other);

  /// \brief Send the file to the multicast group.
  void SendFile() const;

  /// \brief Advertise a file transfer.
  ///
  /// First, send an nftp control message to the multicast group. Then, wait
  /// for acknowlegdements from the receivers in the receiver list.
  ///
  /// \return True if successful, false otherwise.
  bool AdvFileXfer() const;

  /// \brief Generate the control message.
  ///
  /// \param  ctrl_msg      Buffer that will hold the constructed control
  ///                       message.
  /// \param  ctrl_msg_len  Length of the constructed control message.
  ///
  /// \return True if successful, false otherwise.
  bool GenerateCtrlMsg(char* ctrl_msg, UINT16& ctrl_msg_len) const;

  /// \brief Process a received nftp acknowledgement.
  ///
  /// \param  ack_msg  The received acknowledgement message.
  ///
  /// \return True if successful, false otherwise.
  bool ProcessNftpAck(const char* msg) const;

  /// \brief Receive a file.
  void RecvFile();

  /// The network interface.
  NftpNetIf*            net_if_;

  // ============ Sender and receiver member variables ============

  /// The multicast interface name.
  std::string           mcast_if_name_;

  /// String representation of the multicast destination address.
  std::string           mcast_addr_str_;

  /// The multicast destination port.
  UINT16                mcast_dst_port_;

  /// The source port for the file transfer packets.
  UINT16                src_port_;


  // ============ nftp sender specific member variables ============

  /// Remembers if a file is being transferred.
  bool                  sndr_;

  /// The source address of the multicast interface, in network byte order.
  unsigned long         src_addr_;

  /// The fully qualified path of the file being transferred.
  std::string           file_path_;

  /// Remembers if NORM TCP-friendly Congestion Control is enabled.
  bool                  enable_cc_;

  /// Remembers if NORM Window-based Flow Control is enabled.
  bool                  enable_fc_;

  /// The vector of destination information for the file transfer.
  std::vector<DstInfo>  dsts_;

  // ============ nftp receiver specific member variables ============

  /// Remembers if a file is being received.
  bool                  rcvr_;

  /// The output directory for the received file.
  std::string           output_dir_;

  /// The name of the output file.
  std::string           output_file_name_;

  /// The fully qualified output file name.
  std::string           fq_output_file_name_;

  /// String representation of the Source Specific Multicast (SSM) IP
  /// Address.
  std::string           src_addr_str_;

  /// Remembers if temporary files are used when receiving.
  bool                  use_temp_files_;

}; // end class Nftp

#endif // IRON_UTIL_NFTP_NFTP_H
