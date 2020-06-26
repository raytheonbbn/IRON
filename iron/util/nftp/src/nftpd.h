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

#ifndef IRON_UTIL_NFTP_NFTPD_H
#define IRON_UTIL_NFTP_NFTPD_H

#include "nftp_config_info.h"

#include "normApi.h"

#include <string>
#include <vector>

/// \brief NORM File Transfer Program (nftp) deamon class.
class Nftpd
{
  public:

  /// \brief Default constructor.
  Nftpd();

  /// \brief Constructor.
  ///
  /// \param  mcast_if_name   Multicast interface name.
  /// \param  mcast_addr_str  String representation of the destination
  ///                         multicast address.
  /// \param  mcast_port      Destination multicast port.
  // Nftpd(const char* mcast_if_name, const char* mcast_addr_str,
  //       UINT16 mcast_port);

  /// \brief Destructor.
  virtual ~Nftpd();

  /// \brief Initialize the nftp daemon.
  ///
  /// \param  config_info  The configuration information.
  ///
  /// \return True if the initialization is successful, false otherwise.
  bool Initialize(ConfigInfo& config_info);

  /// \brief Start the nftp daemon.
  void Start();

  /// \brief Stop the nftp daemon.
  inline void Stop()
  {
    running_ = false;
  }

  private:

  /// Copy constructor.
  Nftpd(const Nftpd& other);

  /// Copy operator.
  Nftpd& operator=(const Nftpd& other);

  /// \brief Process a received message.
  ///
  /// \param  msg          The received message.
  /// \param  src_addr     The source from the nftp control message.
  /// \param  src_port     The source port from the nftp control message.
  /// \param  dst          The matched destination from the nftp control
  ///                      message.
  /// \param  output_path  The destination output path from the nftp control
  ///                      message.
  bool ProcessMsg(const char* msg, UINT32& src_addr, UINT16& src_port,
                  UINT32& dst, char* output_path) const;

  /// \brief Parse a received nftp control message.
  ///
  /// \param  msg          The received message.
  /// \param  src_addr     The source address from the nftp control message.
  /// \param  src_port     The source port from the nftp control message.
  /// \param  dst          The matched destination from the nftp control
  ///                      message.
  /// \param  output_path  The destination output path from the nftp control
  ///                      message.
  bool ParseNftpCtrlMsg(const char* msg, UINT32& src_addr, UINT16& src_port,
                        UINT32& dst, char* output_path) const;

  /// \brief Wait for the nftp receiver to start.
  ///
  /// \param  src_port  The source port the nftp receiver is listening to.
  void WaitForRcvr(UINT16 src_port) const;

  /// \brief Generate an nftp contol message acknowledgement.
  ///
  /// \param  src_addr     The source address from the nftp control message.
  /// \param  src_port     The source port from the nftp control message.
  /// \param  dst          The matched destination from the nftp control
  ///                      message.
  /// \param  ack_msg      The nftp control message acknowledgement.
  /// \param  ack_msg_len  The length, in bytes, of the nftp control message
  ///                      acknowledgement.
  void GenerateNftpAck(UINT32 src_addr, UINT16 src_port, UINT32 dst,
                       char* ack_msg, UINT16& ack_msg_len) const;

  /// \brief Process the received output path for the file transfer.
  ///
  /// \param  msg_output_path   The received output path for the file
  ///                           transer.
  /// \param  output_dir        The output directory for the file transer.
  /// \param  output_file_name  The output file name, if any.
  ///
  /// \return True if successful, false otherwise.
  bool ProcessOutputPath(const char* msg_output_path,
                         std::string& output_dir,
                         std::string& output_file_name) const;

  /// \brief Get the user's home directory.
  ///
  /// \return User's home directory.
  std::string GetHomeDir() const;

  /// \brief Checks if the provide directory exists.
  ///
  /// \param  dir  The directory to test for existence.
  ///
  /// \return True if the proviced directory exists, false otherwise.
  bool DirExists(const char* dir) const;

  /// The local interface addresses. When an nftp control message is received
  /// this will be used to determine if the local host is in the destination
  /// list.
  std::vector<UINT32>  if_addrs_;

  /// The name of the multicast interface.
  std::string          mcast_if_name_;

  /// String representation of the multicast address.
  std::string          mcast_addr_str_;

  /// Multicast destination port.
  UINT16               mcast_dst_port_;

  /// Boolean flag that remembers if the daemon is running or not.
  bool                 running_;

  /// The location of the nftp binary.
  std::string          nftp_bin_dir_;

  /// Indicates whether the nftp receiver is to use temporary files during
  /// file transfers.
  std::string          temp_files_opt_;

}; // end class Nftpd

#endif // IRON_UTIL_NFTP_NFTPD_H
