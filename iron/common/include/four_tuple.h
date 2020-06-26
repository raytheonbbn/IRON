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

#ifndef IRON_COMMON_FOUR_TUPLE_H
#define IRON_COMMON_FOUR_TUPLE_H

#include <string>

#include <stdint.h>


namespace iron
{

  /// \brief A class for an IPv4 four-tuple that uniquely identifies a flow.
  ///
  /// Contains a source IPv4 address, a source TCP/UDP port number, a
  /// destination IPv4 address, and a destination TCP/UDP port number.  The
  /// addresses and ports are stored in Network Byte Order.
  ///
  /// Note that this class is not designed to be extended (inherited from) in
  /// order to maintain efficiency.  Specifically, the destructor is not
  /// virtual in order to eliminate the VTABLE.
  class FourTuple
  {

   public:

    /// \brief Constructor.
    FourTuple()
        : src_addr_nbo_(0), dst_addr_nbo_(0), src_dst_ports_nbo_(0)
    { }

    /// \brief Copy constructor.
    ///
    /// \param  ft  A reference to the object to copy from.
    FourTuple(const FourTuple& ft)
        : src_addr_nbo_(ft.src_addr_nbo_), dst_addr_nbo_(ft.dst_addr_nbo_),
          src_dst_ports_nbo_(ft.src_dst_ports_nbo_)
    { }

    /// \brief Constructor.
    ///
    /// \param  saddr_nbo  The source IPv4 address in network byte order.
    /// \param  sport_nbo  The source TCP/UDP port number in network byte
    ///                    order.
    /// \param  daddr_nbo  The destination IPv4 address in network byte order.
    /// \param  dport_nbo  The destination TCP/UDP port number in network byte
    ///                    order.
    FourTuple(uint32_t saddr_nbo, uint16_t sport_nbo, uint32_t daddr_nbo,
              uint16_t dport_nbo)
        : src_addr_nbo_(saddr_nbo), dst_addr_nbo_(daddr_nbo),
          src_dst_ports_nbo_((((uint32_t)sport_nbo) << 16) |
                             ((uint32_t)dport_nbo))
    { }

    /// \brief Constructor.
    ///
    /// \param  saddr_nbo    The source IPv4 address in network byte order.
    /// \param  daddr_nbo    The destination IPv4 address in network byte
    ///                      order.
    /// \param  sdports_nbo  The source and destination TCP/UDP port numbers
    ///                      in network byte order, combined into a 32-bit
    ///                      value.
    FourTuple(uint32_t saddr_nbo, uint32_t daddr_nbo, uint32_t sdports_nbo)
        : src_addr_nbo_(saddr_nbo), dst_addr_nbo_(daddr_nbo),
          src_dst_ports_nbo_(sdports_nbo)
    { }

    /// \brief Destructor.
    ///
    /// The destructor is not virtual in order to eliminate the VTABLE in each
    /// object.
    ~FourTuple()
    { }

    /// \brief Copy operator.
    ///
    /// \param  ft  A reference to the object to copy from.
    FourTuple& operator=(const FourTuple& ft);

    /// \brief Equals operator.
    ///
    /// \param  ft  A reference to the object to the right of the operator.
    ///
    /// \return  Returns true if equal, or false otherwise.
    bool operator==(const FourTuple& ft) const
    {
      return ((src_addr_nbo_ == ft.src_addr_nbo_) &&
              (dst_addr_nbo_ == ft.dst_addr_nbo_) &&
              (src_dst_ports_nbo_ == ft.src_dst_ports_nbo_));
    }

    /// \brief Set the four-tuple.
    ///
    /// \param  saddr_nbo  The source IPv4 address in network byte order.
    /// \param  sport_nbo  The source TCP/UDP port number in network byte
    ///                    order.
    /// \param  daddr_nbo  The destination IPv4 address in network byte order.
    /// \param  dport_nbo  The destination TCP/UDP port number in network byte
    ///                    order.
    void Set(uint32_t saddr_nbo, uint16_t sport_nbo, uint32_t daddr_nbo,
             uint16_t dport_nbo)
    {
      src_addr_nbo_      = saddr_nbo;
      dst_addr_nbo_      = daddr_nbo;
      src_dst_ports_nbo_ = ((((uint32_t)sport_nbo) << 16) |
                            ((uint32_t)dport_nbo));
    }

    /// \brief Hash the object into a table index for quick lookups.
    ///
    /// Hashes the object into 16-bit unsigned integer.
    ///
    /// \return  Returns the hashed four-tuple value.
    size_t Hash() const
    {
      // Compute a 16-bit sum, similar to an IP header checksum but without
      // the unnecessary operations, to obtain an index into a hash table.
      uint32_t  sum = ((src_addr_nbo_ >> 16) + (src_addr_nbo_ & 0xffff) +
                       (dst_addr_nbo_ >> 16) + (dst_addr_nbo_ & 0xffff) +
                       (src_dst_ports_nbo_ >> 16) +
                       (src_dst_ports_nbo_ & 0xffff));

      return static_cast<size_t>((sum >> 16) + (sum & 0xffff));
    }

    /// \brief Convert the object to a string.
    ///
    /// \return  The four-tuple as a string object.
    std::string ToString() const;

    /// \brief Get the source IPv4 address.
    ///
    /// \return  The source IPv4 address in network byte order.
    uint32_t src_addr_nbo() const
    {
      return src_addr_nbo_;
    }

    /// \brief Get the destination IPv4 address.
    ///
    /// \return  The destination IPv4 address in network byte order.
    uint32_t dst_addr_nbo() const
    {
      return dst_addr_nbo_;
    }

    /// \brief Get the source TCP/UDP port number.
    ///
    /// \return  The source TCP/UDP port number in network byte order.
    uint16_t src_port_nbo() const
    {
      return ((uint16_t)(src_dst_ports_nbo_ >> 16));
    }

    /// \brief Get the destination TCP/UDP port number.
    ///
    /// \return  The destination TCP/UDP port number in network byte order.
    uint16_t dst_port_nbo() const
    {
      return ((uint16_t)(src_dst_ports_nbo_ & 0xffff));
    }

   private:

    /// The source IPv4 address in network byte order.
    uint32_t  src_addr_nbo_;

    /// The destination IPv4 address in network byte order.
    uint32_t  dst_addr_nbo_;

    /// The source and destination TCP/UDP port numbers in network byte order.
    uint32_t  src_dst_ports_nbo_;

  }; // end class FourTuple

} // namespace iron

#endif // IRON_COMMON_FOUR_TUPLE_H
