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

/// \brief The IRON ipv4 address header file.
///
/// Provides a simple class for storage and manipulation of IPv4 addresses
/// within IRON.


#ifndef IRON_COMMON_SRC_IPv4_ADDRESS_H
#define	IRON_COMMON_SRC_IPv4_ADDRESS_H

#include <string>

#include <arpa/inet.h>
#include <stdint.h>

namespace iron
{
  ///
  /// @class Ipv4Address
  ///
  /// Used to store and compare IPv4 addresses in IRON.  All addresses are
  /// stored and accessed in network byte order.
  ///
  ///
  class Ipv4Address
  {
    public:

      /// @brief Default no-arg constructor.
      Ipv4Address();

      /// @brief Constructor that takes a string.
      ///
      /// @param addr The IPv4 address in dot decimal format
      ///             (e.g. 192.168.10.1).
      Ipv4Address(const std::string& addr);

      /// @brief Constructor that takes a 32-bit integer.
      ///
      /// @param addr The IPv4 address represeted as an integer in network
      ///             byte order.
      Ipv4Address(uint32_t addr);

      /// @brief Constructor that takes a byte array.
      ///
      /// @param addr A pointer to an array of bytes, where the bytes are in
      ///             network byte order.
      Ipv4Address(const uint8_t* addr);

      /// @brief Copy constructor for an IPv4 address.
      ///
      /// @param addr A reference to the Ipv4Address object from which to make
      ///             the object.
      Ipv4Address(const Ipv4Address& addr);

      /// @brief Destructor.
      virtual ~Ipv4Address();

      /// @brief Get the IPv4 Address.
      ///
      /// @return The address as an in_addr_t in network byte order.
      inline in_addr_t address() const
      { return address_; }

      /// @brief Set the IPv4 Address.
      ///
      /// @param addr The IPv4 Address as an in_addr_t type in network byte
      ///             order.
      inline void set_address(in_addr_t addr)
      { address_ = addr; }

      /// @brief Set the IPv4 Address.
      ///
      /// @param  addr  String representation of the IPv4 Address.
      void set_address(const std::string& addr);

      /// @brief Set the IPv4 Address from a string, reporting any parse
      /// errors.
      ///
      /// \param  addr  String representation of the IPv4 Address.
      ///
      /// \return Returns true on success, or false on error.
      bool SetAddress(const std::string& addr);

      /// @brief Convert the IPv4 Address to a string.
      ///
      /// @return The IPv4 Address as a string object.
      std::string ToString() const;

      /// @brief Equality operator.
      ///
      /// @param left A reference to the left Ipv4Address object.
      /// @param right A reference to the right Ipv4Address object.
      ///
      /// @return Returns true if the addresses are equal, false otherwise.
      friend bool operator==(const Ipv4Address& left,
                             const Ipv4Address& right);

      /// @brief Inequality operator.
      ///
      /// @param left A reference to the left Ipv4Address object.
      /// @param right A reference to the right Ipv4Address object.
      ///
      /// @return Return true if the addresses are different, false otherwise.
      friend bool operator!=(const Ipv4Address& left,
                             const Ipv4Address& right);

      /// @brief Less than operator.
      ///
      /// @param left A reference to the left Ipv4Address object.
      /// @param right A reference to the right Ipv4Address object.
      ///
      /// @return Return true if the left address is less than the right
      ///         address, false otherwise.
      friend bool operator<(const Ipv4Address& left,
                            const Ipv4Address& right);

      /// @brief Greater than operator.
      ///
      /// @param left A reference to the left Ipv4Address object.
      /// @param right A reference to the right Ipv4Address object.
      ///
      /// @return Return true if the left address is greater than the right
      ///         address, false otherwise.
      friend bool operator>(const Ipv4Address& left,
                            const Ipv4Address& right);

      /// @brief Less than or equal to operator.
      ///
      /// @param left A reference to the left Ipv4Address object.
      /// @param right A reference to the right Ipv4Address object.
      ///
      /// @return Return true if the left address is less than or equal to the
      ///         right address, false otherwise.
      friend bool operator<=(const Ipv4Address& left,
                             const Ipv4Address& right);

      /// @brief Greater than or equal to operator.
      ///
      /// @param left A reference to the left Ipv4Address object.
      /// @param right A reference to the right Ipv4Address object.
      ///
      /// @return Return true if the left address is greater than or equal to
      ///         the right address, false otherwise.
      friend bool operator>=(const Ipv4Address& left,
                             const Ipv4Address& right);

      /// @brief Assignment operator from a string in dot decimal format.
      ///
      /// @param addr A reference to the address string in dot decimal format.
      ///
      /// @return A reference to the updated Ipv4Address object.
      Ipv4Address& operator=(const std::string& addr);

      /// @brief Assignment operator from an Ipv4Address object.
      ///
      /// @param addr A reference to the Ipv4Address object to copy.
      ///
      /// @return A reference to the updated Ipv4Address object.
      Ipv4Address& operator=(const Ipv4Address& addr);

      /// @brief Assignment operator from an integer in network byte order.
      ///
      /// @param addr The address as an integer in network byte order.
      ///
      /// @return A reference to the updated Ipv4Address object.
      Ipv4Address& operator=(uint32_t addr);

      /// @brief Check if an address is a multicast address.
      /// 
      /// @param addr The address being checked.
      ///
      /// @return True is the IpAddress is class D, false otherwise.
      inline bool IsMulticast() const
      {
        return IN_CLASSD(ntohl(address_));
      }

      /// \brief Hash the object into a table index for quick lookups.
      ///
      /// Hashes the object into 16-bit unsigned integer.
      ///
      /// \return  Returns the hashed four-tuple value.
      size_t Hash() const
      {
        return (static_cast<size_t>((address_ >> 16) + (address_ & 0xffff)));
      }

    protected:

      /// The IPv4 address stored as an in_addr_t in network byte order.
      in_addr_t address_;

    }; // class Ipv4Address

} // namespace iron

#endif	/* IRON_COMMON_SRC_IPv4_ADDRESS_H */
