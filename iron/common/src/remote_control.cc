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

/// \brief The IRON remote control server module.
///
/// Provides the IRON software with a reusable component for remote control
/// operations.

#include "remote_control.h"

#include "log.h"
#include "string_utils.h"
#include "unused.h"

#include <string>

#include <cstdlib>
#include <errno.h>
#include <unistd.h>

using ::iron::EndpointInfo;
using ::iron::RemoteControl;
using ::iron::RemoteControlServer;
using ::iron::RemoteControlClient;
using ::iron::RmtCntlMsgType;
using ::rapidjson::SizeType;
using ::rapidjson::StringBuffer;
using ::rapidjson::Value;
using ::rapidjson::Writer;
using ::std::map;
using ::std::string;


namespace
{
  const char*  UNUSED(kClassName)   = "RemoteControl";
  const char*  UNUSED(kSClassName)  = "RemoteControlServer";
  const char*  UNUSED(kCClassName)  = "RemoteControlClient";
  const char*  UNUSED(kEClassName)  = "EndpointInfo";
}

//
// Static class members.
//

uint32_t RemoteControl::next_ep_id_ = 1;

//============================================================================
EndpointInfo::EndpointInfo()
    : id_(0), addr_(), port_(0),
      sock_(0), msg_size_(0), rcv_offset_(0)
{
  ::memset(rcv_buf_, 0, sizeof(rcv_buf_));
}

//============================================================================
EndpointInfo::EndpointInfo(uint32_t id, int ep_sock,
                                      struct sockaddr_in& addr)
    : id_(id), addr_(addr.sin_addr.s_addr), port_(ntohs(addr.sin_port)),
      sock_(ep_sock), msg_size_(0), rcv_offset_(0)
{
  ::memset(rcv_buf_, 0, sizeof(rcv_buf_));
}

//============================================================================
EndpointInfo::~EndpointInfo()
{
  if (sock_ >= 0)
  {
    ::close(sock_);
    sock_ = -1;
  }
}
//============================================================================
int EndpointInfo::ReceiveMessage()
{
  if (msg_size_ == 0)
  {
    // Receive the message delimiter, which is a 4-byte integer (in network
    // byte order) containing the following JSON message length, in bytes.
    if (!Receive(static_cast<int>(sizeof(uint32_t))))
    {
      return -1;
    }

    // Check if all four bytes have been received.
    if (rcv_offset_ == static_cast<int>(sizeof(uint32_t)))
    {
      // Get the message length, and prepare for receiving the message.
      uint32_t*  len_nbo = (uint32_t*)(rcv_buf_);
      msg_size_          = static_cast<int>(ntohl(*len_nbo));
      rcv_offset_        = 0;

      LogD(kSClassName, __func__, "Message length is %d bytes for remote "
           "control endpoint: %s:%d\n", msg_size_, addr_.ToString().c_str(),
           static_cast<int>(port_));

      // Avoid overflowing the receive buffer.  Leave room for a
      // null-terminated string (JSON is a string format).
      if (msg_size_ > (MAX_RC_MSG_SIZE - 1))
      {
        LogE(kSClassName, __func__, "Error, message length %d is too large "
             "for receive buffer length %d.\n", msg_size_, MAX_RC_MSG_SIZE);
        return -1;
      }
    }
  }
  else
  {
    // Receive more of the JSON message.
    if (!Receive(msg_size_))
    {
      return -1;
    }

    // Check if all of the JSON message has been received.
    if (rcv_offset_ == msg_size_)
    {
      // The entire JSON message has been received.  Null-terminate the
      // string so it can be parsed.
      rcv_buf_[msg_size_] = '\0';

      return 1;
    }
  }
  return 0;
}

//============================================================================
bool EndpointInfo::Receive(int total_size)
{
  // Perform the receive.
  ssize_t  bytes = ::recv(sock_, (void*)&(rcv_buf_[rcv_offset_]),
                          (size_t)(total_size - rcv_offset_), 0);

  if (bytes > 0)
  {
    LogD(kEClassName, __func__, "Received %d bytes from the remote control "
         "endpoint: %s:%d\n", static_cast<int>(bytes), addr_.ToString().c_str(),
         static_cast<int>(port_));

    rcv_offset_ += static_cast<int>(bytes);

    return true;
  }

  if (bytes == 0)
  {
    // The endpoint has closed its end of the connection.
    LogD(kEClassName, __func__, "Remote control endpoint %s:%d has closed its "
         "end of the connection.\n", addr_.ToString().c_str(),
         static_cast<int>(port_));
  }
  else
  {
    // An error has occurred.
    LogE(kEClassName, __func__, "Error receiving from endpoint %s:%d: %s.\n",
         addr_.ToString().c_str(), static_cast<int>(port_), strerror(errno));
  }

  return false;
}

//============================================================================
bool EndpointInfo::SendMessage(uint8_t* msg_buf, int msg_len)
{
  // Validate the arguments.
  if ((msg_buf == NULL) || (msg_len < 0))
  {
    return false;
  }

  // Send the message.
  ssize_t  bytes = ::send(sock_, static_cast<void*>(msg_buf), msg_len, 0);

  if (bytes >= 0)
  {
    if (static_cast<int>(bytes) == msg_len)
    {
      LogD(kEClassName, __func__, "Sent %d bytes to the remote control "
           "endpoint: %s:%d\n", static_cast<int>(bytes),
           addr_.ToString().c_str(), static_cast<int>(port_));
    }
    else
    {
      LogD(kEClassName, __func__, "Only sent %d bytes of %d bytes to the "
           "remote control endpoint: %s:%d\n", static_cast<int>(bytes), msg_len,
           addr_.ToString().c_str(), static_cast<int>(port_));
      return false;
    }
  }
  else
  {
    // An error has occurred.
    LogE(kEClassName, __func__, "Error sending to endpoint %s:%d: %s.\n",
         addr_.ToString().c_str(), static_cast<int>(port_), strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
void EndpointInfo::PrepareForNextMessage()
{
  // Reset the receive size and offset.
  msg_size_   = 0;
  rcv_offset_ = 0;
}

//============================================================================
RemoteControl::RemoteControl()
    : document_(), msg_type_(RC_INVALID), msg_id_(0), msg_target_(),
      msg_interval_(0.0), snd_buf_(NULL), send_str_buf_(NULL),
      send_writer_(NULL), endpoint_ready_(NULL), endpoints_()
{
  // Allocate the send buffer.
  if (snd_buf_ == NULL)
  {
    snd_buf_ = new (std::nothrow) uint8_t[MAX_RC_MSG_SIZE];

    if (snd_buf_ == NULL)
    {
      LogF(kSClassName, __func__, "Error allocating send buffer.\n");
    }

    ::memset(snd_buf_, 0, MAX_RC_MSG_SIZE);
  }
}

//============================================================================
RemoteControl::~RemoteControl()
{
  // Delete the send buffers.
  if (snd_buf_ != NULL)
  {
    delete [] snd_buf_;
    snd_buf_ = NULL;
  }

  if (send_writer_ != NULL)
  {
    delete send_writer_;
    send_writer_ = NULL;
  }

  if (send_str_buf_ != NULL)
  {
    delete send_str_buf_;
    send_str_buf_ = NULL;
  }

  //  Destroy the endpoints.
  map<uint32_t, EndpointInfo*>::iterator itr = endpoints_.begin();
  while (itr != endpoints_.end())
  {
    EndpointInfo* ep = itr->second;
    if (ep != NULL)
    {
      delete ep;
    }
    endpoints_.erase(itr);
    itr = endpoints_.begin();
  }

  endpoint_ready_ = NULL;
}

//============================================================================
void RemoteControl::AddFileDescriptors(int& max_fd, fd_set& read_fds) const
{
  if (!endpoints_.empty())
  {
    for (map<uint32_t, EndpointInfo*>::const_iterator it = endpoints_.begin();
         it != endpoints_.end(); ++it)
    {
      EndpointInfo*  ep = it->second;
      if (ep != NULL)
      {
        if (ep->sock_ > max_fd)
        {
          max_fd = ep->sock_;
        }
        FD_SET(ep->sock_, &read_fds);
      }
    }
  }
}

//============================================================================
void RemoteControl::GetMsgBuffer(StringBuffer& str_buf)
{
  Writer<StringBuffer>  writer(str_buf);
  document_.Accept(writer);
}

//============================================================================
bool iron::RemoteControl::SendMessage(EndpointInfo* ep,
                                      rapidjson::StringBuffer& str_buf)
{
  LogD(kClassName, __func__, "Sending message: %s\n",
       str_buf.GetString());

  if (!ep)
  {
    LogE(kClassName, __func__, "Unable to send message.\n");
    return false;
  }

  // Copy the passed message into the send buffer.  Prepend with a 4-byte
  // integer containing the following JSON message length in network byte
  // order.
  int       json_len     = static_cast<int>(str_buf.GetSize());
  uint32_t  json_len_nbo = static_cast<uint32_t>(htonl(json_len));
  int       msg_len      = (json_len + sizeof(json_len_nbo));

  if (msg_len > (MAX_RC_MSG_SIZE - 1))
  {
    LogE(kClassName, __func__, "Error, message length %d is too large for "
         "send buffer length %d.\n", msg_len, MAX_RC_MSG_SIZE);
    // Close the connection.
    endpoints_.erase(ep->id_);
    delete ep;
    return false;
  }

  LogD(kClassName, __func__, "buffer: %s\n", str_buf.GetString());
  ::memcpy(&(snd_buf_[0]), &json_len_nbo, sizeof(json_len_nbo));
  ::memcpy(&(snd_buf_[sizeof(json_len_nbo)]), str_buf.GetString(), json_len);

  // Send the JSON reply message.
  if (!ep->SendMessage(snd_buf_, msg_len))
  {
    // Close the connection.
    endpoints_.erase(ep->id_);
    delete ep;
    return false;
  }
  return true;
}

//============================================================================
bool iron::RemoteControl::SendMessage(uint32_t ep_id,
                                      rapidjson::StringBuffer& str_buf)
{
  if (endpoints_.find(ep_id) != endpoints_.end())
  {
    return(SendMessage(endpoints_[ep_id], str_buf));
  }
  LogE(kClassName, __func__, "Unable to find endpoint to send message : %s\n",
       str_buf.GetString());
  return false;
}

//============================================================================

void RemoteControl::ResetEndpoint()
{
  if (endpoint_ready_)
  {
    endpoint_ready_->PrepareForNextMessage();
    endpoint_ready_ = NULL;
  }
}

//============================================================================
bool RemoteControl::SetJsonMsgId(uint32_t msg_id)
{
  if ((document_.HasMember("msgid")) && (document_["msgid"].IsUint()))
  {
    document_["msgid"].SetUint(msg_id);
    return true;
  }
  return false;
}

//============================================================================
bool RemoteControl::GetGetMessage(
  std::string& target, const rapidjson::Value*& key_array) const
{
  // Make sure that a client has a message ready.
  if (endpoint_ready_ == NULL)
  {
    return false;
  }

  // Reset the client for receiving the next message.
  endpoint_ready_->PrepareForNextMessage();

  // Get access to the "keys" array.
  const Value&  keys = document_["keys"];

  // Check that "keys" is an array of strings.
  if (!keys.IsArray())
  {
    LogE(kSClassName, __func__, "Received JSON get message from %s:%d has "
         "keys that is not an array: %s\n",
         endpoint_ready_->addr_.ToString().c_str(),
         static_cast<int>(endpoint_ready_->port_),
         (char*)(endpoint_ready_->rcv_buf_));
    return false;
  }

  for (SizeType index = 0; index < keys.Size(); ++index)
  {
    if (!keys[index].IsString())
    {
      LogE(kSClassName, __func__, "Received JSON get message from %s:%d has "
           "keys value that is not a string: %s\n",
           endpoint_ready_->addr_.ToString().c_str(),
           static_cast<int>(endpoint_ready_->port_),
           (char*)(endpoint_ready_->rcv_buf_));
      return false;
    }
  }

  // The message looks OK.  Let the caller have access to it.
  target    = msg_target_;
  key_array = &(keys);

  return true;
}

//============================================================================
bool RemoteControl::GetPushMessage(uint32_t& client_id,
            const rapidjson::Value*& key_val) const
{
  // Make sure that a client has a message ready.
  if (endpoint_ready_ == NULL)
  {
    LogD(kSClassName, __func__, "No ready endpoint\n");
    return false;
  }

  // Reset the client for receiving the next message.
  endpoint_ready_->PrepareForNextMessage();

  // Get access to the "keyvals" object.
  const Value&  key_vals = document_["keyvals"];

  // Check that "keyvals" is an object.
  if (!key_vals.IsObject())
  {
    LogE(kSClassName, __func__, "Received JSON push message from %s:%d "
         "has keyvals that is not an object: %s\n",
         endpoint_ready_->addr_.ToString().c_str(),
         static_cast<int>(endpoint_ready_->port_),
         (char*)(endpoint_ready_->rcv_buf_));
    return false;
  }

  // The message looks OK.  Let the caller have access to it.
  client_id = endpoint_ready_->id_;
  key_val = &(key_vals);

  return true;
}

//============================================================================
bool RemoteControl::InSet(int socket, fd_set& read_fds)
{
  return socket >= 0 && FD_ISSET(socket, &read_fds);
}

//============================================================================
bool RemoteControl::ServiceEndpoints(fd_set& read_fds)
{

  EndpointInfo*  ep = NULL;
  // Only service sockets until one client has a message fully received and
  // ready for processing.  This keeps the API and implementation simple.
  // Check that this is the case before we start.
  if (endpoint_ready_ != NULL)
  {
    LogW(kClassName, __func__, "A remote control client (%s:%d) appears to "
         "have a message ready for servicing when it should not.\n",
         endpoint_ready_->addr_.ToString().c_str(),
         static_cast<int>(endpoint_ready_->port_));

  }

  // Check the client sockets last.
  if (!endpoints_.empty())
  {
    // If there is a received message waiting for processing, then we cannot
    // service another client right now.  Notify the caller that a message is
    // ready for processing again.
    if (endpoint_ready_ != NULL)
    {
      return true;
    }

    map<uint32_t, EndpointInfo*>::iterator  it = endpoints_.begin();

    while (it != endpoints_.end())
    {
      ep = it->second;
      //LogD(kClassName, __func__, "Looking at remote control endpoint: "
      //       "%s:%d\n", ci->addr_.ToString().c_str(),
      //       static_cast<int>(ci->port_));

      if ((ep != NULL) && InSet(ep->sock_, read_fds))
      {
        LogD(kClassName, __func__, "Receiving from remote control endpoint: "
             "%s:%d\n", ep->addr_.ToString().c_str(),
             static_cast<int>(ep->port_));

        // Receive message data from the endpoint.
        int  rv = ep->ReceiveMessage();

        if (rv > 0)
        {
          LogD(kClassName, __func__, "Received JSON request message from "
               "%s:%d: %s\n", ep->addr_.ToString().c_str(),
               static_cast<int>(ep->port_), (char*)(ep->rcv_buf_));

          // Attempt to parse the received JSON message.
          if (ParseJsonMessage(ep))
          {
            // The endpoint now has a message ready.  Record the endpoint pointer.
            endpoint_ready_ = ep;
            LogD(kClassName, __func__, "Endpoint ready %u\n", ep->id_);
            break;
          }
          else
          {
            // The message cannot be parsed.  Close the connection.
            LogW(kClassName, __func__, "Cannot parse JSON message\n");
            endpoints_.erase(it);
            delete ep;
            break;
          }
        }
        else if (rv < 0)
        {
          // The endpoint has closed the connection.
          if (endpoint_ready_ == ep)
          {
            endpoint_ready_ = NULL;
          }
          endpoints_.erase(it);
          delete ep;
          LogD(kClassName, __func__, "Client has closed the connection.\n");
          break;
        }
        else
        {
          LogD(kClassName, __func__, "rv is zero\n");
        }
      }

      ++it;
    }
  }

  return(endpoint_ready_ != NULL);
}

//============================================================================
EndpointInfo* RemoteControl::GetEpInfo(uint32_t endpoint_id)
{
  if (endpoints_.find(endpoint_id) != endpoints_.end())
  {
    return endpoints_[endpoint_id];
  }
  return NULL;
}

//============================================================================
RemoteControlClient::RemoteControlClient()
    : RemoteControl(), err_msg_()
{
}

//============================================================================
RemoteControlClient::~RemoteControlClient()
{
}

//============================================================================
uint32_t RemoteControlClient::Connect(struct sockaddr_in svr_addr)
{
  int sock = 0;
  if ((sock = ::socket(PF_INET, SOCK_STREAM, 0)) < 0)
  {
     LogE(kCClassName, __func__,
                      "Error opening TCP server socket to server.\n");
     return 0;
  }

  if (::connect(sock, (struct sockaddr *) &svr_addr, sizeof(svr_addr)) < 0)
  {
     LogE(kCClassName, __func__, "Error connecting to server.\n");
     ::close(sock);
     return 0;
  }

  EndpointInfo* ep = new (std::nothrow)
       EndpointInfo(RemoteControl::next_ep_id_, sock, svr_addr);

  endpoints_[RemoteControl::next_ep_id_] = ep;

  RemoteControl::next_ep_id_++;

  LogI(kCClassName, __func__, "New remote control server: %s:%d\n",
       ep->addr_.ToString().c_str(), static_cast<int>(ep->port_));

  return(ep->id_);
}
//============================================================================
void RemoteControlClient::Disconnect()
{
  map<uint32_t, EndpointInfo*>::iterator it = endpoints_.begin();
  while (it != endpoints_.end())
  {
    map<uint32_t, EndpointInfo*>::iterator  itr = endpoints_.begin();
    EndpointInfo*                           ep = itr->second;
    if (ep != NULL)
    {
      delete ep;
    }
    endpoints_.erase(itr);
  }
}

//============================================================================
bool RemoteControlClient::ServiceFileDescriptors(fd_set& read_fds)
{
  return(ServiceEndpoints(read_fds));
}

//============================================================================
bool RemoteControlClient::ParseJsonMessage(EndpointInfo* si)
{
  // Initialize.
  msg_type_   = RC_INVALID;
  msg_id_     = 0;
  err_msg_    = "";
  msg_target_ = "";

  LogD(kCClassName, __func__, "Parsing message: %s\n",  si->rcv_buf_);

  // Parse the JSON message into a document object (to use DOM-style APIs).
  if (document_.ParseInsitu((char*)(si->rcv_buf_)).HasParseError())
  {
    LogE(kCClassName, __func__, "Error parsing received JSON reply "
         "message from %s:%d: %s\n", si->addr_.ToString().c_str(),
         static_cast<int>(si->port_), (char*)(si->rcv_buf_));
    return false;
  }

  // Make sure that the message is an object (begins with '{' and ends with
  // '}').
  if (!document_.IsObject())
  {
    LogE(kSClassName, __func__, "Request message from %s:%d is not an "
         "object: %s\n", si->addr_.ToString().c_str(),
         static_cast<int>(si->port_), (char*)(si->rcv_buf_));
    return false;
  }

  // Get the message type.
  string   msg_type_str;

  if ((document_.HasMember("msg")) && (document_["msg"].IsString()))
  {
    msg_type_str = document_["msg"].GetString();

    if (msg_type_str == "setreply")
    {
      msg_type_ = RC_SETREPLY;
    }
    else if (msg_type_str == "getreply")
    {
      msg_type_ = RC_GETREPLY;
    }
    else if (msg_type_str == "pusherror")
    {
      msg_type_ = RC_PUSHERR;
    }
    else if (msg_type_str == "push")
    {
      msg_type_ = RC_PUSH;
    }
    else
    {
      LogE(kCClassName, __func__, "Unknown  message type from %s:%d: "
           "%s\n", si->addr_.ToString().c_str(), static_cast<int>(si->port_),
           msg_type_str.c_str());
      return false;
    }
  }
  else
  {
    LogE(kSClassName, __func__, "Message from %s:%d does not have a "
         "message type: %s\n", si->addr_.ToString().c_str(),
         static_cast<int>(si->port_), (char*)(si->rcv_buf_));
    return false;
  }

  // Get the messge identifier.
  if ((document_.HasMember("msgid")) && (document_["msgid"].IsUint()))
  {
    msg_id_ = document_["msgid"].GetUint();
  }
  else
  {
    LogE(kSClassName, __func__, "Reply message from %s:%d does not have a "
         "message id: %s\n", si->addr_.ToString().c_str(),
         static_cast<int>(si->port_), (char*)(si->rcv_buf_));
    return false;
  }

  // Get the target if there is one (not present in replies).
  if ((document_.HasMember("tgt")) && (document_["tgt"].IsString()))
  {
    msg_target_ = document_["tgt"].GetString();
  }

  // If the request was not successful, get the error message.
  if ((document_.HasMember("errmsg")) && (document_["errmsg"].IsString()))
  {
    err_msg_ = document_["errmsg"].GetString();
  }
  return true;
}

//============================================================================
void RemoteControlClient::SendSetMessage(uint32_t ep_id,
                                         const std::string &target,
                                         const std::string &cmd,
                                         const std::string &arg,
                                         uint32_t msg_id)
{

  // Create the JSON response message.
  StringBuffer          str_buf;
  Writer<StringBuffer>  writer(str_buf);

  writer.StartObject();

  writer.Key("msg");
  writer.String("set");

  writer.Key("msgid");
  if (msg_id != 0)
  {
    writer.Uint(msg_id);
  }
  else
  {
    writer.Uint(msg_id_);
    ++msg_id_;
  }

  writer.Key("tgt");
  writer.String(target.c_str());

  writer.Key("keyvals");

  writer.StartObject();
  writer.Key(cmd.c_str());
  writer.String(arg.c_str());
  writer.EndObject();

  writer.EndObject();
  SendMessage(ep_id, str_buf);

  // The endpoint is no longer ready.
  endpoint_ready_ = NULL;
}

//============================================================================
void RemoteControlClient::SendSetMessage(uint32_t ep_id,
                                         const std::string &target,
                                         const std::string &arg,
                                         uint32_t msg_id)
{

  // Create the JSON response message.
  StringBuffer          str_buf;
  Writer<StringBuffer>  writer(str_buf);

  writer.StartObject();

  writer.Key("msg");
  writer.String("set");

  writer.Key("msgid");
  if (msg_id != 0)
  {
    writer.Uint(msg_id);
  }
  else
  {
    writer.Uint(msg_id_);
    ++msg_id_;
  }

  writer.Key("tgt");
  writer.String(target.c_str());

  writer.Key("keyvals");
  writer.StartObject();

  List<string>  tokens;
  StringUtils::Tokenize(arg, ";", tokens);

  while (tokens.size() > 1)
  {
    string token;
    tokens.Pop(token);
    writer.Key(token.c_str());
    tokens.Pop(token);
    writer.String(token.c_str());
  }

  if (tokens.size() == 1)
  {
    LogE(kClassName, __func__,
         "Set message has wrong number of parameters: %s\n", arg.c_str());
  }

  writer.EndObject();
  writer.EndObject();
  SendMessage(ep_id, str_buf);

  // The endpoint is no longer ready.
  endpoint_ready_ = NULL;
}
//============================================================================
RemoteControlServer::RemoteControlServer()
    : RemoteControl(), server_sock_(-1)
{
}

//============================================================================
RemoteControlServer::~RemoteControlServer()
{
  endpoint_ready_ = NULL;

  // Close the server socket.
  if (server_sock_ >= 0)
  {
    ::close(server_sock_);
    server_sock_ = -1;
  }
}

//============================================================================
bool RemoteControlServer::Initialize(uint16_t tcp_port)
{
  // Only allow successful initialization once.
  if (server_sock_ >= 0)
  {
    LogE(kSClassName, __func__, "Error, the remote control server has already "
         "been initialized.\n");
    return false;
  }

  LogC(kSClassName, __func__, "Initializing remote control server on TCP port "
       "%d.\n", static_cast<int>(tcp_port));

  // Create the TCP server socket for accepting connections.
  if ((server_sock_ = ::socket(PF_INET, SOCK_STREAM, 0)) < 0)
  {
    LogE(kSClassName, __func__, "Error opening TCP server socket: %s\n",
         strerror(errno));
    return false;
  }

  // Bind the socket to the specified port number.
  struct sockaddr_in  addr;

  ::memset(&addr, 0, sizeof(addr));
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port        = htons(tcp_port);

  if (::bind(server_sock_, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    LogE(kSClassName, __func__, "Error binding TCP server socket to port %d: "
         "%s\n", static_cast<int>(tcp_port), strerror(errno));
    ::close(server_sock_);
    server_sock_ = -1;
    return false;
  }

  // Listen on the socket.
  if (::listen(server_sock_, 3) < 0)
  {
    LogE(kSClassName, __func__, "Error listening on TCP server socket: %s\n",
         strerror(errno));
    ::close(server_sock_);
    server_sock_ = -1;
    return false;
  }

  return true;
}

//============================================================================
void RemoteControlServer::AbortClient()
{
  if (endpoint_ready_ != NULL)
  {
    // Close the connection.
    endpoints_.erase(endpoint_ready_->id_);
    delete endpoint_ready_;
    endpoint_ready_ = NULL;
  }
}

//============================================================================
void RemoteControlServer::AddFileDescriptors(int& max_fd,
                                             fd_set& read_fds) const
{
  if (server_sock_ >= 0)
  {
    if (server_sock_ > max_fd)
    {
      max_fd = server_sock_;
    }
    FD_SET(server_sock_, &read_fds);
  }
  RemoteControl::AddFileDescriptors(max_fd, read_fds);
}

//============================================================================
bool RemoteControlServer::ServiceFileDescriptors(fd_set& read_fds)
{
  EndpointInfo*  ep = NULL;

  // Only service sockets until one client has a message fully received and
  // ready for processing.  This keeps the API and implementation simple.
  // Check that this is the case before we start.
  if (endpoint_ready_ != NULL)
  {
    LogW(kSClassName, __func__, "A remote control client (%s:%d) appears to "
         "have a message ready for servicing when it should not.\n",
         endpoint_ready_->addr_.ToString().c_str(),
         static_cast<int>(endpoint_ready_->port_));
  }

  // Check the server socket first.
  if (InSet(server_sock_, read_fds))
  {
    // Accept a new client connection.
    struct sockaddr_in  addr;
    socklen_t           addr_len = sizeof(addr);

    ::memset(&addr, 0, sizeof(addr));

    int  cs = ::accept(server_sock_, (struct sockaddr *)&addr, &addr_len);

    if (cs < 0)
    {
      LogE(kSClassName, __func__, "Error accepting new client TCP connection: "
           "%s\n", strerror(errno));
      return false;
    }

    // Create a new client entry.
    ep = new (std::nothrow) EndpointInfo(RemoteControl::next_ep_id_, cs, addr);

    if (ep == NULL)
    {
      LogE(kSClassName, __func__, "Memory allocation error.\n");
      ::close(cs);
      return false;
    }

    endpoints_[ep->id_] = ep;
    RemoteControlServer::next_ep_id_++;

    LogI(kSClassName, __func__, "New remote control client: %s:%d\n",
         ep->addr_.ToString().c_str(), static_cast<int>(ep->port_));
  }

  ServiceEndpoints(read_fds);

  return(endpoint_ready_ != NULL);
}

//============================================================================
bool RemoteControlServer::ParseJsonMessage(EndpointInfo* ep)
{
  // Initialize.
  msg_type_   = RC_INVALID;
  msg_id_     = 0;
  msg_target_ = "";

  // Parse the JSON message into a document object (to use DOM-style APIs).
  if (document_.ParseInsitu((char*)(ep->rcv_buf_)).HasParseError())
  {
    LogE(kSClassName, __func__, "Error parsing received JSON request "
         "message from %s:%d: %s\n", ep->addr_.ToString().c_str(),
         static_cast<int>(ep->port_), (char*)(ep->rcv_buf_));
    return false;
  }

  // Make sure that the message is an object (begins with '{' and ends with
  // '}').
  if (!document_.IsObject())
  {
    LogE(kSClassName, __func__, "Request message from %s:%d is not an "
         "object: %s\n", ep->addr_.ToString().c_str(),
         static_cast<int>(ep->port_), (char*)(ep->rcv_buf_));
    return false;
  }

  // Get the message type.
  string   msg_type_str;

  if ((document_.HasMember("msg")) && (document_["msg"].IsString()))
  {
    msg_type_str = document_["msg"].GetString();

    if (msg_type_str == "set")
    {
      msg_type_ = RC_SET;
    }
    else if (msg_type_str == "get")
    {
      msg_type_ = RC_GET;
    }
    else if (msg_type_str == "pushreq")
    {
      msg_type_ = RC_PUSHREQ;
    }
    else if (msg_type_str == "pushstop")
    {
      msg_type_ = RC_PUSHSTOP;
    }
    else
    {
      LogE(kSClassName, __func__, "Unknown request message type from %s:%d: "
           "%s\n", ep->addr_.ToString().c_str(), static_cast<int>(ep->port_),
           msg_type_str.c_str());
      return false;
    }
  }
  else
  {
    LogE(kSClassName, __func__, "Request message from %s:%d does not have a "
         "message type: %s\n", ep->addr_.ToString().c_str(),
         static_cast<int>(ep->port_), (char*)(ep->rcv_buf_));
    return false;
  }

  // Get the messge identifier.
  if ((document_.HasMember("msgid")) && (document_["msgid"].IsUint()))
  {
    msg_id_ = document_["msgid"].GetUint();
  }
  else
  {
    LogE(kSClassName, __func__, "Request message from %s:%d does not have a "
         "message id: %s\n", ep->addr_.ToString().c_str(),
         static_cast<int>(ep->port_), (char*)(ep->rcv_buf_));
    return false;
  }
  // Get the message target.
  if ((document_.HasMember("tgt")) && (document_["tgt"].IsString()))
  {
    msg_target_ = document_["tgt"].GetString();
  }

  LogD(kSClassName, __func__, "Request message from %s:%d has: type=%s id=%"
       PRIu32 " target=%s\n", ep->addr_.ToString().c_str(),
       static_cast<int>(ep->port_), msg_type_str.c_str(), msg_id_,
       msg_target_.c_str());

  return true;
}

//============================================================================
bool RemoteControlServer::GetSetMessage(
  std::string& target, const rapidjson::Value*& key_value_object) const
{
  // Make sure that a client has a message ready.
  if (endpoint_ready_ == NULL)
  {
    return false;
  }

  // Reset the client for receiving the next message.
  endpoint_ready_->PrepareForNextMessage();

  // Get access to the "keyvals" object.
  const Value&  key_vals = document_["keyvals"];

  LogW(kSClassName, __func__, "Got set message from %s\n",
       endpoint_ready_->addr_.ToString().c_str());

  // Check that "keyvals" is an object.
  if (!key_vals.IsObject())
  {
    LogE(kSClassName, __func__, "Received JSON request set message from %s:%d "
         "has keyvals that is not an object: %s\n",
         endpoint_ready_->addr_.ToString().c_str(),
         static_cast<int>(endpoint_ready_->port_),
         (char*)(endpoint_ready_->rcv_buf_));
    return false;
  }

  // The message looks OK.  Let the caller have access to it.
  target           = msg_target_;
  key_value_object = &(key_vals);

  return true;
}

//============================================================================
bool RemoteControlServer::GetSetMessage( std::string& target,
     const rapidjson::Value*& key_value_object,
     Ipv4Address& saddr) const
{
  if (GetSetMessage(target, key_value_object))
  {
    saddr            = endpoint_ready_->addr_;
    return true;
  }
  return false;
}

//============================================================================
void RemoteControlServer::SendSetReplyMessage(
  bool success, const std::string& error_msg)
{
  // Make sure that a client has a message ready.
  if (endpoint_ready_ == NULL)
  {
    return;
  }

  // Create the JSON response message.
  StringBuffer          str_buf;
  Writer<StringBuffer>  writer(str_buf);

  writer.StartObject();

  writer.Key("msg");
  writer.String("setreply");

  writer.Key("msgid");
  writer.Uint(msg_id_);

  writer.Key("success");
  writer.Bool(success);

  if (!success)
  {
    writer.Key("errmsg");
    writer.String(error_msg.c_str());
  }

  writer.EndObject();
  SendMessage(endpoint_ready_, str_buf);

  // The client is no longer ready.
  endpoint_ready_ = NULL;
}

//============================================================================
Writer<StringBuffer>* RemoteControlServer::StartGetReplyMessage(
  bool success, const std::string& error_msg)
{
  // Make sure that a client has a message ready.
  if (endpoint_ready_ == NULL)
  {
    return NULL;
  }

  if (send_writer_ != NULL)
  {
    LogE(kSClassName, __func__, "Error, send_writer_ is not NULL.\n");
    delete send_writer_;
    send_writer_ = NULL;
  }

  if (send_str_buf_ != NULL)
  {
    LogE(kSClassName, __func__, "Error, send_str_buf_ is not NULL.\n");
    delete send_str_buf_;
    send_str_buf_ = NULL;
  }

  // Dynamically allocate a writer that will not go out of scope when this
  // method returns.
  send_str_buf_ = new (std::nothrow) StringBuffer();

  if (send_str_buf_ == NULL)
  {
    LogE(kSClassName, __func__, "Error allocating send_str_buf_.\n");
    return NULL;
  }

  send_writer_ = new (std::nothrow) Writer<StringBuffer>(*send_str_buf_);

  if (send_writer_ == NULL)
  {
    LogE(kSClassName, __func__, "Error allocating send_writer_.\n");
    delete send_str_buf_;
    send_str_buf_ = NULL;
    return NULL;
  }

  // Create the start of the JSON response message.
  send_writer_->StartObject();

  send_writer_->Key("msg");
  send_writer_->String("getreply");

  send_writer_->Key("msgid");
  send_writer_->Uint(msg_id_);

  send_writer_->Key("success");
  send_writer_->Bool(success);

  if (!success)
  {
    send_writer_->Key("errmsg");
    send_writer_->String(error_msg.c_str());

    return NULL;
  }

  send_writer_->Key("keyvals");
  send_writer_->StartObject();

  return send_writer_;
}

//============================================================================
void RemoteControlServer::SendGetReplyMessage(bool success)
{
  if ((send_str_buf_ == NULL) || (send_writer_ == NULL))
  {
    LogE(kSClassName, __func__, "Writer or string buffer is NULL.\n");
  }
  else
  {
    // Close the keyvals and outer-most objects and send the reply message.
    if (success)
    {
      send_writer_->EndObject();
    }
    send_writer_->EndObject();
    SendMessage(endpoint_ready_, *send_str_buf_);
  }

  // The client is no longer ready.
  endpoint_ready_ = NULL;

  // The dynamically allocated writer can be deleted.
  if (send_writer_ != NULL)
  {
    delete send_writer_;
    send_writer_ = NULL;
  }

  if (send_str_buf_ != NULL)
  {
    delete send_str_buf_;
    send_str_buf_ = NULL;
  }
}

//============================================================================
bool RemoteControlServer::GetPushRequestMessage(
  uint32_t& client_id, uint32_t& msg_id, std::string& target,
  double& interval_sec, const rapidjson::Value*& key_array)
{
  // Make sure that a client has a message ready.
  if (endpoint_ready_ == NULL)
  {
    return false;
  }

  // Initialize.
  msg_interval_ = 0.0;

  // Reset the client for receiving the next message.
  endpoint_ready_->PrepareForNextMessage();

  // Get the message interval
  if ((document_.HasMember("intv")) && (document_["intv"].IsDouble()))
  {
    msg_interval_ = document_["intv"].GetDouble();
  }
  else if ((document_.HasMember("intv")) && (document_["intv"].IsInt()))
  {
    msg_interval_ = static_cast<double>(document_["intv"].GetInt());
  }
  else
  {
    LogE(kSClassName, __func__, "Received JSON pushreq message from %s:%d "
         "does not have a numeric interval: %s\n",
         endpoint_ready_->addr_.ToString().c_str(),
         static_cast<int>(endpoint_ready_->port_),
         (char*)(endpoint_ready_->rcv_buf_));
    SendPushErrorMessage(endpoint_ready_, msg_id_, "'intv' must be numeric.");
    // There is no immediate response message.
    endpoint_ready_ = NULL;
    return false;
  }

  // Get access to the "keys" array.
  const Value&  keys = document_["keys"];

  // Check that "keys" is an array of strings.
  if (!keys.IsArray())
  {
    LogE(kSClassName, __func__, "Received JSON pushreq message from %s:%d "
         "has keys that is not an array: %s\n",
         endpoint_ready_->addr_.ToString().c_str(),
         static_cast<int>(endpoint_ready_->port_),
         (char*)(endpoint_ready_->rcv_buf_));
    SendPushErrorMessage(endpoint_ready_, msg_id_, "'keys' must be an array.");
    // There is no immediate response message.
    endpoint_ready_ = NULL;
    return false;
  }

  for (SizeType index = 0; index < keys.Size(); ++index)
  {
    if (!keys[index].IsString())
    {
      LogE(kSClassName, __func__, "Received JSON pushreq message from %s:%d "
           "has keys value that is not a string: %s\n",
           endpoint_ready_->addr_.ToString().c_str(),
           static_cast<int>(endpoint_ready_->port_),
           (char*)(endpoint_ready_->rcv_buf_));
      SendPushErrorMessage(endpoint_ready_, msg_id_, "Values in 'keys' array must be strings.");
      // There is no immediate response message.
      endpoint_ready_ = NULL;
      return false;
    }
  }

  // The message looks OK.  Let the caller have access to it.
  client_id    = endpoint_ready_->id_;
  msg_id       = msg_id_;
  target       = msg_target_;
  interval_sec = msg_interval_;
  key_array    = &(keys);

  // There is no immediate response message.
  endpoint_ready_ = NULL;

  return true;
}

//============================================================================
bool RemoteControlServer::GetPushRequestOptions(const string& key,
                                                string& option)
{
  // Get access to the "options" object.
  const Value&  options = document_["options"];

  // Check that "options" is an object.
  if (!options.IsObject())
  {
    LogE(kSClassName, __func__, "Received JSON pushreq message has options "
         "that is not an object.\n"); 
    return false;
  }

  Value::ConstMemberIterator  itr = options.FindMember(key.c_str());
  if (itr == options.MemberEnd())
  {
    LogW(kSClassName, __func__, "No options found for key: %s.\n",
         key.c_str());
    return false;
  }

  // Get the value for the key and ensure that it is a string.
  const Value&  opt = itr->value;
  if (!opt.IsString())
  {
    LogE(kSClassName, __func__, "Push request option must be a string.\n");
    return false;
  }

  // Return the option for the key to the caller.
  option = opt.GetString();

  return true;
}

//============================================================================
Writer<StringBuffer>* RemoteControlServer::StartPushMessage(
  uint32_t client_id, uint32_t msg_id)
{
  // Find the client.
  EndpointInfo* ep = GetEpInfo(client_id);

  if (ep == NULL)
  {
    LogD(kSClassName, __func__, "Cannot find EndpointInfo for client id %"
         PRIu32 ", client must have closed the connection.\n", client_id);
    return NULL;
  }

  if (send_writer_ != NULL)
  {
    LogE(kSClassName, __func__, "Error, send_writer_ is not NULL.\n");
    delete send_writer_;
    send_writer_ = NULL;
  }

  if (send_str_buf_ != NULL)
  {
    LogE(kSClassName, __func__, "Error, send_str_buf_ is not NULL.\n");
    delete send_str_buf_;
    send_str_buf_ = NULL;
  }

  // Dynamically allocate a writer that will not go out of scope when this
  // method returns.
  send_str_buf_ = new (std::nothrow) StringBuffer();

  if (send_str_buf_ == NULL)
  {
    LogE(kSClassName, __func__, "Error allocating send_str_buf_.\n");
    // Close the connection.
    endpoints_.erase(ep->id_);
    delete ep;
    return NULL;
  }

  send_writer_ = new (std::nothrow) Writer<StringBuffer>(*send_str_buf_);

  if (send_writer_ == NULL)
  {
    LogE(kSClassName, __func__, "Error allocating send_writer_.\n");
    delete send_str_buf_;
    send_str_buf_ = NULL;
    // Close the connection.
    endpoints_.erase(ep->id_);
    delete ep;
    return NULL;
  }

  // Create the start of the JSON message.
  send_writer_->StartObject();

  send_writer_->Key("msg");
  send_writer_->String("push");

  send_writer_->Key("msgid");
  send_writer_->Uint(msg_id);

  send_writer_->Key("keyvals");
  send_writer_->StartObject();

  return send_writer_;
}

//============================================================================
void RemoteControlServer::SendPushMessage(uint32_t ep_id)
{
  // Find the client.
  EndpointInfo*  ep = GetEpInfo(ep_id);

  if (ep != NULL)
  {
    if ((send_str_buf_ == NULL) || (send_writer_ == NULL))
    {
      LogE(kSClassName, __func__, "Writer or string buffer is NULL.\n");
      // Close the connection.
      endpoints_.erase(ep->id_);
      delete ep;
    }
    else
    {
      // Close the keyvals and outer-most objects and send the reply message.
      send_writer_->EndObject();
      send_writer_->EndObject();
      SendMessage(ep, *send_str_buf_);
    }
  }
  else
  {
    LogE(kSClassName, __func__, "Error, cannot find EndpointInfo for client id %"
         PRIu32 ".\n", ep_id);
  }

  // The dynamically allocated writer can be deleted.
  if (send_writer_ != NULL)
  {
    delete send_writer_;
    send_writer_ = NULL;
  }

  if (send_str_buf_ != NULL)
  {
    delete send_str_buf_;
    send_str_buf_ = NULL;
  }
}

//============================================================================
void iron::RemoteControlServer::SendPushErrorMessage(
  uint32_t client_id, uint32_t msg_id, const std::string& error_msg)
{
  // Find the client.
  EndpointInfo*  ep = GetEpInfo(client_id);

  if (ep == NULL)
  {
    LogE(kSClassName, __func__, "Error, cannot find EndpointInfo for client id %"
         PRIu32 ".\n", client_id);
    return;
  }
  SendPushErrorMessage(ep, msg_id, error_msg);
}

//============================================================================
void iron::RemoteControlServer::SendPushErrorMessage(
  EndpointInfo* ep, uint32_t msg_id, const std::string& error_msg)
{
  if (ep == NULL)
  {
    LogE(kSClassName, __func__, "Error, EndpointInfo must not be null.\n");
    return;
  }

  // Create the JSON response message.
  StringBuffer          str_buf;
  Writer<StringBuffer>  writer(str_buf);

  writer.StartObject();

  writer.Key("msg");
  writer.String("pusherror");

  writer.Key("msgid");
  writer.Uint(msg_id);

  writer.Key("errmsg");
  writer.String(error_msg.c_str());

  writer.EndObject();
  SendMessage(ep, str_buf);
}

//============================================================================
bool RemoteControlServer::GetPushStopMessage(
  uint32_t& client_id, uint32_t& msg_id, std::string& target,
  uint32_t& to_stop_count)
{
  to_stop_count = 0;
  // Make sure that a client has a message ready.
  if (endpoint_ready_ == NULL)
  {
    return false;
  }
  
  // Reset the client for receiving the next message.
  endpoint_ready_->PrepareForNextMessage();

  if (document_.HasMember("to_stop")) {
    const Value& to_stop = document_["to_stop"];
    if (!to_stop.IsArray()) {
      LogE(kSClassName, __func__, "Received JSON pushstop message from %s:%d "
           "has to_stop that is not an array: %s\n",
           endpoint_ready_->addr_.ToString().c_str(),
           static_cast<int>(endpoint_ready_->port_),
           (char*)(endpoint_ready_->rcv_buf_));
      SendPushErrorMessage(endpoint_ready_, msg_id_, "'to_stop' must be an array "
                           "if present.");
      // There is no immediate response message.
      endpoint_ready_ = NULL;
      return false;
    }

    if (to_stop.Size() != 0)
    {
      for (SizeType index = 0; index < to_stop.Size(); ++index)
      {
        if (!to_stop[index].IsUint())
        {
          LogE(kSClassName, __func__, "Received JSON pushstop message from %s:%d "
               "has to_stop value that is not an unsigned integer : %s\n",
               endpoint_ready_->addr_.ToString().c_str(),
               static_cast<int>(endpoint_ready_->port_),
               (char*)(endpoint_ready_->rcv_buf_));
          SendPushErrorMessage(endpoint_ready_, msg_id_, "'to_stop' an array must "
                               "have unsigned integer values.");
          // There is no immediate response message.
          endpoint_ready_ = NULL;
          return false;
        }
        LogD(kSClassName, __func__, "to_stop[%u]: %" PRIu32 "\n",
             index, to_stop[index].GetUint());
      }

      to_stop_count = to_stop.Size();
    }
  }

  // The message looks OK.  Let the caller have access to it.
  client_id = endpoint_ready_->id_;
  msg_id = msg_id_;
  target = msg_target_;

  // There is no immediate response message.
  endpoint_ready_ = NULL;

  return true;
}

//============================================================================
bool RemoteControlServer::GetPushStopToStopId(const uint32_t& index, uint32_t& id)
{
  if (!document_.HasMember("to_stop"))
  {
    LogE(kSClassName, __func__, "Message did not have a \"to_stop\" value.\n");
    return false;
  }

  const Value& to_stop = document_["to_stop"];
  if (!to_stop.IsArray())
  {
    LogE(kSClassName, __func__, "\"to_stop\" was not an array.\n");
    return false;
  }

  if (index >= to_stop.Size())
  {
    LogE(kSClassName, __func__, "Index (%" PRIu32 ") was to large for array of size %u.\n",
         index, to_stop.Size());
    return false;
  }

  const Value& msg_id = to_stop[index];
  if (msg_id.IsUint())
  {
    id = msg_id.GetUint();
    return true;
  }
  LogE(kSClassName, __func__, "Value at index %" PRIu32 " was not an unsigned int.\n");
  return false;
}
