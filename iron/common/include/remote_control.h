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

#ifndef IRON_COMMON_REMOTE_CONTROL_H
#define IRON_COMMON_REMOTE_CONTROL_H

#include "ipv4_address.h"

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <map>
#include <string>

#include <stdint.h>
#include <sys/select.h>


#define MAX_RC_MSG_SIZE  65535


namespace iron
{

  typedef enum
  {
    RC_SET,
    RC_GET,
    RC_PUSH,
    RC_PUSHREQ,
    RC_PUSHSTOP,
    RC_SETREPLY,
    RC_GETREPLY,
    RC_PUSHERR,
    RC_INVALID
  } RmtCntlMsgType;

  /// A class for holding and managing he remote control endpoint information.
  /// The remote control client/server uses this object to send and receive
  /// messaged over the socket assigned to the connection.
  class EndpointInfo
  {

  public:

    /// \brief The default construtor.
    EndpointInfo();

    /// \brief The constructor.
    ///
    /// Takes ownership of the socket.
    ///
    /// \param  id           The unique identifier assigned to the endpoint.
    /// \param  ep_sock      The end_point socket file descriptor.
    /// \param  addr         A reference to the endpoint's address and port
    ///                      number.
    EndpointInfo(uint32_t id, int ep_sock, struct sockaddr_in& addr);

    /// \brief The destructor.
    virtual ~EndpointInfo();

    /// \brief Receive a message from the endpoint.
    ///
    /// \return  Returns one if the entire JSON message has been received, 0
    ///          if the entire JSON message has not yet been received, or -1
    ///          if the endpoint connection should be closed.
    int ReceiveMessage();

    /// \brief Attempt to receive from the endpoint.
    ///
    /// \param  total_size  The total size of the data to be received in the
    ///                     receive buffer, in bytes.
    ///
    /// \return  True on success, or false if the endpoint connection should
    ///          be closed.
    bool Receive(int total_size);

    /// \brief Send a message to the endpoint.
    ///
    /// \param  msg_buf  A pointer to the buffer containing the message.
    /// \param  msg_len  The message length in bytes.
    ///
    /// \return  True on success, or false otherwise.
    bool SendMessage(uint8_t* msg_buf, int msg_len);

    /// \brief Prepare the endpoint for receiving the next request message.
    void PrepareForNextMessage();

    /// The endpoint's identifer.
    uint32_t           id_;

    /// The endpoint's IP address.
    iron::Ipv4Address  addr_;

    /// The endpoint's TCP port number.
    int                port_;

    /// The endpoint socket.
    int                sock_;

    /// The total size of the message to be received.  When equal to zero,
    /// the message delimiter is being received.  When non-zero, the JSON
    /// message is being received.  In bytes.
    int                msg_size_;

    /// The amount of the message length or JSON message received thus far.
    /// In bytes.
    int                rcv_offset_;

    /// The receive message buffer.
    uint8_t            rcv_buf_[MAX_RC_MSG_SIZE];

  private:

    /// \brief Copy constructor.
    EndpointInfo(const EndpointInfo& other);

    /// \brief Copy operator.
    EndpointInfo& operator=(const EndpointInfo& other);

  }; // class EndpointInfo

  /// All of the messages sent and received by this class are in JSON format.
  /// Individual messages are delimited by prepending a 4-byte unsigned
  /// integer (in network byte order) of the JSON message length (in bytes)
  /// before the JSON message itself.  Because of this framing, a single TCP
  /// connection from a client to this server may be used for many different
  /// transactions over a long period of time.
  ///
  /// The supported JSON messages are as follows:
  ///
  /// | Client Message    | Server Message(s) |
  /// | --------------    | ----------------- |
  /// | set               | setreply          |
  /// | get               | getreply          |
  /// | pushreq, pushstop | push, pusherror   |
  /// | (close socket)    | close             |
  ///
  /// Most messages contains a "msgid" (message identifier) field.  This is a
  /// large integer assigned by the originator of the "set", "get", or
  /// "pushreq" message and is used to pair reply messages with the original
  /// request message.  It is important that the server send the correct
  /// "msgid" in each of the reply messages.
  ///
  /// For the set actions, the client sends a "set" message to the server, and
  /// the server responds with a "setreply" message.  The "msgid" field is
  /// used to pair messages.
  ///
  /// For the get actions, the client sends a "get" message to the server, and
  /// the server responds with a "getreply" message.  The "msgid" field is
  /// used to pair messages.
  ///
  /// For the push actions, the client sends a "pushreq" (push request)
  /// message to the server, specifying what information it wants pushed to it
  /// periodically as well as the interval between updates.  If the server
  /// encounters an error servicing the push request, then the server responds
  /// with a "pusherror" message and the push action is canceled.  If the
  /// server can handle all of the push request, then it sends "push" messages
  /// containing the requested information to the client at the requested
  /// interval using the "msgid" field from the "pushreq" message.  The "push"
  /// messages continue until the client either sends a "pushstop" message to
  /// the server or closes its TCP connection to the server.  The "msgid"
  /// field is used to pair "push" messages to the original "pushreq" message.
  ///
  /// For the close action, the server sends a "close" message to the client
  /// when it wants to terminate the connection.  The client must then close
  /// its TCP connection to the server.  This prevents the server's well-known
  /// TCP port number from becoming stuck in a half-close state.  Note that
  /// the client should simply close its TCP connection to the server whenever
  /// it is done with the connection -- no message exchanges are required in
  /// this case.
  ///
  /// The JSON messages have the following formats:
  ///
  ///
  /// \verbatim
  /// {
  ///   "msg": "set",
  ///   "msgid": 1234,
  ///   "tgt": "pc:1",
  ///   "keyvals": { "MaxLineRateKbps": "1.234",
  ///                "OtherParam": "8",
  ///                ...
  ///              }
  /// }
  ///
  /// {
  ///   "msg": "setreply",
  ///   "msgid": 1234,
  ///   "success": true
  /// }
  ///
  /// {
  ///   "msg": "setreply",
  ///   "msgid": 1234,
  ///   "success": false,
  ///   "errmsg": "Invalid value."
  /// }
  ///
  /// {
  ///   "msg": "get",
  ///   "msgid": 234,
  ///   "tgt": "udp_proxy",
  ///   "keys": [ "stats", "uptime", ... ]
  /// }
  ///
  /// {
  ///   "msg": "getreply",
  ///   "msgid": 234,
  ///   "success": true,
  ///   "keyvals": { "stats": <val>,
  ///                "uptime": <val>,
  ///                ...
  ///              }
  /// }
  ///
  /// {
  ///   "msg": "getreply",
  ///   "msgid": 234,
  ///   "success": false,
  ///   "errmsg": "Unknown key."
  /// }
  ///
  /// {
  ///   "msg": "pushreq",
  ///   "msgid": 34,
  ///   "tgt": "tcp_proxy",
  ///   "intv": 1.5,
  ///   "keys": [ "stats", "flow_stats", "uptime", ... ]
  ///   "options" : { "flow_stats" : <val> }
  /// }
  /// "options" is optional, but some specific key values may require an
  /// associated value (Ex. "flow_stats").
  ///
  /// {
  ///   "msg": "push",
  ///   "msgid": 34,
  ///   "keyvals": { "stats": <val>,
  ///                "flow_stats": <val>,
  ///                "uptime": <val>,
  ///                ...
  ///              }
  /// }
  ///
  /// {
  ///   "msg": "pusherror",
  ///   "msgid": 34,
  ///   "errmsg": "Unknown key."
  /// }
  ///
  /// {
  ///   "msg": "pushstop",
  ///   "msgid": 34,
  ///   "tgt": "tcp_proxy",
  ///   "to_stop": [234, ...]
  /// }
  //  "to_stop" is optional. If omitted or an empty list, the receiver should
  /// stop all push requests. If included, it is a list of message ids that
  /// correspond to the push requests to be stopped.
  ///
  /// {
  ///   "msg": "close"
  /// }
  /// \endverbatim


  class RemoteControl
  {

  public:

    /// \brief The default constructor.
    RemoteControl();

    /// \brief The destructor.
    virtual ~RemoteControl();

    /// \brief Add file descriptors to a read mask.
    ///
    /// This method is to be used in the main processing loop, before the
    /// common select(2) call is made.  The read mask is for use in the
    /// select(2) call.  This method does not clear the read mask -- any
    /// existing file descriptors in the mask are left unchanged.
    ///
    /// \param  max_fd    A reference to the maximum file descriptor value to
    ///                   be updated.
    /// \param  read_fds  A reference to the read mask to be updated.
    void AddFileDescriptors(int& max_fd, fd_set& read_fds) const;

    /// \brief Serialize the document object into a string buffer that is
    /// ready for transmission.
    ///
    /// This method can be used to get a JSON message out of one remote control
    /// object, in a form that can be sent through another remote control
    /// object.
    ///
    /// \param str_buffer A reference to a string object
    void GetMsgBuffer(rapidjson::StringBuffer& str_buffer);

    /// \brief Send a JSON-formatted message to an endpoint.
    ///
    /// \param  ep       A pointer to the EndpointInfo object for the
    ///                  remote endpoint.
    /// \param  str_buf  A reference to the string buffer wrapped by the JSON
    ///                  writer.
    /// \return true if the message was successfully sent.
    bool SendMessage(EndpointInfo* ep, rapidjson::StringBuffer& str_buf);

    /// \brief Send a JSON-formatted message to an endpoint, specifed
    ///        by endpoint ID.
    ///
    /// \param ep_id    The ID of the destination endpoint.
    /// \param str_buf  A reference to the string buffer wrapped by the JSON
    ///                  writer.
    /// \return true if the message was successfully sent.
    bool SendMessage(uint32_t ep_id, rapidjson::StringBuffer& str_buf);

    /// \brief Parse a received message into a JSON formatted document
    /// document, and extract common message attributes into the remote
    /// control object.
    ///
    /// The remote control client and server expect different types of
    /// messages, and each implements this method.
    ///
    /// \param ep A pointer to the endpoint object with the received message.
    /// \return True if the message was successfully parsed.
    virtual bool ParseJsonMessage(EndpointInfo* ep) = 0;

    /// \brief Get an endpoint ready to receive a new message after
    /// processing an existing message.
    void ResetEndpoint();

    /// \brief  Set the message id inside the json-formatted document.
    ///
    /// \param  msg_id  The message id to be placed inside the json doc object.
    ///
    /// \return True on success, false otherwise.
    bool SetJsonMsgId(uint32_t msg_id);

    /// \brief Get the target of the most recently parsed message.
    /// \return The target, as a std::string, of the most recently
    /// processed message from the remote control object.
    inline ::std::string msg_target() const { return msg_target_; }

    /// \brief Get the message ID of the most recently parsed message.
    /// \return The message id, as an integer of the most recently
    /// parsed message from the remote control object.
    inline uint32_t msg_id() const { return msg_id_; }

    /// \brief  Set the message ID of the most recently parsed message.
    ///
    /// \param  msg_id  The message id to set in the most recently parsed
    ///                 message.
    inline void set_msg_id(uint32_t msg_id) { msg_id_ = msg_id; }

    /// \brief Get the received remote control request message type.
    ///
    /// This method should only be called after a call to the
    /// ServiceFileDescriptors() method returns true.
    ///
    /// \return  The received remote control request message type.
    inline RmtCntlMsgType msg_type() const { return msg_type_; }

    /// \brief Get a pointer to an EndpointInfo object that has a
    /// message ready to be parsed and processed.
    /// \return A pointer to the endpoint that has a message ready
    /// for processing.
    inline EndpointInfo* endpoint_ready() { return endpoint_ready_; }

    /// \brief Get the "get" request message contents.
    ///
    /// This method should only be called after msg_type() returns RC_GET.
    /// The caller should use the returned key_array pointer to access the
    /// keys.  This method makes sure that the JSON message "keys" is an array
    /// of strings, so this check does not need to be performed again.
    ///
    /// \param  target     A reference where the target will be placed.
    /// \param  key_array  A reference to a pointer that will be set to the
    ///                    get message's array of keys.  Use the RapidJSON
    ///                    Value methods for accessing the keys.
    ///
    /// \return  True on success, or false otherwise.
    bool GetGetMessage(std::string& target,
                       const rapidjson::Value*& key_array) const;

    /// \brief Get the "push" message contents.
    ///
    /// This method should only be called after msg_type() returns RC_PUSH.
    /// The caller should use the returned key_array pointer to access the
    /// keys. This method makes sure that the JSON message "key_vals" is an
    /// array of objects, so this check does not need to be performed again.
    ///
    /// The value of each out parameter is only valid when the message is
    /// successfully retrieved.
    ///
    /// \param  client_id  The client identifier.
    /// \param  key_val    A reference to a pointer that will be set to the
    ///                    get message's array of key_vals.  Use the RapidJSON
    ///                    Value methods for accessing the keys.
    ///
    /// \return  True on success, or false otherwise.
    bool GetPushMessage(uint32_t& client_id,
                        const rapidjson::Value*& key_val) const;

  protected:
    /// \brief Service the internal file descriptors.
    ///
    /// This method is to be used in the main processing loop, just after the
    /// common select(2) call returns a positive value.  The read mask passed
    /// into this method must have been updated by the select(2) call.  If the
    /// return value from this method is true, then there is a remote control
    /// request message that had been received, and the msg_type(),
    /// GetXxxMessage(), and SendXxxMessage() methods must be called to
    /// process the received request message and send back a message.
    ///
    /// \param  read_fds  A reference to the read mask from select(2).
    ///
    /// \return  True if there is a remote control message waiting to be
    ///          processed, or false otherwise.
    bool ServiceEndpoints(fd_set& read_fds);

    /// \brief Get the EndpointInfo for the specified client identifier.
    ///
    /// \param  client_id  The client identifier.
    ///
    /// \return  The pointer to the EndpointInfo object on success, or NULL
    ///          otherwise.
    EndpointInfo* GetEpInfo(uint32_t client_id);

    /// \brief Check if a given file descriptor is in the set.
    ///
    /// \param socket File descriptor for the socket to check.
    /// \param fds File descriptor set to check.
    ///
    /// \return True if the given socket is in the set of file descriptors,
    ///         false otherwise. False will always be returned if socket
    ///         file descriptor is less than 0.
    virtual bool InSet(int socket, fd_set& fds);

    /// The parsed JSON message.
    rapidjson::Document     document_;

    /// The parsed JSON message type.
    RmtCntlMsgType          msg_type_;

    /// The parsed JSON message identifier.
    uint32_t                msg_id_;

    /// The parsed JSON message target.
    std::string             msg_target_;

    /// The parsed JSON message interval, in seconds.
    double                  msg_interval_;

    /// The send message buffer.
    uint8_t*                snd_buf_;

    /// The string buffer for sending a message using two separate method
    /// calls.  This is dynamically allocated and freed.  The memory is owned
    /// and freed by the RemoteControl object.
    rapidjson::StringBuffer*                     send_str_buf_;

    /// The json writer for sending a message using two separate method
    /// calls.  This is dynamically allocated and freed.  The memory is owned
    /// and freed by the RemoteControl object.
    rapidjson::Writer<rapidjson::StringBuffer>*  send_writer_;

    /// The next endpoint identifier for assignment.
    static uint32_t                next_ep_id_;

    /// The Endpoint with a message ready to be processed.  Set to NULL if no
    /// client has a message ready.
    EndpointInfo*             endpoint_ready_;

    /// A map from the endpoint_id_ to endpoint connections.
    std::map<uint32_t, EndpointInfo*>  endpoints_;

  private:
    /// \brief Copy constructor.
    RemoteControl(const RemoteControl& other);

    /// \brief Copy operator.
    RemoteControl& operator=(const RemoteControl& other);

  }; // class RemoteControl


  /// The remote control client sends requests and receives replies and push
  /// messages from a remote control server.
  ///
  /// The APIs in this class are designed for a single-threaded IRON program.
  /// To integrate this class into an IRON program, a number of API calls need
  /// to be made by the IRON program.  First, the IRON program should have
  /// only a single instance of this class that it uses for all of the remote
  /// control communications.  The Initialize() call must be made during
  /// configuration time.  Connections to remote control servers can be
  /// established using the Connect() call. In the main processing loop, the
  /// AddFileDescriptors() call must be made before calling select(), and the
  /// ServiceFileDescriptors() call must be made when select() returns.  If
  /// ServiceFileDescriptors() returns true, then there is a remote control
  /// request message waiting to be processed. In order to process the
  /// request message, a call to msg_type() is made in order to tell what type
  /// of reply message is waiting.
  /// SET messages can constructed and sent using the SendSetMessage() call,
  /// and JSON message buffers can be sent to a server using SendMessage().

  class RemoteControlClient : public RemoteControl
  {
  public:
       /// \brief The default constructor.
    RemoteControlClient();

    /// \brief The destructor.
    virtual ~RemoteControlClient();

    /// \brief Connect to a remote control server module.
    ///
    /// \param  server_addr  The server's well-known TCP port number to use for
    ///          accepting connections from remote control clients.
    ///
    /// \return  The endpoint_id_ of the newly created endpoint associated
    ///          with the connection.
    ///
    uint32_t Connect(struct sockaddr_in server_addr);

    /// \brief Disconnect from all remote control servers.
    void Disconnect();

    /// \brief Service the internal file descriptors.
    ///
    /// This method is to be used in the main processing loop, just after the
    /// common select(2) call returns a positive value.  The read mask passed
    /// into this method must have been updated by the select(2) call.  If the
    /// return value from this method is true, then there is a remote control
    /// reply message that had been received. GetMessage() can be called to get
    /// the raw JSON buffer, which can be processed or forwarded.
    ///
    /// \param  read_fds  A reference to the read mask from select(2).
    ///
    /// \return  True if there is a remote control message waiting to be
    ///          processed, or false otherwise.
    bool ServiceFileDescriptors(fd_set& read_fds);

    /// \brief Parse the received JSON message from a client.
    ///
    /// \param  si  The pointer to the EndpointInfo object with a complete JSON
    ///             message to be parsed.
    ///
    /// \return  True if the JSON message was parsed successfully, or false
    ///          otherwise.
    bool ParseJsonMessage(EndpointInfo* si);

    /// \brief Send a SET message  to a server with a single key:val to be set.
    ///
    /// \param ep_id    The endpoint ID of the target server for the SET.
    /// \param target   A string indicating the target process for the message.
    /// \param cmd      The 'key' of the 'keyvals' object in the  SET message,
    ///                 this indicates the parameter being set.
    /// \param arg      The 'value' of the 'keyvals' object in the SET message.
    ///                 This indicates the value to be assign to the specified
    ///                 paramter.
    /// \param msg_id   An optional message id to be used in the message. This
    ///                 is used when relaying messages to preserve the original
    ///                 message id.
    void SendSetMessage(uint32_t ep_id,
                        const std::string &target,
                        const std::string &cmd,
                        const std::string &arg,
                        uint32_t msg_id = 0);


    /// \brief Send a SET message  to a server with multiple key:val pairs 
    ///        to be set.
    ///
    /// \param ep_id     The endpoint ID of the target server for the SET.
    /// \param target    A string indicating the target process for the message.
    /// \param kays_vals A string of the form "key1;val1;key2;val2;key3;val3..."
    ///                  which will be parsed into the keyvals object.
    /// \param msg_id    An optional message id to be used in the message. This
    ///                  is used when relaying messages to preserve the original
    ///                  message id.
    void SendSetMessage(uint32_t ep_id,
                        const std::string &target,
                        const std::string &arg,
                        uint32_t msg_id = 0);

    /// Get the error message from the last received message.
    inline std::string err_msg() const { return err_msg_; }

  private:

    /// \brief Copy constructor.
    RemoteControlClient(const RemoteControlClient& other);

    /// \brief Copy operator.
    RemoteControlClient& operator=(const RemoteControlClient& other);

    /// The error message.
    std::string             err_msg_;

  }; // class RemoteControlClient

  /// \brief A class for remote control communications.
  ///
  /// This is a class to be used by IRON programs that require control by a
  /// remote tool.  It creates a TCP server socket on a specified TCP port
  /// number and accepts TCP connections from remote control clients.  This
  /// class implements the remote control server functionality, and supports
  /// multiple simultaneous connections to remote control clients.  Each
  /// client initiates a transaction by sending a request message to an
  /// instance of this class, the IRON program handles the message, and the
  /// transaction is completed by the instance of this class sending a message
  /// back to the client.
  ///
  /// The APIs in this class are designed for a single-threaded IRON program.
  /// To integrate this class into an IRON program, a number of API calls need
  /// to be made by the IRON program.  First, the IRON program should have
  /// only a single instance of this class that it uses for all of the remote
  /// control communications.  The Initialize() call must be made during
  /// configuration time.  In the main processing loop, the
  /// AddFileDescriptors() call must be made before calling select(), and the
  /// ServiceFileDescriptors() call must be made when select() returns.  If
  /// ServiceFileDescriptors() returns true, then there is a remote control
  /// request message waiting to be processed.  In order to process the
  /// request message, a call to msg_type() is made in order to tell what type
  /// of request message is waiting.  If the request message type cannot be
  /// handled by the program, then it must call AbortClient().  If the request
  /// message type can be handled by the program, then the GetXxxMessage() and
  /// SendXxxMessage() calls are used to get access to the request message and
  /// send an appropriate message back to the client.

  class RemoteControlServer : public RemoteControl
  {

  public:
     /// \brief The default constructor.
    RemoteControlServer();

    /// \brief The destructor.
    virtual ~RemoteControlServer();

    /// \brief Initialize the remote control server module.
    ///
    /// Each instance can only be initialized once.
    ///
    /// \param  tcp_port  The well-known TCP port number to use for accepting
    ///                   connections from remote control clients.
    ///
    /// \return  True if the initialization is successful, false otherwise.
    ///
    bool Initialize(uint16_t tcp_port);

    /// \brief Abort the connection to the client.
    ///
    /// This is called when the message type, as returned by msg_type(),
    /// cannot be handled.
    void AbortClient();

    /// \brief Add file descriptors to a read mask.
    ///
    /// This method is to be used in the main processing loop, before the
    /// common select(2) call is made.  The read mask is for use in the
    /// select(2) call.  This method does not clear the read mask -- any
    /// existing file descriptors in the mask are left unchanged.
    ///
    /// \param  max_fd    A reference to the maximum file descriptor value to
    ///                   be updated.
    /// \param  read_fds  A reference to the read mask to be updated.
    void AddFileDescriptors(int& max_fd, fd_set& read_fds) const;

    /// \brief Service the internal file descriptors.
    ///
    /// This method is to be used in the main processing loop, just after the
    /// common select(2) call returns a positive value.  The read mask passed
    /// into this method must have been updated by the select(2) call.  If the
    /// return value from this method is true, then there is a remote control
    /// request message that had been received, and the msg_type(),
    /// GetXxxMessage(), and SendXxxMessage() methods must be called to
    /// process the received request message. GetMessage can be called to get
    /// the raw JSON buffer, which can be processed or forwarded.
    ///
    /// \param  read_fds  A reference to the read mask from select(2).
    ///
    /// \return  True if there is a remote control message waiting to be
    ///          processed, or false otherwise.
    bool ServiceFileDescriptors(fd_set& read_fds);

    /// \brief Parse the received JSON message from a client.
    ///
    /// \param  ep  The pointer to the EndpointInfo object with a complete JSON
    ///             message to be parsed.
    ///
    /// \return  True if the JSON message was parsed successfully, or false
    ///          otherwise.
    bool ParseJsonMessage(EndpointInfo* ep);

    /// \brief Get the "set" request message contents.
    ///
    /// This method should only be called after msg_type() returns RC_SET.
    /// The caller should use the returned key_value_object pointer to access
    /// the key/value pairs.  This method makes sure that the JSON message
    /// "keyvals" is an object, so this check does not need to be performed
    /// again.
    ///
    /// \param  target            A reference where the target will be placed.
    /// \param  key_value_object  A reference to a pointer that will be set to
    ///                           the set message's object of key/value pairs.
    ///                           Use the RapidJSON Value methods for
    ///                           accessing the key/value pairs.
    ///
    /// \return  True on success, or false otherwise.
    bool GetSetMessage(std::string& target,
                       const rapidjson::Value*& key_value_object) const;


    /// \brief Get the "set" request message contents.
    ///
    /// This method should only be called after msg_type() returns RC_SET.
    /// The caller should use the returned key_value_object pointer to access
    /// the key/value pairs.  This method makes sure that the JSON message
    /// "keyvals" is an object, so this check does not need to be performed
    /// again.
    ///
    /// \param  target            A reference where the target will be placed.
    /// \param  key_value_object  A reference to a pointer that will be set to
    ///                           the set message's object of key/value pairs.
    ///                           Use the RapidJSON Value methods for
    ///                           accessing the key/value pairs.
    /// \param  saddr             The Ipaddress of the sender.
    ///
    /// \return  True on success, or false otherwise.
    bool GetSetMessage(std::string& target,
                       const rapidjson::Value*& key_value_object,
                       iron::Ipv4Address& saddr) const;

    /// \brief Send a "set reply" message back to the remote client.
    ///
    /// This method should only be called after a successful call to
    /// GetSetMessage().
    ///
    /// \param  success    A flag indicating if the set request message was
    ///                    successful or not.
    /// \param  error_msg  An optional reference to a string containing an
    ///                    error message to return to the remote client.  Only
    ///                    used if success is equal to false.
    void SendSetReplyMessage(bool success,
                             const std::string& error_msg = std::string());

    /// \brief Start a "get reply" message in which to add the remainder of
    /// the JSON object.
    ///
    /// The method starts the JSON object by adding the type, msgid, and other
    /// necessary fields, then adds the "keyvals" value.  The caller then adds
    /// a JSON object containing all of the key/value pairs.  The caller must
    /// call SendGetReplyMessage() to finish the message and send it.
    ///
    /// Memory ownership: The message memory allocated is owned by the remote
    /// control object.
    ///
    /// \param  success    A flag indicating if the get request message was
    ///                    successful or not.
    /// \param  error_msg  An optional reference to a string containing an
    ///                    error message to return to the remote client.  Only
    ///                    used if success is equal to false.
    ///
    /// \return  If success is true, then the method returns the JSON writer
    ///          to use to complete the message, starting where the "keyvals"
    ///          value object should be created.  If success is false, then
    ///          the method returns NULL, since there is no data to be added.
    rapidjson::Writer<rapidjson::StringBuffer>* StartGetReplyMessage(
      bool success, const std::string& error_msg = std::string());

    /// \brief Send the "get reply" message.
    ///
    /// This closes the outer-most object and sends the message.  It must be
    /// called after StartGetReplyMessage().
    ///
    /// Memory ownership: This method clears memory allocated by
    /// StartGetReplyMessage().
    ///
    /// \param  success  A flag indicating if the get request message was
    ///                  successful or not.  Must match the value passed into
    ///                  StartGetReplyMessage().
    void SendGetReplyMessage(bool success);

    /// \brief Get the "pushreq" request message contents.
    ///
    /// This method should only be called after msg_type() returns RC_PUSHREQ.
    /// The caller should use the returned key_array pointer to access the
    /// keys. This method makes sure that the JSON message "keys" is an array
    /// of strings, so this check does not need to be performed again.
    ///
    /// Each "push" message sent using the SendPushMessage() method or any
    /// "pusherror" messages sent using SentPushErrorMessage() must use
    /// the client identifier and message identifier returned by this method.
    ///
    /// A "pusherror" message will be sent is an issue is detected with the
    /// message's fields.
    ///
    /// The value of each out parameter is only valid when the message is
    /// successfully retrieved.
    ///
    /// \param  client_id     A reference where the client identifier will be
    ///                       placed.
    /// \param  msg_id        A reference where the message identifier will be
    ///                       placed.
    /// \param  target        A reference where the target will be placed.
    /// \param  interval_sec  A reference where the update interval, in
    ///                       seconds, will be placed.
    /// \param  key_array     A reference to a pointer that will be set to the
    ///                       pushreq message's array of keys.  Use the
    ///                       RapidJSON Value methods for accessing the keys.
    ///
    /// \return  True on success, or false otherwise.
    bool GetPushRequestMessage(uint32_t& client_id, uint32_t& msg_id,
                               std::string& target, double& interval_sec,
                               const rapidjson::Value*& key_array);

    /// \brief Get "pushreq" request message options.
    ///
    /// \param  key      The key from the "pushreq" message for which options
    ///                  are being requested.
    /// \param  options  A reference where the options for the "pushreq" key
    ///                  will be placed.
    ///
    /// \return  True if successful, false otherwise.
    bool GetPushRequestOptions(const std::string& key, std::string& options);

    /// \brief Start a "push" message in which to add the remainder of the
    /// JSON object.
    ///
    /// This method should be called periodically after receiving a "pushreq"
    /// message.  If this method returns non-NULL, then the client is still
    /// available and the "push" messages should continue.  If this method
    /// returns NULL, then the client is no longer available and the "push"
    /// messages should stop.
    ///
    /// The method starts the JSON object by adding the type, msgid, and other
    /// necessary fields, then adds the "keyvals" value.  The caller then adds
    /// a JSON object containing all of the key/value pairs.  The caller must
    /// call SendPushMessage() to finish the message and send it.
    ///
    /// Memory ownership: The message memory allocated is owned by the remote
    /// control object.
    ///
    /// \param  client_id  The client identifier from the "pushreq" message.
    /// \param  msg_id     The message identifier from the "pushreq" message.
    ///
    /// \return  On success, the method returns the JSON writer to use to
    ///          complete the message, starting where the "keyvals" value
    ///          object should be created.  On failure, the method returns
    ///          NULL and the periodic "push" messages should stop.
    rapidjson::Writer<rapidjson::StringBuffer>* StartPushMessage(
      uint32_t client_id, uint32_t msg_id);

    /// \brief Send a "push" message to the remote client.
    ///
    /// This closes the outer-most object and sends the message.  It must be
    /// called after StartPushMessage().
    ///
    /// Memory ownership: This method clears memory allocated by
    /// StartPushMessage().
    ///
    /// \param  client_id  The client identifier from the "pushreq" message.
    void SendPushMessage(uint32_t client_id);

    /// \brief Send a "pusherror" message to the remote client.
    ///
    /// Called when a received "pushreq" message cannot be handled.
    ///
    /// \param  client_id  The client identifier from the "pushreq" message.
    /// \param  msg_id     The message identifier from the "pushreq" message.
    /// \param  error_msg  An optional reference to a string containing an
    ///                    error message to return to the remote client.
    void SendPushErrorMessage(uint32_t client_id, uint32_t msg_id,
                              const std::string& error_msg = std::string());

    /// \brief Get the "pushstop" request message.
    ///
    /// This method should only be called after msg_type() returns
    /// RC_PUSHSTOP. The caller should use the returned values to stop
    /// push activity. If "to_stop" is present, this method ensures that the
    /// value is an array of unsigned integers, so this check does not need
    /// to be performed again.
    ///
    /// Any "pusherror" message sent using the SendPushMessage() method must use
    /// the client identifier and message identifier returned by this method.
    ///
    /// A "pusherror" message will be sent is an issue is detected with the
    /// message's fields.
    ///
    /// The value of each out parameter is only valid when the message is
    /// successfully retrieved.
    ///
    /// \param  client_id     A reference where the client identifier will be
    ///                       placed.
    /// \param  msg_id        A reference where the message identifier will be
    ///                       placed.
    /// \param  target        A reference where the target will be placed.
    /// \param  to_stop_count A reference where the number of pushreq message
    ///                       ids will be placed. If 0, "to_stop" was
    ///                       not or present or the array was empty. In this
    ///                       case all push activity should be stoped.
    ///                       Otherwise, the value is the number of ids in 
    ///                       the array. The push activites initiated with
    ///                       the given ids should be stopped.
    ///
    /// \return  True on success, or false otherwise.
    bool GetPushStopMessage(uint32_t& client_id, uint32_t& msg_id,
                            std::string& target,
                            uint32_t& to_stop_count);

    /// \brief Get "pushstop" request message "to_stop" value.
    ///
    /// \param  index   The index into the "to_stop" aray from the "pushstop"
    ///                 message for which options are being requested.
    /// \param  id      A reference where the id "to_stop" value
    ///                 will be placed.
    ///
    /// \return  True if successful, false otherwise.
    bool GetPushStopToStopId(const uint32_t& index, uint32_t& id);


  private:

    /// \brief Copy constructor.
    RemoteControlServer(const RemoteControlServer& other);

    /// \brief Copy operator.
    RemoteControlServer& operator=(const RemoteControlServer& other);
    
    void SendPushErrorMessage(EndpointInfo* ep, uint32_t msg_id,
                              const std::string& error_msg = std::string());

    /// The server socket.
    int                     server_sock_;

  }; // class RemoteControlServer

} // namespace iron

#endif // IRON_COMMON_REMOTE_CONTROL_H
