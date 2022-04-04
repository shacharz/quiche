//! WebTransport over HTTP/3 session management implementation.
//!
//! This module provides both server-side and client-side
//! WebTransport session management API.
//!
//! ## Connection setup
//!
//! Same as quiche::h3 module, WebTransport session
//! requires a QUIC transport-layer connection, see
//! [Connection setup] for a full description of the setup process.
//!
//! To use HTTP/3, the QUIC connection must be configured with a suitable
//! Application Layer Protocol Negotiation (ALPN) Protocol ID:
//!
//! ```
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The QUIC handshake is driven by [sending] and [receiving] QUIC packets.
//!
//! Once the handshake has completed, the first step in establishing an HTTP/3
//! connection and WebTransport session is creating its configuration object:
//!
//! WebTransport over HTTP/3 client and server connections are both created using the
//! [`with_transport()`] function, the role is inferred from the type of QUIC
//! connection:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let from = "127.0.0.1:1234".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, from, &mut config).unwrap();
//! let h3_conn = quiche::webtransport::ServerSession::with_transport(&mut conn)?;
//! # Ok::<(), quiche::webtransport::Error>(())
//! ```
//!
use crate::h3::{self, Header, NameValue};
use crate::stream::is_bidi;
use crate::Connection;
use std::collections::HashMap;
use std::str;

const HTTP_STATUS_BAD_REQUEST: u32 = 400;
const HTTP_STATUS_TOO_MANY_REQUESTS: u32 = 429;
const QUIC_CLOSE_REASON_REQUEST_REJECTED: u64 = 0x10B;

/// An error on CONNECT request to establish WebTransport session.
#[derive(Clone, Debug, PartialEq)]
enum ConnectRequestError {
    /// A parameter not found.
    MissingParam(&'static str),
    /// A parameter' type or format is wrong.
    InvalidParam(&'static str, Vec<u8>),
    /// A parameter doesn't match to expected one.
    ParamMismatch(&'static str, &'static str, Vec<u8>),
}

/// An WebTransport error.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// There is no error or no work todo
    Done,

    /// Invalid state of session.
    InvalidState,

    /// An argument of method is wrong.
    InvalidArg(&'static str),

    /// Invalid QUIC tarnsport configuration found.
    InvalidConfig(&'static str),

    /// The specified stream doesn't exist.
    StreamNotFound,

    /// The direction or initiater of the specified stream does not match.
    InvalidStream,

    /// The session ID in the datagram was different from the desired one.
    DatagramSessionIdMismatch,

    /// Error originated from the transport layer.
    TransportError(crate::Error),

    /// Unexpected data received from peer.
    UnexpectedMessage,

    /// Error originated from the HTTP3 layer.
    HTTPError(h3::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<h3::Error> for Error {
    fn from(err: h3::Error) -> Self {
        match err {
            h3::Error::Done => Error::Done,
            h3::Error::TransportError(e) => Error::TransportError(e),
            _ => Error::HTTPError(err),
        }
    }
}

impl std::convert::From<crate::Error> for Error {
    fn from(err: crate::Error) -> Self {
        match err {
            crate::Error::Done => Error::Done,
            _ => Error::TransportError(err),
        }
    }
}

/// An WebTransport server session event.
#[derive(Clone, Debug, PartialEq)]
pub enum ServerEvent {
    /// HTTP headers requesting WebTransport start were received.
    ConnectRequest(ConnectRequest),

    /// WebTransport stream payload was received
    StreamData(u64),

    /// WebTransport stream was closed.
    StreamFinished(u64),

    /// DATAGRAM was received
    Datagram,

    /// WebTransport session-control-stream was closed.
    SessionFinished,

    /// WebTransport session-control-stream was reset.
    SessionReset(u64),

    /// GOAWAY was received on WebTransport session-control-stream.
    SessionGoAway,

    /// Bypassed events related to HTTP other than WebTransport
    BypassedHTTPEvent(u64, h3::Event),
}

/// An WebTransport client session event.
#[derive(Clone, Debug, PartialEq)]
pub enum ClientEvent {
    /// response for CONNECT request was received with OK status.
    Connected,

    /// response for CONNECT request was received with not OK status.
    Rejected(i32),

    /// WebTransport stream payload was received
    StreamData(u64),

    /// WebTransport stream was closed.
    StreamFinished(u64),

    /// DATAGRAM was received
    Datagram,

    /// WebTransport session-control-stream was closed.
    SessionFinished,

    /// WebTransport session-control-stream was reset.
    SessionReset(u64),

    /// GOAWAY was received on WebTransport session-control-stream.
    SessionGoAway,

    /// Events related to HTTP other than WebTransport
    BypassedHTTPEvent(u64, h3::Event),
}

/// A specialized [`Result`] type for quiche WebTransport operations.
///
/// This type is used throughout quiche's WebTransport public API for any operation
/// that can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// The main header values that were included in the HTTP request to initiate WebTransport
#[derive(Clone, Debug, PartialEq)]
pub struct ConnectRequest {
    authority: String,
    path: String,
    origin: String,
}

impl ConnectRequest {
    /// Create a new connect-request
    pub fn new(authority: String, path: String, origin: String) -> Self {
        Self {
            authority,
            path,
            origin,
        }
    }

    /// accessor to the ':authority' header value
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// accessor to the ':path' header value
    pub fn path(&self) -> &str {
        &self.path
    }

    /// accessor to the 'origin' header value
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// Information about WebTransport stream.
struct StreamInfo {
    stream_id: u64,
    local: bool,
    initialized: bool,
}

impl StreamInfo {
    /// Create a new stream info
    pub fn new(stream_id: u64, local: bool) -> Self {
        Self {
            stream_id,
            local,
            initialized: false,
        }
    }

    /// Returns true if the stream is bidirectional.
    pub fn is_bidi(&self) -> bool {
        is_bidi(self.stream_id)
    }

    /// Returns true if it is already marked as initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns true if the stream was created locally.
    pub fn is_local(&self) -> bool {
        self.local
    }

    /// Mark as initialized. This method should be called after send required data before payload.
    pub fn mark_initialized(&mut self) {
        self.initialized = true;
    }
}

fn find_request(
    list: &[h3::Header],
) -> std::result::Result<ConnectRequest, ConnectRequestError> {
    match is_webtransport_request(list) {
        Ok(()) => {
            let mut headers = list.into_iter();

            let authority = find_string_param(&mut headers, ":authority")?;
            let path = find_string_param(&mut headers, ":path")?;
            let origin = find_string_param(&mut headers, "origin")?;

            Ok(ConnectRequest::new(authority, path, origin))
        },

        Err(e) => Err(e),
    }
}

fn find_string_param(
    headers: &mut std::slice::Iter<h3::Header>, param: &'static str,
) -> std::result::Result<String, ConnectRequestError> {
    if let Some(header) = headers.find(|h| h.name() == param.as_bytes()) {
        if let Ok(param_str) = String::from_utf8(header.value().to_vec()) {
            Ok(param_str)
        } else {
            Err(ConnectRequestError::InvalidParam(
                param,
                header.value().to_vec(),
            ))
        }
    } else {
        Err(ConnectRequestError::MissingParam(param))
    }
}

fn find_integer_param(
    headers: &mut std::vec::IntoIter<h3::Header>, param: &'static str,
) -> std::result::Result<i32, ConnectRequestError> {
    if let Some(header) = headers.find(|h| h.name() == param.as_bytes()) {
        if let Ok(param_str) = String::from_utf8(header.value().to_vec()) {
            let param_int = param_str.parse::<i32>().map_err(|_| {
                ConnectRequestError::InvalidParam(param, header.value().to_vec())
            })?;
            Ok(param_int)
        } else {
            Err(ConnectRequestError::InvalidParam(
                param,
                header.value().to_vec(),
            ))
        }
    } else {
        Err(ConnectRequestError::MissingParam(param))
    }
}

fn validate_param(
    headers: &mut std::slice::Iter<h3::Header>, param: &'static str,
    expected: &'static str,
) -> std::result::Result<(), ConnectRequestError> {
    if let Some(method) = headers.find(|h| h.name() == param.as_bytes()) {
        if method.value() != expected.as_bytes() {
            Err(ConnectRequestError::ParamMismatch(
                param,
                expected,
                method.value().to_vec(),
            ))
        } else {
            Ok(())
        }
    } else {
        Err(ConnectRequestError::MissingParam(param))
    }
}

fn is_webtransport_request(
    list: &[h3::Header],
) -> std::result::Result<(), ConnectRequestError> {
    let mut headers = list.into_iter();
    validate_param(&mut headers, ":method", "CONNECT")?;
    validate_param(&mut headers, ":protocol", "webtransport")?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
enum ServerState {
    Init,
    Requested(u64),
    Connected(u64),
    Finished,
}

/// Represents an individual WebTransport session on the server side
pub struct ServerSession {
    h3_conn: h3::Connection,
    streams: HashMap<u64, StreamInfo>,
    state: ServerState,
}

impl ServerSession {
    fn new(h3_conn: h3::Connection) -> Self {
        Self {
            h3_conn,
            state: ServerState::Init,
            streams: HashMap::new(),
        }
    }

    /// Returns true if this session has accepted the CONNECT request.
    pub fn is_connected(&self) -> bool {
        match self.state {
            ServerState::Connected(_) => true,
            _ => false,
        }
    }

    /// Create a new WebTransport session using the provided QUIC connection.
    ///
    /// This includes the HTTP/3 handshake.
    ///
    /// On success the new session is returned.
    ///
    /// The [`StreamLimit`] error is returned when the HTTP/3 control stream
    /// cannot be created.
    pub fn with_transport(conn: &mut Connection) -> Result<Self> {
        if !conn.dgram_enabled() {
            return Err(Error::InvalidConfig("dgram_enabled"));
        }
        let mut config = h3::Config::new().unwrap();
        config.set_enable_webtransport(true);
        let h3_conn = match h3::Connection::with_transport(conn, &config) {
            Ok(v) => v,
            Err(e) => return Err(e.into()),
        };
        Ok(Self::new(h3_conn))
    }

    /// Reads stream payload data into the provided buffer.
    ///
    /// Applications should call this method whenever the [`poll()`] method
    /// returns a [`StreamData`] event.
    ///
    /// On success the amount of bytes read is returned, or [`Done`] if there
    /// is no data to read.
    ///
    /// [`poll()`]: struct.ServerSession.html#method.poll
    /// [`StreamData`]: enum.ServerEvent.html#variant.StreamData
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn recv_stream_data(
        &mut self, conn: &mut Connection, stream_id: u64, out: &mut [u8],
    ) -> Result<usize> {
        self.h3_conn
            .recv_webtransport_stream_data(conn, stream_id, out)
            .map_err(|e| e.into())
    }

    /// Reads a DATAGRAM into the provided buffer.
    ///
    /// Applications should call this method whenever the [`poll()`] method
    /// returns a [`Datagram`] event.
    ///
    /// On success the DATAGRAM data is returned, with offset wichi represents
    /// length of the session ID and total length of data.
    ///
    /// [`Done`] is returned if there is no data to read.
    ///
    /// [`BufferTooShort`] is returned if the provided buffer is too small for
    /// the data.
    ///
    /// [`poll()`]: struct.ServerSession.html#method.poll
    /// [`Datagram`]: enum.ServerEvent.html#variant.Datagram
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`BufferTooShort`]: ../h3/enum.Error.html#variant.BufferTooShort
    pub fn recv_dgram(
        &mut self, conn: &mut Connection, buf: &mut [u8],
    ) -> Result<(usize, usize)> {
        match self.h3_conn.recv_dgram(conn, buf) {
            Ok((len, session_id, session_id_len)) => match self.state {
                ServerState::Connected(sid) => {
                    if sid == session_id {
                        Ok((session_id_len, len))
                    } else {
                        info!("The session_id included in Datagram frame doesn't match to current WebTransport session.");
                        Err(Error::DatagramSessionIdMismatch)
                    }
                },
                _ => Err(Error::InvalidState),
            },
            Err(e) => Err(e.into()),
        }
    }

    /// Processes WebTransport data received from the peer.
    ///
    /// On success it returns an [`Event`] and an ID, or [`Done`] when there are
    /// no events to report.
    ///
    /// Note that all events are edge-triggered, meaning that once reported they
    /// will not be reported again by calling this method again, until the event
    /// is re-armed.
    pub fn poll(&mut self, conn: &mut Connection) -> Result<ServerEvent> {
        match self.h3_conn.poll(conn) {
            Ok((stream_id, h3::Event::Headers { list, has_body: _ })) => {
                match find_request(&list) {
                    Ok(wt_req) => {
                        if self.state == ServerState::Init {
                            self.state = ServerState::Requested(stream_id);
                            Ok(ServerEvent::ConnectRequest(wt_req))
                        } else {
                            info!("A New WebTransport request is received while current state is not idle: {:?}", self.state);
                            let _ = self.reject_internal(
                                conn,
                                stream_id,
                                HTTP_STATUS_TOO_MANY_REQUESTS,
                                None,
                            );
                            Err(Error::Done)
                        }
                    },
                    Err(e) => {
                        info!(
                            "This is a bad request to connect WebTransport: {:?}",
                            e
                        );
                        let _ = self.reject_internal(
                            conn,
                            stream_id,
                            HTTP_STATUS_BAD_REQUEST,
                            None,
                        );
                        Err(Error::Done)
                    },
                }
            },

            Ok((stream_id, h3::Event::WebTransportStreamData(session_id))) => {
                match self.state {
                    ServerState::Connected(sid) => {
                        if sid == session_id {
                            if !self.streams.contains_key(&stream_id) {
                                self.streams.insert(
                                    stream_id,
                                    StreamInfo::new(stream_id, false),
                                );
                            }
                            Ok(ServerEvent::StreamData(stream_id))
                        } else {
                            info!("A WebTransport stream data received, but session_id does't match: {}", session_id);
                            Ok(ServerEvent::BypassedHTTPEvent(
                                stream_id,
                                h3::Event::WebTransportStreamData(session_id),
                            ))
                        }
                    },
                    _ => Ok(ServerEvent::BypassedHTTPEvent(
                        stream_id,
                        h3::Event::WebTransportStreamData(session_id),
                    )),
                }
            },

            Ok((stream_id, h3::Event::Data)) => {
                Ok(ServerEvent::BypassedHTTPEvent(stream_id, h3::Event::Data))
            },

            Ok((stream_id, h3::Event::Finished)) => {
                if self.streams.contains_key(&stream_id) {
                    Ok(ServerEvent::StreamFinished(stream_id))
                } else {
                    match self.state {
                        ServerState::Requested(sid) => {
                            if sid == stream_id {
                                Ok(ServerEvent::SessionFinished)
                            } else {
                                info!("A stream 'finished' event received, but stream_id is unknown: {}", stream_id);
                                Ok(ServerEvent::BypassedHTTPEvent(
                                    stream_id,
                                    h3::Event::Finished,
                                ))
                            }
                        },
                        ServerState::Connected(sid) => {
                            if sid == stream_id {
                                Ok(ServerEvent::SessionFinished)
                            } else {
                                info!("A stream 'finished' event received, but stream_id is unknown: {}", stream_id);
                                Ok(ServerEvent::BypassedHTTPEvent(
                                    stream_id,
                                    h3::Event::Finished,
                                ))
                            }
                        },
                        _ => Ok(ServerEvent::BypassedHTTPEvent(
                            stream_id,
                            h3::Event::Finished,
                        )),
                    }
                }
            },

            Ok((stream_id, h3::Event::Reset(e))) => match self.state {
                ServerState::Requested(sid) => {
                    if sid == stream_id {
                        Ok(ServerEvent::SessionReset(e))
                    } else {
                        info!("A stream 'reset' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ServerEvent::BypassedHTTPEvent(
                            stream_id,
                            h3::Event::Reset(e),
                        ))
                    }
                },
                ServerState::Connected(sid) => {
                    if sid == stream_id {
                        Ok(ServerEvent::SessionReset(e))
                    } else {
                        info!("A stream 'reset' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ServerEvent::BypassedHTTPEvent(
                            stream_id,
                            h3::Event::Reset(e),
                        ))
                    }
                },
                _ => Ok(ServerEvent::BypassedHTTPEvent(
                    stream_id,
                    h3::Event::Reset(e),
                )),
            },

            Ok((session_id, h3::Event::Datagram)) => match self.state {
                ServerState::Connected(sid) => {
                    if sid == session_id {
                        Ok(ServerEvent::Datagram)
                    } else {
                        info!("A stream 'datagram' event received, but session_id is unknown: {}", session_id);
                        Ok(ServerEvent::BypassedHTTPEvent(
                            session_id,
                            h3::Event::Datagram,
                        ))
                    }
                },
                _ => Ok(ServerEvent::BypassedHTTPEvent(
                    session_id,
                    h3::Event::Datagram,
                )),
            },

            Ok((stream_id, h3::Event::GoAway)) => match self.state {
                ServerState::Requested(sid) => {
                    if sid == stream_id {
                        Ok(ServerEvent::SessionGoAway)
                    } else {
                        info!("A stream 'goaway' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ServerEvent::BypassedHTTPEvent(
                            stream_id,
                            h3::Event::GoAway,
                        ))
                    }
                },
                ServerState::Connected(sid) => {
                    if sid == stream_id {
                        Ok(ServerEvent::SessionGoAway)
                    } else {
                        info!("A stream 'goaway' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ServerEvent::BypassedHTTPEvent(
                            stream_id,
                            h3::Event::GoAway,
                        ))
                    }
                },
                _ => Ok(ServerEvent::BypassedHTTPEvent(
                    stream_id,
                    h3::Event::GoAway,
                )),
            },

            Err(h3::Error::Done) => Err(Error::Done),

            Err(e) => Err(e.into()),
        }
    }

    /// accept connect request
    pub fn accept_connect_request(
        &mut self, conn: &mut Connection, extra_headers: Option<&[Header]>,
    ) -> Result<()> {
        match self.state {
            ServerState::Requested(session_id) => {
                let mut list = vec![
                    Header::new(b":status", b"200"),
                    Header::new(b"sec-webtransport-http3-draft", b"draft02"),
                ];
                if let Some(extra_headers) = extra_headers {
                    list.append(&mut extra_headers.to_vec());
                }
                let _ =
                    self.h3_conn.send_response(conn, session_id, &list, false)?;
                self.state = ServerState::Connected(session_id);
                Ok(())
            },
            _ => Err(Error::InvalidState),
        }
    }

    /// reject connect request
    pub fn reject_connect_request(
        &mut self, conn: &mut Connection, code: u32,
        extra_headers: Option<&[Header]>,
    ) -> Result<()> {
        match self.state {
            ServerState::Requested(session_id) => {
                self.reject_internal(conn, session_id, code, extra_headers)
            },
            _ => Err(Error::InvalidState),
        }
    }

    fn reject_internal(
        &mut self, conn: &mut Connection, stream_id: u64, code: u32,
        extra_headers: Option<&[Header]>,
    ) -> Result<()> {
        if code < 400 {
            return Err(Error::InvalidArg("code"));
        }
        let code = format!("{}", code).into_bytes();
        let mut list = vec![
            Header::new(b":status", &code),
            Header::new(b"sec-webtransport-http3-draft", b"draft02"),
        ];
        if let Some(extra_headers) = extra_headers {
            list.append(&mut extra_headers.to_vec());
        }
        if let Err(e) = self.h3_conn.send_response(conn, stream_id, &list, true) {
            warn!("Failed to send WebTransport reject response: {}", e);
        }
        self.state = ServerState::Finished;
        conn.close(true, QUIC_CLOSE_REASON_REQUEST_REJECTED, b"")?;
        Ok(())
    }

    /// open new WebTransport stream
    pub fn open_stream(
        &mut self, conn: &mut Connection, is_bidi: bool,
    ) -> Result<u64> {
        match self.state {
            ServerState::Connected(session_id) => {
                match self
                    .h3_conn
                    .open_webtransport_stream(conn, session_id, is_bidi)
                {
                    Ok(stream_id) => {
                        let mut stream = StreamInfo::new(stream_id, true);
                        stream.mark_initialized();
                        self.streams.insert(stream_id, stream);
                        Ok(stream_id)
                    },

                    Err(e) => Err(e.into()),
                }
            },
            _ => Err(Error::InvalidState),
        }
    }

    /// send WebTransport stream data
    pub fn send_stream_data(
        &mut self, conn: &mut Connection, stream_id: u64, data: &[u8],
    ) -> Result<usize> {
        match self.state {
            ServerState::Connected(_session_id) => {
                match self.streams.get(&stream_id) {
                    Some(stream) => {
                        if !stream.is_bidi() && !stream.is_local() {
                            Err(Error::InvalidStream)
                        } else {
                            let written =
                                conn.stream_send(stream_id, &data, false)?;
                            Ok(written)
                        }
                    },
                    None => Err(Error::StreamNotFound),
                }
            },
            _ => Err(Error::InvalidState),
        }
    }

    /// send WebTransport dgram
    pub fn send_dgram(
        &mut self, conn: &mut Connection, data: &[u8],
    ) -> Result<()> {
        match self.state {
            ServerState::Connected(session_id) => {
                self.h3_conn.send_dgram(conn, session_id, data)?;
                Ok(())
            },
            _ => Err(Error::InvalidState),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ClientState {
    Init,
    Requesting(u64),
    Connected(u64),
}

/// Represents a WebTransport session on the client side
pub struct ClientSession {
    h3_conn: h3::Connection,
    streams: HashMap<u64, StreamInfo>,
    state: ClientState,
}

impl ClientSession {
    fn new(h3_conn: h3::Connection) -> Self {
        Self {
            h3_conn,
            streams: HashMap::new(),
            state: ClientState::Init,
        }
    }

    /// Returns true if this session got response for CONNECT request with OK status
    pub fn is_connected(&self) -> bool {
        match self.state {
            ClientState::Connected(_) => true,
            _ => false,
        }
    }

    pub fn with_transport(conn: &mut Connection) -> Result<Self> {
        if !conn.dgram_enabled() {
            return Err(Error::InvalidConfig("dgram_enabled"));
        }
        let mut config = h3::Config::new().unwrap();
        config.set_enable_webtransport(true);
        let h3_conn = match h3::Connection::with_transport(conn, &config) {
            Ok(v) => v,
            Err(e) => return Err(e.into()),
        };
        Ok(Self::new(h3_conn))
    }

    pub fn send_connect_request(
        &mut self, conn: &mut Connection, authority: &[u8], path: &[u8],
        origin: &[u8], extra_headers: Option<&[Header]>,
    ) -> Result<u64> {
        if self.state != ClientState::Init {
            return Err(Error::InvalidState);
        }
        let mut req = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":scheme", b"https"),
            Header::new(b":protocol", b"webtransport"),
            Header::new(b"sec-webtransport-http3-draft02", b"1"),
            Header::new(b":authority", &authority),
            Header::new(b":path", &path),
            Header::new(b"origin", &origin),
        ];
        if let Some(extra_headers) = extra_headers {
            req.append(&mut extra_headers.to_vec());
        }
        let stream_id = self.h3_conn.send_request(conn, &req, false)?;
        self.state = ClientState::Requesting(stream_id);

        Ok(stream_id)
    }

    pub fn poll(&mut self, conn: &mut Connection) -> Result<ClientEvent> {
        match self.h3_conn.poll(conn) {
            Ok((stream_id, h3::Event::Headers { list, has_body })) => {
                match self.state {
                    ClientState::Requesting(sid) => {
                        if sid == stream_id {
                            let mut headers = list.into_iter();
                            match find_integer_param(&mut headers, ":status") {
                                Ok(code) => {
                                    if code >= 200 && code < 300 {
                                        self.state =
                                            ClientState::Connected(stream_id);
                                        Ok(ClientEvent::Connected)
                                    } else {
                                        Ok(ClientEvent::Rejected(code))
                                    }
                                },
                                Err(_e) => {
                                    debug!("header requires proper :status");
                                    Err(Error::UnexpectedMessage)
                                },
                            }
                        } else {
                            debug!("Headers event received with unknown stream_id: {}", stream_id);
                            Ok(ClientEvent::BypassedHTTPEvent(
                                stream_id,
                                h3::Event::Headers { list, has_body },
                            ))
                        }
                    },
                    _ => {
                        debug!("Headers event received with stream_id: {}, while not requesting it.", stream_id);
                        Ok(ClientEvent::BypassedHTTPEvent(
                            stream_id,
                            h3::Event::Headers { list, has_body },
                        ))
                    },
                }
            },

            Ok((stream_id, h3::Event::WebTransportStreamData(session_id))) => {
                match self.state {
                    ClientState::Connected(sid) => {
                        if sid == session_id {
                            if !self.streams.contains_key(&stream_id) {
                                self.streams.insert(
                                    stream_id,
                                    StreamInfo::new(stream_id, false),
                                );
                            }
                            Ok(ClientEvent::StreamData(stream_id))
                        } else {
                            info!("A WebTransport stream data received, but session_id does't match: {}", session_id);
                            Ok(ClientEvent::BypassedHTTPEvent(
                                stream_id,
                                h3::Event::WebTransportStreamData(session_id),
                            ))
                        }
                    },
                    _ => Ok(ClientEvent::BypassedHTTPEvent(
                        stream_id,
                        h3::Event::WebTransportStreamData(session_id),
                    )),
                }
            },

            Ok((stream_id, h3::Event::Data)) => {
                Ok(ClientEvent::BypassedHTTPEvent(stream_id, h3::Event::Data))
            },

            Ok((stream_id, h3::Event::Finished)) => {
                if self.streams.contains_key(&stream_id) {
                    Ok(ClientEvent::StreamFinished(stream_id))
                } else {
                    match self.state {
                        ClientState::Requesting(sid) => {
                            if sid == stream_id {
                                Ok(ClientEvent::SessionFinished)
                            } else {
                                info!("A stream 'finished' event received, but stream_id is unknown: {}", stream_id);
                                Ok(ClientEvent::BypassedHTTPEvent(
                                    stream_id,
                                    h3::Event::Finished,
                                ))
                            }
                        },
                        ClientState::Connected(sid) => {
                            if sid == stream_id {
                                Ok(ClientEvent::SessionFinished)
                            } else {
                                info!("A stream 'finished' event received, but stream_id is unknown: {}", stream_id);
                                Ok(ClientEvent::BypassedHTTPEvent(
                                    stream_id,
                                    h3::Event::Finished,
                                ))
                            }
                        },
                        _ => Ok(ClientEvent::BypassedHTTPEvent(
                            stream_id,
                            h3::Event::Finished,
                        )),
                    }
                }
            },

            Ok((stream_id, h3::Event::Reset(e))) => match self.state {
                ClientState::Requesting(sid) => {
                    if sid == stream_id {
                        Ok(ClientEvent::SessionReset(e))
                    } else {
                        info!("A stream 'reset' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ClientEvent::BypassedHTTPEvent(
                            stream_id,
                            h3::Event::Reset(e),
                        ))
                    }
                },
                ClientState::Connected(sid) => {
                    if sid == stream_id {
                        Ok(ClientEvent::SessionReset(e))
                    } else {
                        info!("A stream 'reset' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ClientEvent::BypassedHTTPEvent(
                            stream_id,
                            h3::Event::Reset(e),
                        ))
                    }
                },
                _ => Ok(ClientEvent::BypassedHTTPEvent(
                    stream_id,
                    h3::Event::Reset(e),
                )),
            },

            Ok((session_id, h3::Event::Datagram)) => match self.state {
                ClientState::Connected(sid) => {
                    if sid == session_id {
                        Ok(ClientEvent::Datagram)
                    } else {
                        info!("A stream 'datagram' event received, but session_id is unknown: {}", session_id);
                        Ok(ClientEvent::BypassedHTTPEvent(
                            session_id,
                            h3::Event::Datagram,
                        ))
                    }
                },
                _ => Ok(ClientEvent::BypassedHTTPEvent(
                    session_id,
                    h3::Event::Datagram,
                )),
            },

            Ok((stream_id, h3::Event::GoAway)) => match self.state {
                ClientState::Requesting(sid) => {
                    if sid == stream_id {
                        Ok(ClientEvent::SessionGoAway)
                    } else {
                        info!("A stream 'goaway' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ClientEvent::BypassedHTTPEvent(
                            stream_id,
                            h3::Event::GoAway,
                        ))
                    }
                },
                ClientState::Connected(sid) => {
                    if sid == stream_id {
                        Ok(ClientEvent::SessionGoAway)
                    } else {
                        info!("A stream 'goaway' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ClientEvent::BypassedHTTPEvent(
                            stream_id,
                            h3::Event::GoAway,
                        ))
                    }
                },
                _ => Ok(ClientEvent::BypassedHTTPEvent(
                    stream_id,
                    h3::Event::GoAway,
                )),
            },

            Err(h3::Error::Done) => Err(Error::Done),

            Err(e) => Err(e.into()),
        }
    }
    /// open new WebTransport stream
    pub fn open_stream(
        &mut self, conn: &mut Connection, is_bidi: bool,
    ) -> Result<u64> {
        match self.state {
            ClientState::Connected(session_id) => {
                match self
                    .h3_conn
                    .open_webtransport_stream(conn, session_id, is_bidi)
                {
                    Ok(stream_id) => {
                        let mut stream = StreamInfo::new(stream_id, true);
                        stream.mark_initialized();
                        self.streams.insert(stream_id, stream);
                        Ok(stream_id)
                    },

                    Err(e) => Err(e.into()),
                }
            },
            _ => Err(Error::InvalidState),
        }
    }

    /// send WebTransport stream data
    pub fn send_stream_data(
        &mut self, conn: &mut Connection, stream_id: u64, data: &[u8],
    ) -> Result<usize> {
        match self.state {
            ClientState::Connected(session_id) => {
                match self.streams.get_mut(&stream_id) {
                    Some(stream) => {
                        if !stream.is_bidi() && !stream.is_local() {
                            Err(Error::InvalidStream)
                        } else {
                            if stream.is_bidi()
                                && !stream.is_local()
                                && !stream.is_initialized()
                            {
                                self.h3_conn.send_webtransport_frame_header(
                                    conn, session_id, stream_id,
                                )?;
                                stream.mark_initialized();
                            }
                            let written =
                                conn.stream_send(stream_id, &data, false)?;
                            Ok(written)
                        }
                    },
                    None => Err(Error::StreamNotFound),
                }
            },
            _ => Err(Error::InvalidState),
        }
    }

    pub fn recv_stream_data(
        &mut self, conn: &mut Connection, stream_id: u64, out: &mut [u8],
    ) -> Result<usize> {
        self.h3_conn
            .recv_webtransport_stream_data(conn, stream_id, out)
            .map_err(|e| e.into())
    }

    pub fn recv_dgram(
        &mut self, conn: &mut Connection, buf: &mut [u8],
    ) -> Result<(usize, usize)> {
        match self.h3_conn.recv_dgram(conn, buf) {
            Ok((len, session_id, session_id_len)) => match self.state {
                ClientState::Connected(sid) => {
                    if sid == session_id {
                        Ok((session_id_len, len))
                    } else {
                        info!("The session_id included in Datagram frame doesn't match to current WebTransport session.");
                        Err(Error::DatagramSessionIdMismatch)
                    }
                },
                _ => Err(Error::InvalidState),
            },
            Err(e) => Err(e.into()),
        }
    }

    /// send WebTransport dgram
    pub fn send_dgram(
        &mut self, conn: &mut Connection, data: &[u8],
    ) -> Result<()> {
        match self.state {
            ClientState::Connected(session_id) => {
                self.h3_conn.send_dgram(conn, session_id, data)?;
                Ok(())
            },
            _ => Err(Error::InvalidState),
        }
    }
}
