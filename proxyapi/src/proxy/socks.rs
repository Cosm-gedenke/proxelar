use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use http::uri::{Authority, Scheme};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tower_service::Service;

use crate::ca::{CertificateAuthority, Ssl};
use crate::handler::CapturingHandler;
use crate::rewind::Rewind;

use super::forward::{serve_pinned_stream, sniff_stream_protocol, StreamProtocol};
use super::outbound::OutboundConnector;
use super::BoxError;

const SOCKS_VERSION: u8 = 5;
const AUTH_NONE: u8 = 0;
const AUTH_UNACCEPTABLE: u8 = 0xff;
const COMMAND_CONNECT: u8 = 1;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 3;
const ADDRESS_IPV6: u8 = 4;

pub async fn handle_connection(
    mut stream: TcpStream,
    remote_addr: SocketAddr,
    handler: CapturingHandler,
    ca: Arc<Ssl>,
    mut outbound: OutboundConnector,
    upstream_tls: Arc<rustls::ClientConfig>,
    listen_addr: SocketAddr,
) {
    let authority = match accept_connect(&mut stream).await {
        Ok(authority) => authority,
        Err(error) => {
            tracing::debug!("SOCKS5 handshake failed: {error}");
            return;
        }
    };
    let upstream = match connect_target(&authority, &mut outbound).await {
        Ok(upstream) => upstream,
        Err(error) => {
            let status = reply_status(error.as_ref());
            let _ = send_reply(&mut stream, status, None).await;
            tracing::debug!("SOCKS5 upstream connection failed: {error}");
            return;
        }
    };
    let bound = upstream.local_addr().ok();
    if let Err(error) = send_reply(&mut stream, 0, bound).await {
        tracing::debug!("SOCKS5 success reply failed: {error}");
        return;
    }

    let (protocol, buffered) = match sniff_stream_protocol(&mut stream).await {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!("SOCKS5 protocol detection failed: {error}");
            return;
        }
    };
    let stream = Rewind::new_buffered(stream, buffered);
    match protocol {
        StreamProtocol::Http => {
            if let Err(error) = serve_pinned_stream(
                stream,
                upstream,
                Scheme::HTTP,
                handler,
                ca,
                remote_addr,
                listen_addr,
            )
            .await
            {
                tracing::debug!("SOCKS5 HTTP inspection failed: {error}");
            }
        }
        StreamProtocol::Tls => {
            let server_name = match ServerName::try_from(authority.host().to_owned()) {
                Ok(server_name) => server_name,
                Err(error) => {
                    tracing::warn!("SOCKS5 upstream TLS server name is invalid: {error}");
                    return;
                }
            };
            let upstream = match TlsConnector::from(upstream_tls)
                .connect(server_name, upstream)
                .await
            {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!("SOCKS5 upstream TLS handshake failed: {error}");
                    return;
                }
            };
            let server_config = match ca.gen_server_config(&authority).await {
                Ok(config) => config,
                Err(error) => {
                    tracing::warn!("SOCKS5 certificate generation failed: {error}");
                    return;
                }
            };
            let stream = match TlsAcceptor::from(server_config).accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!("SOCKS5 TLS interception failed: {error}");
                    return;
                }
            };
            if let Err(error) = serve_pinned_stream(
                stream,
                upstream,
                Scheme::HTTPS,
                handler,
                ca,
                remote_addr,
                listen_addr,
            )
            .await
            {
                tracing::debug!("SOCKS5 HTTPS inspection failed: {error}");
            }
        }
        StreamProtocol::Unknown => {
            let mut client_stream = stream;
            let mut upstream = upstream;
            if let Err(error) = super::raw::tunnel(
                &mut client_stream,
                &mut upstream,
                authority.to_string(),
                handler.event_tx_clone(),
            )
            .await
            {
                tracing::debug!("SOCKS5 TCP tunnel failed: {error}");
            }
        }
    }
}

async fn accept_connect(stream: &mut TcpStream) -> Result<Authority, std::io::Error> {
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != SOCKS_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported SOCKS version",
        ));
    }
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&AUTH_NONE) {
        stream
            .write_all(&[SOCKS_VERSION, AUTH_UNACCEPTABLE])
            .await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "SOCKS client does not support no-auth",
        ));
    }
    stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await?;

    let mut request = [0_u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != SOCKS_VERSION || request[1] != COMMAND_CONNECT || request[2] != 0 {
        send_reply(stream, 7, None).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "only SOCKS5 CONNECT is supported",
        ));
    }
    let host = match request[3] {
        ADDRESS_IPV4 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets)).to_string()
        }
        ADDRESS_IPV6 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            format!("[{}]", Ipv6Addr::from(octets))
        }
        ADDRESS_DOMAIN => {
            let length = stream.read_u8().await?;
            let mut domain = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
        }
        _ => {
            send_reply(stream, 8, None).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported SOCKS address type",
            ));
        }
    };
    let port = stream.read_u16().await?;
    let authority = format!("{host}:{port}")
        .parse::<Authority>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(authority)
}

async fn connect_target(
    authority: &Authority,
    outbound: &mut OutboundConnector,
) -> Result<TcpStream, BoxError> {
    let destination = format!("http://{authority}/").parse()?;
    poll_fn(|context| outbound.poll_ready(context)).await?;
    Ok(outbound.call(destination).await?.into_inner())
}

fn reply_status(error: &(dyn std::error::Error + 'static)) -> u8 {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<std::io::Error>() {
            return match error.kind() {
                std::io::ErrorKind::PermissionDenied => 2,
                std::io::ErrorKind::NetworkUnreachable => 3,
                std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::TimedOut => 4,
                std::io::ErrorKind::ConnectionRefused => 5,
                _ => 1,
            };
        }
        current = error.source();
    }
    1
}

async fn send_reply(
    stream: &mut TcpStream,
    status: u8,
    bound: Option<SocketAddr>,
) -> Result<(), std::io::Error> {
    let bound = bound.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut reply = vec![SOCKS_VERSION, status, 0];
    match bound.ip() {
        IpAddr::V4(ip) => {
            reply.push(ADDRESS_IPV4);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(ADDRESS_IPV6);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&reply).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn accepts_domain_connect_and_rejects_missing_no_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            accept_connect(&mut stream).await.unwrap()
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut auth = [0_u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [5, 0]);
        client
            .write_all(&[
                5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                0, 80,
            ])
            .await
            .unwrap();
        assert_eq!(server.await.unwrap().as_str(), "example.com:80");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            accept_connect(&mut stream).await.unwrap_err()
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [5, 0xff]);
        assert_eq!(
            server.await.unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}
