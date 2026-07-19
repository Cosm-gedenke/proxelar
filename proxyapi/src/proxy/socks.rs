use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use http::uri::{Authority, Scheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::ca::{CertificateAuthority, Ssl};
use crate::handler::CapturingHandler;
use crate::rewind::Rewind;

use super::forward::{serve_stream, sniff_stream_protocol, StreamProtocol};
use super::Client;

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
    client: Arc<Client>,
    listen_addr: SocketAddr,
) {
    let authority = match accept_connect(&mut stream).await {
        Ok(authority) => authority,
        Err(error) => {
            tracing::debug!("SOCKS5 handshake failed: {error}");
            return;
        }
    };
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
            if let Err(error) = serve_stream(
                stream,
                Scheme::HTTP,
                handler,
                ca,
                client,
                remote_addr,
                listen_addr,
            )
            .await
            {
                tracing::debug!("SOCKS5 HTTP inspection failed: {error}");
            }
        }
        StreamProtocol::Tls => {
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
            if let Err(error) = serve_stream(
                stream,
                Scheme::HTTPS,
                handler,
                ca,
                client,
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
            let mut upstream = match TcpStream::connect(authority.as_str()).await {
                Ok(upstream) => upstream,
                Err(error) => {
                    tracing::debug!("SOCKS5 upstream connection failed: {error}");
                    return;
                }
            };
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
        send_reply(stream, 7).await?;
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
            send_reply(stream, 8).await?;
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
    send_reply(stream, 0).await?;
    Ok(authority)
}

async fn send_reply(stream: &mut TcpStream, status: u8) -> Result<(), std::io::Error> {
    stream
        .write_all(&[SOCKS_VERSION, status, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0])
        .await
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
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
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
