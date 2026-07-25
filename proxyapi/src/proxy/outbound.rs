use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use base64::Engine as _;
use http::uri::Authority;
use http::{HeaderValue, Uri};
use hyper_util::client::legacy::connect::proxy::{SocksV5, Tunnel};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tower_service::Service;

use super::BoxError;

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProxyKind {
    Http,
    Socks5,
}

/// Upstream HTTP CONNECT or SOCKS5 proxy configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamProxyConfig {
    kind: ProxyKind,
    destination: Uri,
    username: Option<String>,
    password: Option<String>,
}

impl UpstreamProxyConfig {
    /// Attach credentials used for Basic (HTTP) or username/password (SOCKS5)
    /// authentication.
    #[must_use]
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    pub fn destination(&self) -> &Uri {
        &self.destination
    }
}

impl FromStr for UpstreamProxyConfig {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (kind, rest) = if let Some(rest) = value.strip_prefix("http://") {
            (ProxyKind::Http, rest)
        } else if let Some(rest) = value.strip_prefix("socks5://") {
            (ProxyKind::Socks5, rest)
        } else {
            return Err("upstream proxy must use http:// or socks5://".to_owned());
        };
        if rest.contains('@') {
            return Err(
                "put credentials in --upstream-proxy-auth, not in the proxy URL".to_owned(),
            );
        }
        let destination: Uri = format!("http://{rest}")
            .parse()
            .map_err(|error: http::uri::InvalidUri| error.to_string())?;
        if destination.host().is_none() || destination.port_u16().is_none() {
            return Err("upstream proxy URL must include host and port".to_owned());
        }
        Ok(Self {
            kind,
            destination,
            username: None,
            password: None,
        })
    }
}

#[derive(Clone)]
pub(crate) enum OutboundConnector {
    Direct(HttpConnector),
    Http(Tunnel<HttpConnector>),
    Socks5(SocksV5<HttpConnector>),
}

impl OutboundConnector {
    pub(crate) fn new(proxy: Option<&UpstreamProxyConfig>) -> Result<Self, crate::Error> {
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        match proxy {
            None => Ok(Self::Direct(connector)),
            Some(config) if config.kind == ProxyKind::Http => {
                let mut tunnel = Tunnel::new(config.destination.clone(), connector);
                if let Some(username) = &config.username {
                    let password = config.password.as_deref().unwrap_or("");
                    let encoded = base64::engine::general_purpose::STANDARD
                        .encode(format!("{username}:{password}"));
                    let auth = HeaderValue::from_str(&format!("Basic {encoded}"))?;
                    tunnel = tunnel.with_auth(auth);
                }
                Ok(Self::Http(tunnel))
            }
            Some(config) => {
                let mut socks = SocksV5::new(config.destination.clone(), connector);
                if let Some(username) = &config.username {
                    socks = socks.with_auth(
                        username.clone(),
                        config.password.clone().unwrap_or_default(),
                    );
                }
                Ok(Self::Socks5(socks))
            }
        }
    }
}

impl Service<Uri> for OutboundConnector {
    type Response = TokioIo<TcpStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::Direct(connector) => connector.poll_ready(context).map_err(box_error),
            Self::Http(connector) => connector.poll_ready(context).map_err(box_error),
            Self::Socks5(connector) => connector.poll_ready(context).map_err(box_error),
        }
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        match self {
            Self::Direct(connector) => {
                let future = connector.call(destination);
                Box::pin(async move { future.await.map_err(box_error) })
            }
            Self::Http(connector) => {
                let future = connector.call(with_default_port(destination));
                Box::pin(async move { future.await.map_err(box_error) })
            }
            Self::Socks5(connector) => {
                let future = connector.call(with_default_port(destination));
                Box::pin(async move { future.await.map_err(box_error) })
            }
        }
    }
}

fn with_default_port(destination: Uri) -> Uri {
    if destination.port_u16().is_some() {
        return destination;
    }
    let Some(port) = destination.scheme_str().and_then(|scheme| match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }) else {
        return destination;
    };
    let Some(authority) = destination.authority() else {
        return destination;
    };
    let Ok(authority) = Authority::from_str(&format!("{authority}:{port}")) else {
        return destination;
    };

    let mut parts = destination.clone().into_parts();
    parts.authority = Some(authority);
    Uri::from_parts(parts).unwrap_or(destination)
}

fn box_error(error: impl std::error::Error + Send + Sync + 'static) -> BoxError {
    Box::new(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_and_socks5_proxies_and_rejects_ambiguous_values() {
        let http: UpstreamProxyConfig = "http://proxy.test:8080".parse().unwrap();
        assert_eq!(http.kind, ProxyKind::Http);
        assert_eq!(
            http.destination(),
            &"http://proxy.test:8080".parse::<Uri>().unwrap()
        );

        let socks: UpstreamProxyConfig = "socks5://127.0.0.1:1080".parse().unwrap();
        assert_eq!(socks.kind, ProxyKind::Socks5);
        assert_eq!(socks.username, None);

        assert!("https://proxy.test:443"
            .parse::<UpstreamProxyConfig>()
            .is_err());
        assert!("http://user:pass@proxy.test:8080"
            .parse::<UpstreamProxyConfig>()
            .is_err());
        assert!("http://proxy.test".parse::<UpstreamProxyConfig>().is_err());
    }

    #[test]
    fn adds_the_scheme_default_port_for_proxy_tunnels() {
        let http = with_default_port("http://example.test/path?q=1".parse().unwrap());
        assert_eq!(http, "http://example.test:80/path?q=1");

        let https = with_default_port("https://[::1]/".parse().unwrap());
        assert_eq!(https, "https://[::1]:443/");

        let explicit = "https://example.test:8443/".parse::<Uri>().unwrap();
        assert_eq!(with_default_port(explicit.clone()), explicit);

        let unknown = "custom://example.test/path".parse::<Uri>().unwrap();
        assert_eq!(with_default_port(unknown.clone()), unknown);
        let relative = "/path".parse::<Uri>().unwrap();
        assert_eq!(with_default_port(relative.clone()), relative);
    }

    #[tokio::test]
    async fn constructs_and_calls_each_connector_kind() {
        use std::future::poll_fn;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        let direct_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct_address = direct_listener.local_addr().unwrap();
        let direct_server = tokio::spawn(async move {
            let (_stream, _) = direct_listener.accept().await.unwrap();
        });
        let mut direct = OutboundConnector::new(None).unwrap();
        poll_fn(|context| direct.poll_ready(context)).await.unwrap();
        direct
            .call(format!("http://{direct_address}/").parse().unwrap())
            .await
            .unwrap();
        direct_server.await.unwrap();

        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_address = http_listener.local_addr().unwrap();
        let http_server = tokio::spawn(async move {
            let (mut stream, _) = http_listener.accept().await.unwrap();
            let mut request = vec![0_u8; 1_024];
            let length = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..length]).starts_with("CONNECT "));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });
        let http_config: UpstreamProxyConfig = format!("http://{http_address}").parse().unwrap();
        let authenticated = http_config.clone().with_auth("user", "password");
        assert_eq!(authenticated.username.as_deref(), Some("user"));
        assert_eq!(authenticated.password.as_deref(), Some("password"));
        let mut http = OutboundConnector::new(Some(&authenticated)).unwrap();
        assert!(matches!(http, OutboundConnector::Http(_)));
        poll_fn(|context| http.poll_ready(context)).await.unwrap();
        http.call("http://example.test/".parse().unwrap())
            .await
            .unwrap();
        http_server.await.unwrap();

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_address = socks_listener.local_addr().unwrap();
        let socks_server = tokio::spawn(async move {
            let (mut stream, _) = socks_listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..3], &[5, 1, 0]);
            match request[3] {
                1 => {
                    let mut rest = [0_u8; 6];
                    stream.read_exact(&mut rest).await.unwrap();
                }
                3 => {
                    let length = stream.read_u8().await.unwrap();
                    let mut rest = vec![0_u8; usize::from(length) + 2];
                    stream.read_exact(&mut rest).await.unwrap();
                }
                4 => {
                    let mut rest = [0_u8; 18];
                    stream.read_exact(&mut rest).await.unwrap();
                }
                other => panic!("unexpected SOCKS address type {other}"),
            }
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
        });
        let socks_config: UpstreamProxyConfig =
            format!("socks5://{socks_address}").parse().unwrap();
        let mut socks = OutboundConnector::new(Some(&socks_config)).unwrap();
        assert!(matches!(socks, OutboundConnector::Socks5(_)));
        poll_fn(|context| socks.poll_ready(context)).await.unwrap();
        socks
            .call("http://example.test/".parse().unwrap())
            .await
            .unwrap();
        socks_server.await.unwrap();

        let authenticated_socks = socks_config.with_auth("user", "password");
        assert!(matches!(
            OutboundConnector::new(Some(&authenticated_socks)).unwrap(),
            OutboundConnector::Socks5(_)
        ));
    }
}
