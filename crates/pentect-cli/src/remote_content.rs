//! Constrained retrieval for model-bound remote attachments.

use futures_util::StreamExt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use zeroize::Zeroize;

const MAX_REMOTE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REDIRECTS: usize = 3;

pub(crate) struct RemoteContent {
    pub(crate) bytes: Vec<u8>,
    pub(crate) media_type: String,
    pub(crate) filename: String,
}

pub(crate) async fn fetch(url: &str) -> Result<RemoteContent, String> {
    let mut current = validate_url(url)?;
    for redirects in 0..=MAX_REDIRECTS {
        let host = current
            .host_str()
            .ok_or_else(|| "remote attachment URL has no host".to_string())?
            .to_string();
        let port = current
            .port_or_known_default()
            .ok_or_else(|| "remote attachment URL has no port".to_string())?;
        let addresses = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| "remote attachment host could not be resolved".to_string())?
            .collect::<Vec<_>>();
        if addresses.is_empty() || addresses.iter().any(|address| !public_ip(address.ip())) {
            return Err("remote attachment resolved to a non-public address".to_string());
        }
        let pinned = SocketAddr::new(addresses[0].ip(), port);
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .resolve(&host, pinned)
            .build()
            .map_err(|_| "remote attachment client could not be created".to_string())?;
        let response = client
            .get(current.clone())
            .send()
            .await
            .map_err(|_| "remote attachment could not be fetched".to_string())?;
        if response.status().is_redirection() {
            if redirects == MAX_REDIRECTS {
                return Err("remote attachment redirected too many times".to_string());
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| "remote attachment redirect has no Location".to_string())?;
            current = validate_url(
                current
                    .join(location)
                    .map_err(|_| "remote attachment redirect is invalid".to_string())?
                    .as_str(),
            )?;
            continue;
        }
        if !response.status().is_success() {
            return Err(format!(
                "remote attachment returned HTTP {}",
                response.status().as_u16()
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_REMOTE_BYTES as u64)
        {
            return Err("remote attachment is too large".to_string());
        }
        let media_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap_or("application/octet-stream")
            .trim()
            .to_string();
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => {
                    bytes.zeroize();
                    return Err("remote attachment body failed".to_string());
                }
            };
            if bytes.len().saturating_add(chunk.len()) > MAX_REMOTE_BYTES {
                bytes.zeroize();
                return Err("remote attachment is too large".to_string());
            }
            bytes.extend_from_slice(&chunk);
        }
        let filename = current
            .path_segments()
            .and_then(|mut segments| segments.rfind(|part| !part.is_empty()))
            .unwrap_or("attachment")
            .to_string();
        return Ok(RemoteContent {
            bytes,
            media_type,
            filename,
        });
    }
    Err("remote attachment could not be fetched".to_string())
}

fn validate_url(value: &str) -> Result<reqwest::Url, String> {
    let url =
        reqwest::Url::parse(value).map_err(|_| "remote attachment URL is invalid".to_string())?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err("remote attachment URL must use https".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("remote attachment URL must not contain credentials or a fragment".to_string());
    }
    Ok(url)
}

fn public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
                || address.octets()[0] == 0
                || address.octets()[0] >= 240
                || (address.octets()[0] == 100 && (64..=127).contains(&address.octets()[1]))
                || (address.octets()[0] == 198 && (18..=19).contains(&address.octets()[1])))
        }
        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (address.segments()[0] & 0xfe00) == 0xfc00
                || (address.segments()[0] & 0xffc0) == 0xfe80
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|address| !public_ip(IpAddr::V4(address))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_local_and_credentialed_urls() {
        assert!(validate_url("http://example.com/file").is_err());
        assert!(validate_url("https://user:pass@example.com/file").is_err());
        assert!(!public_ip("127.0.0.1".parse().unwrap()));
        assert!(!public_ip("169.254.169.254".parse().unwrap()));
        assert!(!public_ip("::1".parse().unwrap()));
        assert!(public_ip("1.1.1.1".parse().unwrap()));
    }
}
