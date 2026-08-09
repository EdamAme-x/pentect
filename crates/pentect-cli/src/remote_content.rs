//! Constrained retrieval for model-bound remote attachments.

use futures_util::StreamExt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use zeroize::Zeroize;

const MAX_REMOTE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REMOTE_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_REMOTE_REQUEST_ITEMS: usize = 16;
const MAX_REDIRECTS: usize = 3;

/// Request-local limits shared by every remote attachment resolution in one
/// model request. Callers should create one budget and pass it to every fetch.
pub(crate) struct RemoteRequestBudget {
    bytes: usize,
    items: usize,
    current_item_bytes: usize,
    max_bytes: usize,
    max_items: usize,
}

impl Default for RemoteRequestBudget {
    fn default() -> Self {
        Self {
            bytes: 0,
            items: 0,
            current_item_bytes: 0,
            max_bytes: MAX_REMOTE_REQUEST_BYTES,
            max_items: MAX_REMOTE_REQUEST_ITEMS,
        }
    }
}

impl RemoteRequestBudget {
    #[cfg(test)]
    fn with_limits(max_bytes: usize, max_items: usize) -> Self {
        Self {
            bytes: 0,
            items: 0,
            current_item_bytes: 0,
            max_bytes,
            max_items,
        }
    }

    pub(crate) fn begin(&mut self) -> Result<(), String> {
        if self.items >= self.max_items {
            return Err("remote attachments exceed the request item limit".to_string());
        }
        self.items += 1;
        self.current_item_bytes = 0;
        Ok(())
    }

    pub(crate) fn check_declared_size(&self, bytes: u64) -> Result<(), String> {
        let bytes = usize::try_from(bytes)
            .map_err(|_| "remote attachments exceed the request byte limit".to_string())?;
        if bytes > MAX_REMOTE_BYTES.saturating_sub(self.current_item_bytes)
            || bytes > self.max_bytes.saturating_sub(self.bytes)
        {
            return Err("remote attachments exceed the request byte limit".to_string());
        }
        Ok(())
    }

    pub(crate) fn consume(&mut self, bytes: usize) -> Result<(), String> {
        if bytes > MAX_REMOTE_BYTES.saturating_sub(self.current_item_bytes)
            || bytes > self.max_bytes.saturating_sub(self.bytes)
        {
            return Err("remote attachments exceed the request byte limit".to_string());
        }
        self.bytes += bytes;
        self.current_item_bytes += bytes;
        Ok(())
    }
}

pub(crate) struct RemoteContent {
    pub(crate) bytes: Vec<u8>,
    pub(crate) media_type: String,
    pub(crate) filename: String,
}

pub(crate) async fn fetch_with_budget(
    url: &str,
    budget: &mut RemoteRequestBudget,
) -> Result<RemoteContent, String> {
    budget.begin()?;
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
            .no_proxy()
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
        if let Some(length) = response.content_length() {
            budget.check_declared_size(length)?;
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
            if let Err(error) = budget.consume(chunk.len()) {
                bytes.zeroize();
                return Err(error);
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
            if let Some(embedded) = pentect_agent::embedded_ipv4(address) {
                return public_ip(IpAddr::V4(embedded));
            }
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (address.segments()[0] & 0xfe00) == 0xfc00
                || (address.segments()[0] & 0xffc0) == 0xfe80
                || (address.segments()[0] & 0xffc0) == 0xfec0
                || (address.segments()[0] == 0x2001 && address.segments()[1] == 0)
                || (address.segments()[0] == 0x2001 && address.segments()[1] == 0x0db8))
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
        assert!(!public_ip("::127.0.0.1".parse().unwrap()));
        assert!(!public_ip("64:ff9b::127.0.0.1".parse().unwrap()));
        assert!(!public_ip("2002:7f00:0001::".parse().unwrap()));
        assert!(public_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn request_budget_limits_items_and_aggregate_bytes() {
        let mut budget = RemoteRequestBudget::with_limits(10, 2);
        budget.begin().unwrap();
        budget.consume(6).unwrap();
        budget.begin().unwrap();
        assert!(budget.check_declared_size(5).is_err());
        budget.consume(4).unwrap();
        assert!(budget.consume(1).is_err());
        assert!(budget.begin().is_err());
    }

    #[test]
    fn request_budget_rejects_single_oversized_item() {
        let mut budget = RemoteRequestBudget::with_limits(MAX_REMOTE_BYTES * 2, 1);
        budget.begin().unwrap();
        assert!(budget
            .check_declared_size(MAX_REMOTE_BYTES as u64 + 1)
            .is_err());
    }

    #[test]
    fn request_budget_rejects_chunked_item_over_the_single_item_limit() {
        let mut budget = RemoteRequestBudget::default();
        budget.begin().unwrap();
        budget.consume(4 * 1024 * 1024).unwrap();
        budget.consume(4 * 1024 * 1024).unwrap();
        assert!(budget.consume(1).is_err());
    }
}
