use std::io::Read;
use std::io::Write;
use std::fs::File;
use ureq::{Agent};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
use crate::json;

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct ProxyInfo {
    pub host: String,
    pub port: u16,
    pub username: Option<Zeroizing<String>>,
    pub password: Option<Zeroizing<String>>,

    #[zeroize(skip)]
    pub proxy_type: ProxyType
}

#[derive(Debug, PartialEq)]
pub enum ProxyType {
    Http,
    Socks4,
    Socks5,
}

fn proxy_to_string(proxy: &ProxyInfo) -> String {
    let scheme = match proxy.proxy_type {
        ProxyType::Http => "http",
        ProxyType::Socks4 => "socks4",
        ProxyType::Socks5 => "socks5",
    };

    let auth = match (&proxy.username, &proxy.password) {
        (Some(user), Some(pass)) => {
            format!("{}:{}@", user.as_str(), pass.as_str())
        }
        (Some(user), None) => {
            format!("{}@", user.as_str())
        }
        _ => String::new(),
    };

    format!("{}://{}{}:{}", scheme, auth, proxy.host, proxy.port)
}


pub fn get_request(url: String, headers: Option<&[(String, String)]>, metadata: Option<&(String, Vec<String>)>, proxy: Option<&ProxyInfo>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut config = Agent::config_builder()
        .http_status_as_error(false);


    if proxy.is_some() {
        let proxy_str = proxy_to_string(&proxy.unwrap());
        
        let p = ureq::Proxy::new(&proxy_str).expect("Failed to create proxy instance");

        config = config.proxy(Some(p));
    }

    let config = config.build();

    let agent: Agent = config.into();

    let mut request = agent.get(url);


    if metadata.is_some() {
        for m in metadata.unwrap().1.clone() {
            request = request.query(metadata.unwrap().0.clone(), m);
        }
    }

    if headers.is_some() {
        for (key, value) in headers.unwrap() {
            request = request.header(key, value);
        }
    }

    let mut body = Zeroizing::new(Vec::with_capacity(1024));

    let mut response = request
        .call()
        .map_err(|_| Error::FailedToSendRequest)?;

    response.body_mut()
        .as_reader()
        .read_to_end(&mut body)
        .map_err(|_| Error::FailedToReadResponseBody)?;

    Ok(body)
}







pub fn post_request(url: String, headers: Option<&[(String, String)]>, metadata_json: Option<&[(String, String)]>, blob: Option<Zeroizing<Vec<u8>>>, proxy: Option<&ProxyInfo>) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !metadata_json.is_some() && !blob.is_some() {
        return Err(Error::InvalidRequestBody);
    }



    let mut config = Agent::config_builder()
        .http_status_as_error(false);


    if proxy.is_some() {
        let proxy_str = proxy_to_string(&proxy.unwrap());
        
        let p = ureq::Proxy::new(&proxy_str).expect("Failed to create proxy instance");

        config = config.proxy(Some(p));
    }

    let config = config.build();

    let agent: Agent = config.into();

    let mut request = agent.post(url);


    if headers.is_some() {
        for (key, value) in headers.unwrap() {
            request = request.header(key, value);
        }
    }


    let mut body = Zeroizing::new(Vec::with_capacity(1024));

    let mut response = if let Some(blob_data) = blob {
        let boundary = "WebKitFormBoundary1234567890abcdefg";
        let crlf = "\r\n";


        // let metadata_bytes = json::kv_pairs_to_json(metadata).into_bytes();

        let mut body = Vec::new();


        if metadata_json.is_some() {
            let metadata_str = json::kv_pairs_to_json(metadata_json.unwrap());
             write!(
                &mut body,
                "--{boundary}{crlf}Content-Disposition: form-data; name=\"metadata\"{crlf}{crlf}{metadata}{crlf}",
                boundary = boundary,
                crlf = crlf,
                metadata = metadata_str
             ).map_err(|_| Error::FailedToWriteToRequestBody)?;

        }


         write!(
            &mut body,
            "--{boundary}{crlf}Content-Disposition: form-data; name=\"blob\"; filename=\"{filename}\"{crlf}Content-Type: application/octet-stream{crlf}{crlf}",
            boundary = boundary,
            crlf = crlf,
            filename = "test_lol.bin"
        ).map_err(|_| Error::FailedToWriteToRequestBody)?;

        body.extend_from_slice(&blob_data);
        body.extend_from_slice(crlf.as_bytes());

        // Closing boundary
        write!(&mut body, "--{boundary}--{crlf}", boundary = boundary, crlf = crlf)
            .map_err(|_| Error::FailedToWriteToRequestBody)?;
            

        request = request.header("content-type", format!("multipart/form-data; boundary={}", boundary));

        request
            .send(body.as_slice())
            .map_err(|_| Error::FailedToSendRequestBody)?
      
    } else if let Some(metadata) = metadata_json {
        let metadata_bytes = json::kv_pairs_to_json(metadata).into_bytes();
        request
            .header("content-type", "application/json")
            .send(metadata_bytes)
            .map_err(|_| Error::FailedToSendRequestBody)?
    } else {
        return Err(Error::ImpossibleConditionButRustForcesUsToReturnError);
    };


    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut body)
        .map_err(|_| Error::FailedToReadResponseBody)?;


    Ok(body)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_get() {
        let server_url = String::from("https://google.com");

        let result = get_request(server_url, None, None);

        assert!(!result.is_err(), "Failed to send a GET request to google.com");
    }

    #[test]
    fn test_request_post_metadata() {
        let server_url = String::from("https://google.com");

        let metadata: &[(String, String)] = &[
            ("Hello".to_string(), "World!".to_string()),
        ];

        let result = post_request(server_url, None, Some(metadata), None);

        assert!(!result.is_err(), "Failed to send a POST request to google.com");
    }

    #[test]
    fn test_request_post_blob() {
        let server_url = String::from("https://google.com");

        let blob = libcold::crypto::generate_secure_random_bytes(100000).expect("Failed to generate random bytes");

        let result = post_request(server_url, None, None, Some(blob));

        assert!(!result.is_err(), "Failed to send a POST request to google.com");
    }
}
