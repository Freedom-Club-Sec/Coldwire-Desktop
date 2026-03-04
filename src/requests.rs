use std::io::Read;
use ureq::{Agent};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
use crate::url_encode;
use crate::json;

pub fn get_request(url: String, headers: Option<&[(String, String)]>, metadata_str: Option<&[(String, String)]>, metadata_list: Option<&[(String, Vec<String>)]>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut full_url = url;

    if metadata_str.is_some() && metadata_list.is_some() {
        return Err(Error::InvalidRequestMetadata)
    }

    if metadata_str.is_some() {
        let metadata_str_encoded = url_encode::urlencode(metadata_str.unwrap());
        full_url = format!("{}?{}", full_url, metadata_str_encoded);
    
    } else if metadata_list.is_some() {
        let metadata_list_encoded = url_encode::urlencode_list_bracketed(metadata_list.unwrap());
        full_url = format!("{}?{}", full_url, metadata_list_encoded);

    }

    let mut config = Agent::config_builder()
        .http_status_as_error(false)
        .build();

    let agent: Agent = config.into();

    let mut request = agent.get(full_url);

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







pub fn post_request(url: String, headers: Option<&[(String, String)]>, metadata_json: Option<&[(String, String)]>, blob: Option<Zeroizing<Vec<u8>>>) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !metadata_json.is_some() && !blob.is_some() {
        return Err(Error::InvalidRequestBody);
    }

    if metadata_json.is_some() && blob.is_some() {
        return Err(Error::InvalidRequestBody);
    }



    let mut config = Agent::config_builder()
        .http_status_as_error(false)
        .build();

    let agent: Agent = config.into();

    let mut request = agent.post(url);


    if headers.is_some() {
        for (key, value) in headers.unwrap() {
            request = request.header(key, value);
        }
    }


    let mut body = Zeroizing::new(Vec::with_capacity(1024));

    let mut response = if let Some(metadata) = metadata_json {
            let metadata_bytes = json::kv_pairs_to_json(metadata).into_bytes();
            request
                .header("content-type", "application/json")
                .send(metadata_bytes)
                .map_err(|_| Error::FailedToSendRequestBody)?
        } else if let Some(blob_data) = blob {
            request
                .send(blob_data.as_slice())
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

        let result = get_request(server_url, None, None, None);

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
