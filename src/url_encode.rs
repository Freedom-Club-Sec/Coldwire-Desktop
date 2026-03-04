fn url_escape(s: &str) -> String {
    let mut escaped = String::new();
    for b in s.bytes() {
        match b {
            // Unreserved characters according to RFC 3986
            b'A'..=b'Z' |
            b'a'..=b'z' |
            b'0'..=b'9' |
            b'-' | b'_' | b'.' | b'~' => escaped.push(b as char),
            _ => escaped.push_str(&format!("%{:02X}", b)),
        }
    }
    escaped
}

/// Minimal url-safe encoding function
pub fn urlencode(data: &[(String, String)]) -> String {
    data.iter()
        .map(|(k, v)| format!("{}={}", url_escape(k.as_ref()), url_escape(v.as_ref())))
        .collect::<Vec<_>>()
        .join("&")
}


/// Encode a list-style metadata as a single bracketed value:
/// e.g. [("tags", vec!["a","b"])] -> "tags=%5Ba%2C%20b%5D"
pub fn urlencode_list_bracketed(data: &[(String, Vec<String>)]) -> String {
    let mut parts = Vec::new();
    for (k, vec) in data {
        let joined = vec.join(", ");
        let bracketed = format!("[{}]", joined);
        parts.push(format!("{}={}", url_escape(k), url_escape(&bracketed)));
    }
    parts.join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_output_pairs() {
        let metadata = [
            ("name".to_string(), "chad".to_string()),
            ("tags".to_string(), "rust".to_string()),
            ("tags".to_string(), "safe".to_string()),
        ];

        let expected = "name=chad&tags=rust&tags=safe";
        let encoded = urlencode(&metadata);
        assert_eq!(encoded, expected);
    }


    #[test]
    fn test_list_bracketed() {
        let metadata = [
            ("tags".to_string(), vec!["some".to_string(), "values".to_string(), "like this".to_string()]),
        ];
        let encoded = urlencode_list_bracketed(&metadata);
        // bracketed value: "[some, values, like this]" percent-encoded
        assert!(encoded.starts_with("tags="));
        // make sure brackets and spaces were encoded
        assert!(encoded.contains("%5B"));
        assert!(encoded.contains("%5D"));
        assert!(encoded.contains("%20"));
    }
}
