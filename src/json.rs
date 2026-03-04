pub fn kv_pairs_to_json(metadata: &[(String, String)]) -> String {
    let mut json = String::from("{");
    for (i, (k, v)) in metadata.iter().enumerate() {
        json.push('"');
        json.push_str(k);
        json.push_str("\":\"");
        json.push_str(v);
        json.push('"');
        if i != metadata.len() - 1 {
            json.push(',');
        }
    }
    json.push('}');
    json
}

pub fn extract_json_value(json: &str, key: &str) -> Option<String> {
    let json = json.trim();
    let search = format!(r#""{}":""#, key);

    let start = json.find(&search)? + search.len();

    let end = json[start..].find('"')? + start;

    Some(json[start..end].to_string())
}
