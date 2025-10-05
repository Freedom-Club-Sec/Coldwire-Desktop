use std::env;
use std::process::exit;

const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:9050";

/// Configuration parsed from CLI
#[derive(Debug)]
struct Config {
    server_url: String,
    state_file_path: String,
    proxy: Option<ProxyInfo>,
    debug: bool,
}

#[derive(Debug)]
struct ProxyInfo {
    ptype: ProxyType,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug)]
enum ProxyType {
    Http,
    Socks4,
    Socks5,
}

fn usage() -> &'static str {
    "\
Usage:
  coldwire-desktop --server <server-url> --state-file <file-path> [--debug] [--use-proxy]
If --use-proxy is present you can pass:
  --proxy-type <HTTP|SOCKS4|SOCKS5>    (default: SOCKS5)
  --proxy-addr <host:port>             (default: 127.0.0.1:9050)
  --proxy-user <username>
  --proxy-pass <password>"
}

/// Parse command-line args. Returns a Config or an error string.
fn parse_args() -> Result<Config, String> {
    let mut args = env::args().skip(1); 

    let mut server_url     : Option<String> = None;
    let mut state_file_path: Option<String> = None;

    let mut use_proxy = false;
    
    let mut proxy_type = ProxyType::Socks5;
    let mut proxy_addr: Option<String> = None;
    let mut proxy_user: Option<String> = None;
    let mut proxy_pass: Option<String> = None;
    let mut debug = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server" => {
                if let Some(v) = args.next() {
                    server_url = Some(v);
                } else {
                    return Err(String::from("--server requires a value"));
                }
            }

            "--state-file" => {
                if let Some(v) = args.next() {
                    state_file_path = Some(v);
                } else {
                    return Err(String::from("--state-file requires a file name / path"));
                }
            }
            "--use-proxy" => {
                use_proxy = true;
            }

            "--proxy-type" => {
                if let Some(v) = args.next() {
                    let v_up = v.to_ascii_uppercase();
                    proxy_type = match v_up.as_str() {
                        "HTTP" => ProxyType::Http,
                        "SOCKS4" => ProxyType::Socks4,
                        "SOCKS5" => ProxyType::Socks5,
                        other => return Err(format!(
                            "Invalid proxy type: {} (allowed: HTTP, SOCKS4, SOCKS5)",
                            other
                        )),
                    };
                } else {
                    return Err(String::from("--proxy-type requires a value"));
                }
            }

            "--proxy-addr" => {
                if let Some(v) = args.next() {
                    proxy_addr = Some(v);
                } else {
                    return Err(String::from("--proxy-addr requires a value"));
                }
            }

            "--proxy-user" => {
                if let Some(v) = args.next() {
                    proxy_user = Some(v);
                } else {
                    return Err(String::from("--proxy-user requires a value"));
                }
            }

            "--proxy-pass" => {
                if let Some(v) = args.next() {
                    proxy_pass = Some(v);
                } else {
                    return Err(String::from("--proxy-pass requires a value"));
                }
            }

            "--debug" => {
                debug = true;
            }

            "--help" | "-h" => {
                return Err(String::from("help")); // special-case: main will print usage
            }

            other => {
                return Err(format!("Unknown argument: {}", other));
            }
        }
    }

    // server required
    let server_url = match server_url {
        Some(s) => match clean_server_url(s) {
            Ok(u) => u,
            Err(e) => return Err(e),
        },
        None => return Err(String::from("--server is required")),
    };

    let state_file_path = match state_file_path {
        Some(p) => p,
        None => return Err(String::from("--state-file is required")),
    };

    // build proxy info if requested
    let proxy = if use_proxy {
        let addr = proxy_addr.unwrap_or_else(|| DEFAULT_PROXY_ADDR.to_string());
        let (host, port) = match parse_proxy_addr(&addr) {
            Ok(hp) => hp,
            Err(e) => return Err(format!("Invalid proxy address '{}': {}", addr, e)),
        };

        Some(ProxyInfo {
            ptype: proxy_type,
            host,
            port,
            username: proxy_user,
            password: proxy_pass,
        })
    } else {
        None
    };

    return Ok(Config {
        server_url,
        state_file_path,
        proxy,
        debug,
    });
}

/// Normalize and validate server URL:
/// - If no scheme given, prepend "https://"
/// - Only allow http/https
/// - Require a valid hostname:
///     * ASCII alnum, dot, dash, or "localhost"
///     * max 255 chars
/// - Allow optional :port (0..65535)
/// - No path/query (ignored)
/// - Max total length = 512
fn clean_server_url(mut url: String) -> Result<String, String> {
    if url.len() > 512 {
        return Err(String::from("URL too long (max 512 chars)"));
    }

    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        url = format!("https://{}", url);
    }

    let parts: Vec<&str> = url.splitn(2, "://").collect();
    if parts.len() != 2 {
        return Err(String::from("missing scheme"));
    }
    let scheme = parts[0];
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme '{}'", scheme));
    }

    let rest = parts[1];
    let netloc = rest.split('/').next().unwrap_or("");

    // Split host[:port]
    let (host, port_opt) = if let Some(i) = netloc.rfind(':') {
        (&netloc[..i], Some(&netloc[i+1..]))
    } else {
        (netloc, None)
    };

    if host.is_empty() {
        return Err(String::from("hostname empty"));
    }
    if host.len() > 255 {
        return Err(String::from("hostname too long (max 255 chars)"));
    }

    // Allow localhost or alnum+.- only
    if host != "localhost" {
        if !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
            return Err(String::from("hostname contains invalid characters"));
        }
        if !host.contains('.') {
            return Err(String::from("hostname must contain a dot unless 'localhost'"));
        }
    }

    // Validate port if present
    if let Some(port_str) = port_opt {
        if port_str.is_empty() {
            return Err(String::from("port is empty"));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| String::from("port is not a valid number"))?;
        return Ok(format!("{}://{}:{}", scheme, host, port));
    }

    Ok(format!("{}://{}", scheme, host))
}

/// Parse "host:port" into (host, port).
/// Accepts:
///   - "hostname:1234"
///   - "127.0.0.1:9050"
///   - "[::1]:9050"  (IPv6 MUST be bracketed)
fn parse_proxy_addr(s: &str) -> Result<(String, u16), String> {
    if s.starts_with('[') {
        // expect [ipv6]:port
        let closing = s.find(']').ok_or_else(|| String::from("missing closing ']' for IPv6"))?;
        let host = &s[1..closing];
        let rest = &s[(closing + 1)..];
        if !rest.starts_with(':') {
            return Err(String::from("Missing ':' after IPv6 address"));
        }
        let port_str = &rest[1..];
        if port_str.is_empty() {
            return Err(String::from("Port is empty"));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| String::from("Port is not a valid number"))?;
        return Ok((host.to_string(), port));
    }

    // normal host:port - split on last ':' so host may contain colons only if bracketed
    let mut parts = s.rsplitn(2, ':');
    let port_str = parts.next().unwrap_or("");
    let host = parts.next().unwrap_or("");
    if host.is_empty() || port_str.is_empty() {
        return Err(String::from("Empty host or port"));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| String::from("Port is not a valid number"))?;
    return Ok((host.to_string(), port));
}

fn main() {
    match parse_args() {
        Ok(cfg) => {
            if cfg.debug {
                eprintln!("Parsed config: {:#?}", cfg);
            } else {
                println!("Server: {}", cfg.server_url);
                if let Some(p) = &cfg.proxy {
                    println!(
                        "Proxy: {:?} {}:{}{}",
                        p.ptype,
                        p.host,
                        p.port,
                        if p.username.is_some() || p.password.is_some() {
                            " (with auth)"
                        } else {
                            ""
                        }
                    );
                } else {
                    println!("No proxy");
                }
            }
            // TODO: hand cfg to connection/auth code...
        }
        Err(e) => {
            if e == "help" {
                println!("{}", usage());
                exit(0);
            } else {
                eprintln!("Error: {}", e);
                eprintln!();
                eprintln!("{}", usage());
                exit(1);
            }
        }
    }
}
