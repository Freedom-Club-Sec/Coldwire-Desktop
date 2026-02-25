mod error;
mod consts;

use std::env;
use std::process::exit;
use std::io::Write;
use std::path::Path;

use zeroize::{Zeroize, Zeroizing};
use crate::error::Error;


#[derive(Zeroize, Debug)]
#[zeroize(drop)]
struct Config {
    server_url: Option<Zeroizing<String>>,
    state_file_path: Option<Zeroizing<String>>,
    proxy: Option<ProxyInfo>,
    debug: bool,

    state_file_password: Option<Zeroizing<Vec<u8>>>
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
struct ProxyInfo {
    #[zeroize(skip)]
    proxy_type: ProxyType,    

    host: String,
    port: u16,
    username: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>
}

#[derive(Debug)]
enum ProxyType {
    Http,
    Socks4,
    Socks5,
}

impl Config {
    pub fn confirm_proxy_info(&mut self) -> Result<(), Error> {
        if let Some(proxy) = &self.proxy {
            let user_part = proxy.username
                .as_ref()
                .map(|u| format!(" ({})", u.as_str()))
                .unwrap_or_default();

            let pass_part = proxy.password
                .as_ref()
                .map(|_| " (with password authentication)".to_string())
                .unwrap_or_default();

            println!(
                "Configured proxy: {:?} {}:{}{}{}\n",
                proxy.proxy_type,
                proxy.host,
                proxy.port,
                user_part,
                pass_part
            );
        } else {
            println!("No proxy was configured.\n");
        }


        let confirm = prompt_user("Is the proxy configuration correct? [y/N]: ")?;
        if !confirm.eq_ignore_ascii_case("yes") && !confirm.eq_ignore_ascii_case("y") {
            println!("Aborting the program for safety.");
            std::process::exit(2);
        }

        Ok(())
    }


    pub fn prompt_state_file(&mut self) -> Result<(), Error> {
        let mut state_file_path = Zeroizing::new(String::new());

        loop {
            state_file_path = prompt_user(
                "Enter the state file path (If it does not exist, it will be created): ",
            )?;
            if state_file_path.is_empty() {
                println!("Please enter a valid path!\n");
                continue;
            }
            break;
        }

        if Path::new(&state_file_path).exists() {
            let state_file_password = Zeroizing::new(prompt_user("Enter password: ")?);
        } else {
            let confirm = prompt_user("File does not exist, would you like to create it? [y/N]: ")?;
            if !confirm.eq_ignore_ascii_case("yes") && !confirm.eq_ignore_ascii_case("y") {
                println!("Aborting program.");
                std::process::exit(2);
            }

            self.update_server_url()?;

            loop {
                let state_file_password = Zeroizing::new(prompt_user("Create password: ")?);
                let state_file_password_confirm = Zeroizing::new(prompt_user("Confirm password: ")?);
                
                if state_file_password != state_file_password_confirm {
                    println!("Password does not match! Try again.\n");
                    continue;
                }
                break;
            }


        }

        Ok(())
    }

    fn update_server_url(&mut self) -> Result<(), Error> {
        let mut server_url = Zeroizing::new(String::new());

        loop {
            server_url = prompt_user("Enter server URL: ")?;

            server_url = match clean_server_url(server_url.to_string()) {
                Ok(u) => Zeroizing::new(u),
                Err(e) => {
                    println!("ERROR: {}\n", e);
                    continue
                }
            };
            break
        }

        self.server_url = Some(server_url);

        Ok(())
    }
}


fn prompt_user(msg: &str) -> Result<Zeroizing<String>, Error> {
    print!("{msg}");
    std::io::stdout().flush()
        .map_err(|_| Error::FailedToFlush)?;

    let mut input = Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut input)
        .map_err(|_| Error::FailedToReadLine)?;

    Ok(Zeroizing::new(input.trim().to_string()))
}



fn usage() -> &'static str {
    "\
Usage:
  coldwire-desktop [--debug] [--use-proxy]
If --use-proxy is present you can pass:
  --proxy-type <HTTP|SOCKS4|SOCKS5>    (default: SOCKS5)
  --proxy-addr <host:port>             (default: 127.0.0.1:9050)
  --proxy-user <username>
  --proxy-pass <password>"
}

/// Parse command-line args. Returns a Config or an error string.
fn parse_args() -> Result<Config, String> {
    let mut args = env::args().skip(1); 

    let mut use_proxy = false;
    
    let mut proxy_type = ProxyType::Socks5;
    let mut proxy_addr: Option<Zeroizing<String>> = None;
    let mut proxy_user: Option<Zeroizing<String>> = None;
    let mut proxy_pass: Option<Zeroizing<String>> = None;
    let mut debug = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
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
                    proxy_addr = Some(Zeroizing::new(v));
                } else {
                    return Err(String::from("--proxy-addr requires a value"));
                }
            }

            "--proxy-user" => {
                if let Some(v) = args.next() {
                    proxy_user = Some(Zeroizing::new(v));
                } else {
                    return Err(String::from("--proxy-user requires a value"));
                }
            }

            "--proxy-pass" => {
                if let Some(v) = args.next() {
                    proxy_pass = Some(Zeroizing::new(v));
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

    let proxy = if use_proxy {
        let addr = proxy_addr.unwrap_or_else(|| Zeroizing::new(consts::DEFAULT_PROXY_ADDR.to_string()));
        let (host, port) = match parse_proxy_addr(&addr) {
            Ok(hp) => hp,
            Err(e) => return Err(format!("Invalid proxy address: {}", e)),
        };

        Some(ProxyInfo {
            proxy_type: proxy_type,
            host,
            port,
            username: proxy_user,
            password: proxy_pass,
        })
    } else {
        None
    };

    return Ok(Config {
        server_url: None,
        state_file_path: None,
        state_file_password: None,
        proxy: proxy,
        debug: debug,
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
    let mut cfg = match parse_args() {
        Ok(cfg) => {
            cfg
            
            
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
    };

    cfg.confirm_proxy_info();
    cfg.prompt_state_file();

    // TODO: hand cfg to connection/auth code...


}
