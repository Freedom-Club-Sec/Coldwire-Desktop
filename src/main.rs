mod error;
mod utils;
mod json;
mod consts;
mod crypto;
mod requests;

use std::env;
use std::process::exit;
use std::fs::File;
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;

use zeroize::{Zeroize, Zeroizing};
use base64::{
    engine::general_purpose,
    prelude::*
};
use libcold;
use crate::error::Error;


#[derive(Zeroize, Debug)]
#[zeroize(drop)]
struct Config {
    server_url: Option<Zeroizing<String>>,

    user_id: Option<Zeroizing<String>>,
    auth_token: Option<Zeroizing<String>>,

    auth_secret_key: Option<Zeroizing<Vec<u8>>>,
    auth_public_key: Option<Zeroizing<Vec<u8>>>,


    contact_list: Option<Vec<libcold::Contact>>,

    state_file_path: Option<Zeroizing<String>>,
    proxy: Option<ProxyInfo>,
    debug: bool,

    state_file_password_hash: Option<Zeroizing<Vec<u8>>>,
    state_file_password_hash_salt: Option<Zeroizing<Vec<u8>>>
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


        let confirm = prompt_user("Is the proxy configuration correct? [y/N]: ", true)?;
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
                true
            )?;
            if state_file_path.is_empty() {
                println!("Please enter a valid path!\n");
                continue;
            }
            break;
        }

        if Path::new(&state_file_path).exists() {
            self.prompt_and_decrypt_state_file(&state_file_path)?;
            self.state_file_path = Some(state_file_path);

        } else {
            let confirm = prompt_user("File does not exist, would you like to create it? [y/N]: ", true)?;
            if !confirm.eq_ignore_ascii_case("yes") && !confirm.eq_ignore_ascii_case("y") {
                println!("Aborting program.");
                std::process::exit(2);
            }

            self.update_server_url()?;

            loop {
                let state_file_password = prompt_user("Create password: ", false)?;
                let state_file_password_confirm = prompt_user("Confirm password: ", false)?;
                
                if state_file_password != state_file_password_confirm {
                    println!("Password does not match! Try again.\n");
                    continue;
                }
            
                let state_file_password_salt = libcold::crypto::generate_secure_random_bytes_whiten(consts::ARGON2ID_SALT_SIZE)
                    .map_err(|_| Error::FailedToGenerateSecureRandomBytes)?;


                let state_file_password_hash = libcold::crypto::hash_argon2id(state_file_password.as_bytes(), &state_file_password_salt)
                .map_err(|_| Error::Argon2IdHashingError)?;
     
                let state_file_password_hash = Zeroizing::new(state_file_password_hash[..32].to_vec());


                self.state_file_password_hash = Some(state_file_password_hash);
                self.state_file_password_hash_salt = Some(state_file_password_salt);

                self.state_file_path = Some(state_file_path);

                self.save_state_file()?;

                break;
            }
        }

        Ok(())
    }

    fn prompt_and_decrypt_state_file(&mut self, state_file_path: &str) -> Result<(), Error> {
        let mut state_file_password_salt = Zeroizing::new(vec![0u8; consts::ARGON2ID_SALT_SIZE]);

        let mut file = File::open(&state_file_path)
            .map_err(|_| Error::FailedToOpenFile)?;

        let file_len = file.metadata()
            .map_err(|_| Error::FailedToGetFileMetadata)?
            .len();

        // If size is less than argon2id salt size, authentication tag, and nonce, it must be a
        // corrupted file.
        if file_len < (consts::ARGON2ID_SALT_SIZE as u64 + 16 + consts::XCHACHA20POLY1305_NONCE_SIZE as u64) {
            return Err(Error::InvalidStateFile);
        }
        
        file.seek(std::io::SeekFrom::Start(file_len - consts::ARGON2ID_SALT_SIZE as u64))
            .map_err(|_| Error::FailedToSeekInFile)?;
        
        file.read_exact(&mut state_file_password_salt)
            .map_err(|_| Error::FailedToReadFile)?;


        let state_file_password = prompt_user("Enter password: ", false)?;

        
        // Ciphertext + authentication tag
        let ct_and_tag_len = file_len - consts::XCHACHA20POLY1305_NONCE_SIZE as u64 - consts::ARGON2ID_SALT_SIZE as u64;

        if ct_and_tag_len > usize::MAX as u64 {
            return Err(Error::StateFileTooLargeToReadIntoMemory);
        }

        let mut ct_and_tag = Zeroizing::new(vec![0u8; ct_and_tag_len as usize]);

        file.seek(std::io::SeekFrom::Start(0))
            .map_err(|_| Error::FailedToSeekInFile)?;

        file.read_exact(&mut ct_and_tag)
            .map_err(|_| Error::FailedToReadFile)?;

        // Ciphertext's nonce
        let mut nonce = Zeroizing::new(vec![0u8; consts::XCHACHA20POLY1305_NONCE_SIZE]);

        file.seek(std::io::SeekFrom::Start(ct_and_tag_len))
            .map_err(|_| Error::FailedToSeekInFile)?;

        file.read_exact(&mut nonce)
            .map_err(|_| Error::FailedToReadFile)?;


        let state_file_password_hash = libcold::crypto::hash_argon2id(state_file_password.as_bytes(), &state_file_password_salt)
        .map_err(|_| Error::Argon2IdHashingError)?;

        let state_file_password_hash = Zeroizing::new(state_file_password_hash[..32].to_vec());

        let plaintext = crypto::decrypt_xchacha20poly1305(&state_file_password_hash, &nonce, &ct_and_tag)?;

        self.parse_decrypted_state_content(plaintext.as_slice())?;


        self.state_file_password_hash = Some(state_file_password_hash);
        self.state_file_password_hash_salt = Some(state_file_password_salt);

        Ok(())
    }


    fn parse_decrypted_state_content(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        let plaintext_string = std::str::from_utf8(plaintext)
            .map_err(|_| Error::FailedToConvertBytesToUtf8)?;

        for line in plaintext_string.lines() {
            // skip empty lines
            if line.trim().is_empty() {
                continue;
            }
            
            let (tag, b64) = line.split_once(':')
                .ok_or(Error::FailedToSplitLineOnce)?;
    
            let decoded = Zeroizing::new(BASE64_STANDARD.decode(b64)
                    .map_err(|_| Error::FailedToDecodeBase64)?);


            if tag == "server_url" {
                let utf8_string = Zeroizing::new(String::from_utf8(decoded.to_vec())
                    .map_err(|_| Error::FailedToConvertBytesToUtf8)?);

                self.server_url = Some(utf8_string);

            } else if tag == "auth_secret_key" {
                self.auth_secret_key = Some(decoded);

            } else if tag == "auth_public_key" {
                self.auth_public_key = Some(decoded);

            } else if tag == "user_id" {
                let s = Zeroizing::new(String::from_utf8(decoded.to_vec())
                        .map_err(|_| Error::FailedToConvertBytesToUtf8)?);

                self.user_id = Some(s);

            } else if tag == "contact" {
                let contact = libcold::Contact::import_plain(decoded.as_slice())
                    .map_err(|_| Error::FailedToImportContact)?;

                match &mut self.contact_list {
                    Some(vec) => vec.push(contact),
                    None => self.contact_list = Some(vec![contact]),
                }


            } else {
                return Err(Error::StateFileCorrupted);
            }
            
        }

        Ok(())
    }

    fn save_state_file(&mut self) -> Result<(), Error> {
        let state_file_path = self.state_file_path
            .as_ref()
            .unwrap();

        let state_file_password_hash = self.state_file_password_hash
            .as_ref()
            .unwrap();

        let state_file_password_hash_salt = self.state_file_password_hash_salt
            .as_ref()
            .unwrap();

        if self.auth_secret_key.as_ref().is_none() || self.auth_public_key.as_ref().is_none() {
            let (new_auth_pk, new_auth_sk) = libcold::crypto::generate_ml_dsa_87_keypair()
                                                .map_err(|_| Error::FailedToGenerateAuthKeypair)?;

            self.auth_public_key = Some(new_auth_pk);
            self.auth_secret_key = Some(new_auth_sk);
        }





        let tag_separator = b":";

        let server_url_tag = b"server_url";
        let auth_pk_tag = b"auth_public_key";
        let auth_sk_tag = b"auth_secret_key";

        let server_url_base64 = BASE64_STANDARD.encode(self.server_url
            .as_ref()
            .unwrap()
            .as_bytes());


        let auth_pk_base64 = BASE64_STANDARD.encode(self.auth_public_key.as_ref().unwrap());
        let auth_sk_base64 = BASE64_STANDARD.encode(self.auth_secret_key.as_ref().unwrap());


        let mut file = File::create(state_file_path)
            .map_err(|_| Error::FailedToCreateFile)?;
        
        let mut payload_plaintext = Zeroizing::new(Vec::with_capacity(
                server_url_tag.len() + 
                tag_separator.len() + 
                server_url_base64.as_bytes().len() + 
                1 +
                auth_pk_tag.len() +
                tag_separator.len() + 
                auth_pk_base64.as_bytes().len() 
            )
        );

        payload_plaintext.extend_from_slice(server_url_tag);
        payload_plaintext.extend_from_slice(tag_separator);
        payload_plaintext.extend_from_slice(server_url_base64.as_bytes());

        payload_plaintext.push(b'\n');
        payload_plaintext.extend_from_slice(auth_pk_tag);
        payload_plaintext.extend_from_slice(tag_separator);
        payload_plaintext.extend_from_slice(auth_pk_base64.as_bytes());

        payload_plaintext.push(b'\n');
        payload_plaintext.extend_from_slice(auth_sk_tag);
        payload_plaintext.extend_from_slice(tag_separator);
        payload_plaintext.extend_from_slice(auth_sk_base64.as_bytes());

        
        if self.user_id.as_ref().is_some() {
            let user_id_tag = b"user_id";
            let user_id_base64 = BASE64_STANDARD.encode(self.user_id.as_ref().unwrap().as_bytes());

            payload_plaintext.push(b'\n');
            payload_plaintext.extend_from_slice(user_id_tag);
            payload_plaintext.extend_from_slice(tag_separator);
            payload_plaintext.extend_from_slice(user_id_base64.as_bytes());

        }


        if self.contact_list.as_ref().is_some() {
            let contact_tag = b"contact";

            for contact in self.contact_list.as_ref().unwrap() {
                let contact_exported = contact.export_plain()
                    .map_err(|_| Error::FailedToExportContact)?;

                let contact_exported_base64 = BASE64_STANDARD.encode(contact_exported);

                payload_plaintext.push(b'\n');
                payload_plaintext.extend_from_slice(contact_tag);
                payload_plaintext.extend_from_slice(tag_separator);
                payload_plaintext.extend_from_slice(contact_exported_base64.as_bytes());

            }
        }


        let (encrypted_payload, encrypted_payload_nonce) = crypto::encrypt_xchacha20poly1305(state_file_password_hash, payload_plaintext.as_slice(), None, 0)?;

        let mut final_payload_plaintext = Zeroizing::new(Vec::with_capacity(
                encrypted_payload.as_slice().len() +
                consts::XCHACHA20POLY1305_NONCE_SIZE + 
                consts::ARGON2ID_SALT_SIZE
            )
        );
        final_payload_plaintext.extend_from_slice(encrypted_payload.as_slice());
        final_payload_plaintext.extend_from_slice(encrypted_payload_nonce.as_slice());
        final_payload_plaintext.extend_from_slice(state_file_password_hash_salt.as_slice());


        file.write_all(final_payload_plaintext.as_slice())
            .map_err(|_| Error::FailedToWriteToFile)?;

        Ok(())

    }

    fn update_server_url(&mut self) -> Result<(), Error> {
        let mut server_url = Zeroizing::new(String::new());

        loop {
            server_url = prompt_user("Enter server URL: ", true)?;

            let https_server_url = match clean_server_url(server_url.to_string(), true) {
                Ok(u) => Zeroizing::new(u),
                Err(e) => {
                    println!("ERROR: {}\n", e);
                    continue
                }
            };

            let http_server_url = match clean_server_url(server_url.to_string(), false) {
                Ok(u) => Zeroizing::new(u),
                Err(e) => {
                    println!("ERROR: {}\n", e);
                    continue
                }
            };



            if requests::get_request(https_server_url.to_string(), None, None).is_err() {
                if requests::get_request(http_server_url.to_string(), None, None).is_err() {
                    println!("Failed to fetch server URL. Check the URl and your proxy settings.");
                    continue
                } else {
                    server_url = http_server_url;
                }
            } else {
                server_url = https_server_url;
            }
            

            break
        }


        self.server_url = Some(server_url);

        Ok(())
    }

    fn authenticate(&mut self) -> Result<(), Error> {
        let server_url = self.server_url.as_ref().expect("Server_URL empty");
        let user_id = self.user_id.as_ref();

        if self.auth_secret_key.as_ref().is_none() || self.auth_public_key.as_ref().is_none() {
            let (new_auth_pk, new_auth_sk) = libcold::crypto::generate_ml_dsa_87_keypair()
                                                .map_err(|_| Error::FailedToGenerateAuthKeypair)?;


            self.auth_public_key = Some(new_auth_pk);
            self.auth_secret_key = Some(new_auth_sk);
        }


        let auth_pk = self.auth_public_key.as_ref().unwrap();
        let auth_sk = self.auth_secret_key.as_ref().unwrap();


        let mut result = Zeroizing::new(Vec::new());

        if user_id.is_some() {
            let metadata = &[
                ("user_id".to_string(), user_id.unwrap().to_string()),
            ];

            result = requests::post_request(format!("{}authenticate/init", server_url.to_string()), None, Some(metadata), None)?;

        } else {
            let pk_encoded = BASE64_STANDARD.encode(auth_pk);

            let metadata = &[
                ("public_key".to_string(), pk_encoded.to_string()),
            ];

            result = requests::post_request(format!("{}authenticate/init", server_url.to_string()), None, Some(metadata), None)?;
       
        }


        let json_string = String::from_utf8(result.to_vec())
            .map_err(|_| {
                println!("Server did not respond with a valid JSON UTF-8 string, are you sure this is a Coldwire messenger server?");
                Error::InvalidServerResponse
            })?;


        let challenge_base64_encoded = json::extract_json_value(&json_string, "challenge");
        if challenge_base64_encoded.is_none() {
            println!("Server did not respond with a valid JSON UTF-8 string, are you sure this is a Coldwire messenger server?");
            return Err(Error::MalformedServerResponse);
        }

        let challenge_decoded = BASE64_STANDARD.decode(challenge_base64_encoded.as_ref().unwrap())
            .map_err(|_| {
                println!("Server did not give us a valid base64 encoded challenge.");
                Error::FailedToDecodeBase64
            })?;


        let sig = libcold::crypto::generate_ml_dsa_87_signature(auth_sk, challenge_decoded.as_slice())
            .map_err(|_| Error::FailedToSignChallenge)?;

        let sig_base64_encoded = BASE64_STANDARD.encode(sig);

        let metadata = &[
                ("signature".to_string(), sig_base64_encoded),
                ("challenge".to_string(), challenge_base64_encoded.as_ref().unwrap().to_string()),
            ];


        
        result = requests::post_request(format!("{}authenticate/verify", server_url.to_string()), None, Some(metadata), None)?;

        
        let json_string = String::from_utf8(result.to_vec())
            .map_err(|_| {
                println!("Server did not respond with a valid JSON UTF-8 string, are you sure this is a Coldwire messenger server?");
                Error::InvalidServerResponse
            })?;


        let user_id = json::extract_json_value(&json_string, "user_id");
        let token = json::extract_json_value(&json_string, "token");


        if user_id.is_none() || token.is_none() {
            println!("Server did not respond with a `user_id` nor a `token`, either your account is missing or the server is not a coldwire messenger server.");
            return Err(Error::MalformedServerResponse);
        }

        self.user_id = Some(Zeroizing::new(user_id.unwrap()));
        self.auth_token = Some(Zeroizing::new(token.unwrap()));

        self.save_state_file()?;

        Ok(())        
    }

    fn delete_contact(&mut self) -> Result<(), Error> {
        let general_id = prompt_user("Choose a contact: ", true)?;

            
        
        if let Some(contacts) = self.contact_list.as_mut() {
        
            let mut to_remove: Option<usize> = None;

            for (i, contact) in contacts.iter_mut().enumerate() {
                let ad_bytes = contact.additional_data.as_ref().expect("Contact does not have additional assosicated data. Impossible condition");

                let ad_str = std::str::from_utf8(ad_bytes)
                    .expect("additional_data is not valid UTF-8");

                
                let id = json::extract_json_value(ad_str, "id");
                let nickname = json::extract_json_value(ad_str, "nickname");

                if !(
                    nickname.as_ref().map(|n| *n == *general_id).unwrap_or(false)
                    || id.as_ref().map(|z| &**z == *general_id).unwrap_or(false)
                ) {
                    continue;
                }

                    
                to_remove = Some(i);

            }

            if let Some(i) = to_remove {
                contacts.remove(i);
                println!("[*] Successfully deleted contact\n");
                self.save_state_file()?;
                return Ok(());
            }
        }
        

        println!("[!] Contact not found!");
        Ok(())
    }

    fn add_contact(&mut self) -> Result<(), Error> {
        let mut contact = libcold::Contact::new().expect("Could not create new contact instance");
        let (mut id, mut question, mut answer);

        loop {
            id = prompt_user("Enter contact identifier: ", true)?;

            if !utils::validate_identifier(&id) {
                println!("\n[*] Invalid identifier! Ensure the identifier is correct format (i.e. 1234567890123456, 1234567890123456@example.com, etc)");
                continue
            }

            break;
        }

        if let Some(contacts) = self.contact_list.as_mut() {
            for (i, contact) in contacts.iter_mut().enumerate() {
                let ad_bytes = contact.additional_data.as_ref().expect("Contact does not have additional assosicated data. Impossible condition");

                let ad_str = std::str::from_utf8(ad_bytes)
                    .expect("additional_data is not valid UTF-8");

                
                let cid = json::extract_json_value(ad_str, "id").unwrap();

                if cid == id.as_str() {
                    println!("You already have the contact saved!");
                    return Ok(());
                }
            }
        }



        loop {
            question = prompt_user("Enter a question: ", true)?;

            answer = prompt_user("Enter an answer: ", true)?;

            break
        }

        let output = contact.init_smp(question, answer)
            .map_err(|_| Error::FailedToInitializeSmp)?;

        let output = match output {
            libcold::ContactOutput::Wire(w) => w,
            _ => panic!("Impossible condition.")
        };


        let server_url = self.server_url.as_ref().unwrap();
        let auth_token = self.auth_token.as_ref().unwrap();


        let metadata = &[
            ("recipient".to_string(), id.to_string()),
        ];

        let headers = &[
            ("authorization".to_string(), format!("Bearer {}", auth_token.to_string())),
        ];


        let blob = Zeroizing::new(output[0].to_vec());


        let response = requests::post_request(format!("{}data/send", server_url.to_string()), Some(headers), Some(metadata), Some(blob))?;

        let json_string = String::from_utf8(response.to_vec())
            .map_err(|_| Error::FailedToConvertBytesToUtf8)?;


        let status = json::extract_json_value(&json_string, "status");
        if status.is_none() {
            println!("Server did not respond with a valid JSON UTF-8 string.");
            return Err(Error::InvalidJsonInServerResponse);
        } else if status.unwrap() != "success" {
            println!("Server responded with a non-success status.");
            return Err(Error::NonSuccessServerStatus);
        }



        let ad_string = format!("{{\"id\":\"{}\",\"nickname\":\"\"}}", id.to_string());
        let ad_bytes = ad_string.into_bytes(); 
        contact.additional_data = Some(Zeroizing::new(ad_bytes));

        match &mut self.contact_list {
                Some(vec) => vec.push(contact),
                None => self.contact_list = Some(vec![contact]),
            }

        self.save_state_file()?;

        Ok(())
    }


    fn print_contact_list(&mut self) {
        if let Some(contacts) = self.contact_list.as_ref() {
            for (i, contact) in contacts.iter().enumerate() {
                let ad_bytes = contact.additional_data.as_ref().expect("Contact does not have additional assosicated data. Impossible condition");

                let contact_state = if contact.state  == libcold::ContactState::Verified {
                    "Verified"
                } else {
                    "Pending verification"
                };

                let ad_str = std::str::from_utf8(ad_bytes)
                    .expect("additional_data is not valid UTF-8");

                
                let id = json::extract_json_value(ad_str, "id");
                let nickname = json::extract_json_value(ad_str, "nickname");

                if nickname.is_some() && !nickname.as_ref().unwrap().is_empty() {
                    println!("[{}]: {} ({})", i, nickname.unwrap(), contact_state)
                } else if id.is_some() {
                    println!("[{}]: {} ({})", i, id.unwrap(), contact_state)
                } else {
                    println!("{}", ad_str);
                    panic!("Congraulations, you have discovered a bug");
                }
            }
        } else {
            println!("[*] You currently have no contacts in your list.");
        }
    }
    
    fn send_message(&mut self) -> Result<(), Error> {
        let server_url = self.server_url.as_ref().unwrap().clone();
        let auth_token = self.auth_token.as_ref().unwrap();

        let headers = &[
            ("authorization".to_string(), format!("Bearer {}", auth_token.to_string())),
        ];



        let general_id = prompt_user("Choose a contact: ", true)?;

        if let Some(contacts) = self.contact_list.as_mut() {
            for (i, contact) in contacts.iter_mut().enumerate() {
                let ad_bytes = contact.additional_data.as_ref().expect("Contact does not have additional assosicated data. Impossible condition");

                let ad_str = std::str::from_utf8(ad_bytes)
                    .expect("additional_data is not valid UTF-8");

                
                let id = json::extract_json_value(ad_str, "id");
                let nickname = json::extract_json_value(ad_str, "nickname");

                if !(
                    nickname.as_ref().map(|n| *n == *general_id).unwrap_or(false)
                    || id.as_ref().map(|z| &**z == *general_id).unwrap_or(false)
                ) {
                    continue;
                }

                if contact.state != libcold::ContactState::Verified {
                    println!("[!] Contact is not verified!");
                    println!("[!] Please wait until they're verified and try again.");
                    return Ok(());
                }

        
                let message = prompt_user("Enter your message: ", true)?;

                if message.is_empty() {
                    println!("[!] Message cannot be empty");
                    return Ok(());
                }


                let output = contact.send_message(&message)
                    .map_err(|_| {
                        Error::FailedToPrepareMessage
                    })?;


                if let libcold::ContactOutput::Wire(output) = output {
                    let metadata = &[
                        ("recipient".to_string(), id.unwrap().to_string()),
                    ];


                    for blob in output {
                        let blob = Zeroizing::new(blob.to_vec());

                        let response = requests::post_request(format!("{}data/send", server_url.to_string()), Some(headers), Some(metadata), Some(blob))?;

                        let json_string = String::from_utf8(response.to_vec())
                            .map_err(|_| Error::FailedToConvertBytesToUtf8)?;


                        let status = json::extract_json_value(&json_string, "status");
                        if status.is_none() {
                            println!("Server did not respond with a valid JSON UTF-8 string.");
                            return Err(Error::InvalidJsonInServerResponse);
                        } else if status.unwrap() != "success" {
                            println!("Server responded with a non-success status.");
                            return Err(Error::NonSuccessServerStatus);
                        }
                    }
                }   


                contact.i_confirm_message_has_been_sent()
                    .map_err(|_| {
                        Error::FailedToUnlockMessage
                    })?;

                self.save_state_file()?;

                return Ok(());
        
            }
        }

        println!("\n[!] Did not find the specificed contact.");

        Ok(())

    }
    
    fn check_for_new_data(&mut self, old_acks: Vec<String>) -> Result<Vec<String>, Error> {
        let server_url = self.server_url.as_ref().unwrap().clone();
        let auth_token = self.auth_token.as_ref().unwrap();


        let headers = &[
            ("authorization".to_string(), format!("Bearer {}", auth_token.to_string())),
        ];


        let mut acks: Vec<String> = Vec::new();

        let metadata_list: Option<(String, Vec<String>)> = Some(
                ("acks".to_string(), old_acks.clone()),
            );


        let mut response;
        
        if old_acks.is_empty() {
            response = requests::get_request(format!("{}data/longpoll", server_url.to_string()), Some(headers), None);
        } else {
            response = requests::get_request(format!("{}data/longpoll", server_url.to_string()), Some(headers), metadata_list.as_ref());
        }

        if response.is_err() {
            println!("Data longpoll request timed out, you don't have any new unreceived data.");
            return Ok(acks);
        }

        if !old_acks.is_empty() {
            self.save_state_file()?;
        }

        
        let new_data = utils::decode_blob_stream(&response.unwrap())?;
        let new_data = utils::parse_blobs(new_data)?;




        for data in &new_data {
            let mut cl = self.contact_list.as_mut();

            let mut to_remove: Option<usize> = None;

            // If we do not have the contact instance, we create it.
            if cl.is_none() {
                let mut contact = libcold::Contact::new().expect("Could not create new contact instance");
                
                let ad_string = format!("{{\"id\":\"{}\",\"nickname\":\"\"}}", data.sender.to_string());
                let ad_bytes = ad_string.into_bytes(); 
                contact.additional_data = Some(Zeroizing::new(ad_bytes));


                match &mut self.contact_list {
                    Some(vec) => vec.push(contact),
                    None => self.contact_list = Some(vec![contact]),
                    
                }

                cl = self.contact_list.as_mut();
            }


            let cl = cl.unwrap();

            // println!("{:?} Sent by {:?}, ack id is: {:?}", data.blob, data.sender, data.ack_id);
            for (i, contact) in cl.iter_mut().enumerate() {
                let ad_bytes = contact.additional_data.as_ref().expect("Contact does not have additional assosicated data. Impossible condition");    
                let ack_id = general_purpose::URL_SAFE_NO_PAD.encode(data.ack_id);

                let ad_str = std::str::from_utf8(ad_bytes)
                    .expect("additional_data is not valid UTF-8");

                    
                let id = json::extract_json_value(ad_str, "id").unwrap();
                let nickname = json::extract_json_value(ad_str, "nickname").unwrap();
                if id != data.sender {
                    continue
                }


                // TODO: Dont panic.
                let output = contact.process(data.blob.as_slice())
                    .map_err(|e| {
                        println!("AHHHHHHHHHHHHHHH {:?} ", e);
                        Error::FailedToProcessContactBlob
                    })?;


                if contact.state  == libcold::ContactState::Uninitialized {
                    if nickname.is_empty() {
                        println!("Contact ({}) have failed SMP verification!", id);
                    } else {
                        println!("Contact ({}) nicknamed ({}) have failed SMP verification!", id, nickname);
                    }
                    
                    to_remove = Some(i);
                }

                let metadata = &[
                        ("recipient".to_string(), id.to_string()),
                    ];
                
                if let libcold::ContactOutput::None = output {
                    acks.push(ack_id.clone());
                    continue;
                
                } else if let libcold::ContactOutput::Wire(output) = output {
                    for blob in output {
                        let blob = Zeroizing::new(blob.to_vec());

                        let response = requests::post_request(format!("{}data/send", server_url.to_string()), Some(headers), Some(metadata), Some(blob))?;

                        let json_string = String::from_utf8(response.to_vec())
                            .map_err(|_| Error::FailedToConvertBytesToUtf8)?;


                        let status = json::extract_json_value(&json_string, "status");
                        if status.is_none() {
                            println!("Server did not respond with a valid JSON UTF-8 string.");
                            return Err(Error::InvalidJsonInServerResponse);
                        } else if status.unwrap() != "success" {
                            println!("Server responded with a non-success status.");
                            return Err(Error::NonSuccessServerStatus);
                        }
                    }

                } else if let libcold::ContactOutput::Prompt(output) = output {
                    let question = output.question;

                    println!("Contact ({}) wants to verify you, Please answer the question below.", id);

                    println!("Question: {}", question);

                
                    let answer_str = prompt_user("Answer: ", false)?;

                    let answer = libcold::UserAnswer::new(answer_str).expect("Failed to create answer");

                    let output = match contact.provide_smp_answer(answer) {
                        Ok(output) => output,
                        Err(e) => {
                            println!("We errored while processing SMP answer: {:?}", e);
                            continue;
                        }
                    };

                    let blobs = if let libcold::ContactOutput::Wire(blobs) = output {
                        blobs
                    } else {
                        panic!("Expected Wire output, got something else!");
                    };


                    for blob in blobs {
                        let blob = Zeroizing::new(blob.to_vec());

                        let response = requests::post_request(format!("{}data/send", server_url.to_string()), Some(headers), Some(metadata), Some(blob))?;

                        let json_string = String::from_utf8(response.to_vec())
                            .map_err(|_| Error::FailedToConvertBytesToUtf8)?;


                        let status = json::extract_json_value(&json_string, "status");
                        if status.is_none() {
                            println!("Server did not respond with a valid JSON UTF-8 string.");
                            return Err(Error::InvalidJsonInServerResponse);
                        } else if status.unwrap() != "success" {
                            println!("Server responded with a non-success status.");
                            return Err(Error::NonSuccessServerStatus);
                        }

                    }

                } else if let libcold::ContactOutput::Message(output) = output {
                    let message = sanitize_message(output.message);
                    println!("[*] Contact ({}) sent you a new message:\n{}\n\n", id, message);

                } else {
                    println!("WHAT THE ACTUAL FUCK?????????? {:?}", output);
                }   

                acks.push(ack_id.clone());
                continue;
                



            }
            if let Some(i) = to_remove {
                cl.remove(i);
            }
        }


    
        Ok(acks)
    }
}


/// Sanitizes a string for terminal-safe printing.
/// Removes ANSI escape sequences and replaces non-printable characters with '?'.
pub fn sanitize_message(input: Zeroizing<String>) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Potential start of ANSI sequence
            if let Some('[') = chars.peek() {
                chars.next(); // consume '['
                // Consume until a letter in the range @A-Za-z
                while let Some(&next) = chars.peek() {
                    if ('@'..='~').contains(&next) {
                        chars.next(); // consume the final letter
                        break;
                    } else {
                        chars.next(); // consume intermediate char
                    }
                }
                // ANSI sequence skipped
                continue;
            } else {
                // Lone ESC, replace with '?'
                result.push('?');
            }
        } else if c.is_control() && !matches!(c, '\n' | '\r' | '\t') {
            // Replace other control chars with '?'
            result.push('?');
        } else {
            // Safe printable char
            result.push(c);
        }
    }

    result
}


fn prompt_user(msg: &str, trim: bool) -> Result<Zeroizing<String>, Error> {
    print!("{msg}");
    std::io::stdout().flush()
        .map_err(|_| Error::FailedToFlush)?;

    let mut input = Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut input)
        .map_err(|_| Error::FailedToReadLine)?;

    if trim {
        return Ok(Zeroizing::new(input.trim().to_string()));
    }

    Ok(Zeroizing::new(input.to_string()))
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

        user_id: None,

        contact_list: None,

        auth_token: None,

        auth_secret_key: None,
        auth_public_key: None,

        state_file_path: None,
        state_file_password_hash: None,
        state_file_password_hash_salt: None,
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
fn clean_server_url(mut url: String, enforce_https_prefix: bool) -> Result<String, String> {
    // overall length cap
    if url.len() > 512 {
        return Err(String::from("URL too long (max 512 chars)"));
    }

    // ensure scheme (check lowercase for detection but keep original for rest)
    let lower = url.to_ascii_lowercase();
    if enforce_https_prefix && !lower.starts_with("http://") && !lower.starts_with("https://") {
        url = format!("https://{}", url);

    } else if !enforce_https_prefix && !lower.starts_with("http://") && !lower.starts_with("https://") {
        url = format!("http://{}", url);
    }

    if !url.ends_with("/") {
        url = format!("{}/", url);
    }

    // split scheme://rest
    let parts: Vec<&str> = url.splitn(2, "://").collect();
    if parts.len() != 2 {
        return Err(String::from("missing scheme"));
    }
    let scheme = parts[0];
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme '{}'", scheme));
    }

    let rest = parts[1];

    // split netloc and the rest-of-path (we keep EVERYTHING after the first '/')
    let mut rest_iter = rest.splitn(2, '/');
    let netloc = rest_iter.next().unwrap_or("");
    let path = rest_iter.next().map(|s| format!("/{}", s)).unwrap_or_default();

    // Split host[:port]
    let (host, port_opt) = if let Some(i) = netloc.rfind(':') {
        (&netloc[..i], Some(&netloc[i + 1..]))
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

        return Ok(format!("{}://{}:{}{}", scheme, host, port, path));
    }

    Ok(format!("{}://{}{}", scheme, host, path))
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


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = match parse_args() {
        Ok(cfg) => cfg,
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

    if let Err(e) = cfg.confirm_proxy_info() {
        eprintln!("ERROR: {:?}", e); 
        std::process::exit(1);
    }


    
    if let Err(e) = cfg.prompt_state_file() {
        eprintln!("ERROR: {:?}", e); 
        std::process::exit(1);
    }


    if let Err(e) = cfg.authenticate() {
        eprintln!("ERROR: {:?}", e); 
        std::process::exit(1);
    }


    
    let mut acks: Vec<String> = Vec::new();

    let our_user_id = cfg.user_id.as_ref().expect("user_id not initialized, this is an impossible condition. Please open an issue on Github.");

    println!("\n[*] You are authenticated as {}", our_user_id.to_string());

   
    loop {
        loop {
            if !acks.is_empty() {
                println!("\n[*] We are checking for new data, please be patient.");
                acks = cfg.check_for_new_data(acks)
                    .map_err(|e| {
                    eprintln!("ERROR: {:?}", e); 
                    std::process::exit(1);
                })?;
                continue
            }
            break;
        }

        println!("\n[*] Choose an option:\n");
        println!("0. List all your contacts");
        println!("1. Check for new add requests and messages");
        println!("2. Send a message to a contact");
        println!("3. Add a new contact");
        println!("4. Delete a contact\n");

        let result = prompt_user("> ", true)
            .map_err(|e| {
                eprintln!("ERROR: {:?}", e); 
                std::process::exit(1);
            })?;

        if *result == "0" {
            println!("\n[*] Your current contacts list:");
            cfg.print_contact_list();

        } else if *result == "1" {
            println!("\n[*] We are checking for new data, please be patient.");
            acks = cfg.check_for_new_data(acks)
                .map_err(|e| {
                eprintln!("ERROR: {:?}", e); 
                std::process::exit(1);
            })?;



            
        } else if *result == "2" {
            println!("\n[*] Choose a contact from below to send the message to: ");
            cfg.print_contact_list();

            cfg.send_message()
                .map_err(|e| {
                    eprintln!("ERROR: {:?}", e); 
                    std::process::exit(1);
                })?;

        } else if *result == "3" {
            cfg.add_contact()
                .map_err(|e| {
                eprintln!("ERROR: {:?}", e); 
                std::process::exit(1);
            })?;
        }

        else if *result == "4" {
            println!("\n[*] Choose a contact from below to delete: ");
            cfg.print_contact_list();
            cfg.delete_contact()
                .map_err(|e| {
                eprintln!("ERROR: {:?}", e); 
                std::process::exit(1);
            })?;
        }
    }

    Ok(())
}
