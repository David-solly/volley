use actix_files::{Files, NamedFile};
use actix_web::{
    get, http::header, web::Path, web::ServiceConfig, HttpRequest, HttpResponse, Responder,
};
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use serde::{Deserialize, Serialize};
use shuttle_actix_web::ShuttleActixWeb;
use url::Url;

#[derive(Deserialize)]
struct RedirectRequest {
    public_key: Option<String>,
    tail: String,
}

#[derive(Serialize)]
struct ErrorResponseBody {
    error: String,
}

#[get("/")]
async fn index() -> impl Responder {
    NamedFile::open_async("./static/index.html")
        .await
        .map_err(actix_web::error::ErrorInternalServerError)
}

#[get("/secure/{tail:.*}")]
async fn forward_to_secure(req: HttpRequest, path: Path<RedirectRequest>) -> impl Responder {
    let pos_regex = regex::Regex::new(r"http").unwrap();
    let pos = match pos_regex.find(req.uri().to_string().as_str()) {
        Some(pos) => pos.start(),
        None => {
            return HttpResponse::BadRequest().finish();
        }
    };

    let url = match Url::parse(req.uri().to_string().split_at(pos).1) {
        Ok(url) => url,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponseBody {
                error: String::from("Only http and https urls are supported"),
            });
        }
    };

    if path.tail.is_empty() || (url.scheme() != "https" && url.scheme() != "http") {
        return HttpResponse::BadRequest().finish();
    }

    // return a 302 response with the new url as the location header
    // if https, skip encryption
    match url.scheme() {
        "https" => HttpResponse::Found()
            .insert_header((header::LOCATION, url.as_str()))
            .finish(),

        "http" => HttpResponse::BadRequest().json(ErrorResponseBody {
            error: String::from("Only https redirect urls are supported for this route"),
        }),
        _ => HttpResponse::BadRequest().finish(),
    }
}

#[get("/{public_key}/{tail:.*}")]
async fn forward_to(req: HttpRequest, path: Path<RedirectRequest>) -> impl Responder {
    //extract the tail:* of the url and the request to that tail
    //e.g. http://localhost:8080/auth/https://www.google.com
    //will forward the request to https://www.google.com

    // let url = path.tail.clone(); doesn't preserve query strings

    let pos_regex = regex::Regex::new(r"http").unwrap();
    let pos = match pos_regex.find(req.uri().to_string().as_str()) {
        Some(pos) => pos.start(),
        None => {
            return HttpResponse::BadRequest().finish();
        }
    };

    let mut url = match Url::parse(req.uri().to_string().split_at(pos).1) {
        Ok(url) => url,
        Err(_e) => {
            return HttpResponse::BadRequest().json(ErrorResponseBody {
                error: String::from("Only http and https urls are supported"),
            });
        }
    };

    if path.tail.is_empty()
        || (url.scheme() != "https" && url.scheme() != "http")
        || path.public_key.is_none()
    {
        return HttpResponse::BadRequest().finish();
    }

    // return a 302 response with the new url as the location header
    // if https, skip encryption
    match url.scheme() {
        "https" => HttpResponse::Found()
            .insert_header((header::LOCATION, url.as_str()))
            .finish(),

        "http" => {
            let code = extract_code_from_url(url.clone().to_string());

            let decoded_pem = match general_purpose::URL_SAFE_NO_PAD
                .decode(path.public_key.clone().unwrap().as_bytes())
            {
                Ok(pem) => pem,
                Err(_e) => {
                    return HttpResponse::BadRequest().json(ErrorResponseBody {
                        error: String::from("Invalid public key format"),
                    });
                }
            };

            let pem = match String::from_utf8(decoded_pem) {
                Ok(pem) => pem.replace(
                    &[
                        '<', '>', '(', ')', ',', '\"', '.', ';', ':', '\'', '!', '@', '\\', '{',
                        '}', '[', ']', '&', '^', '*', '|', '~', '`', '?', '%',
                    ][..],
                    "",
                ),
                Err(_e) => {
                    return HttpResponse::BadRequest().json(ErrorResponseBody {
                        error: String::from("Invalid public key"),
                    });
                }
            };

            let public_key = match RsaPublicKey::from_public_key_pem(pem.as_str()) {
                Ok(key) => key,
                Err(_e) => {
                    return HttpResponse::BadRequest().finish();
                }
            };

            let encrypted_payload =
                encrypt_secret(public_key, format!("{}{}", url.clone().to_string(), code)).await;

            let new_query = format!("volley={}", encrypted_payload);
            // set the new query part of the url
            url.set_query(Some(&new_query));

            HttpResponse::Found()
                .insert_header((header::LOCATION, url.as_str()))
                .finish()
        }
        _ => HttpResponse::BadRequest().finish(),
    }
}

async fn encrypt_secret(public_key: RsaPublicKey, data: String) -> String {
    let encrypted_data = public_key
        .encrypt(
            &mut rand::thread_rng(),
            Pkcs1v15Encrypt,
            &data.as_bytes()[..],
        )
        .expect("failed to encrypt");
    let encoded_url = general_purpose::URL_SAFE_NO_PAD.encode(encrypted_data);
    encoded_url
}

fn extract_code_from_url(url: String) -> String {
    let re = Regex::new(r"\?[^?].*$").unwrap();
    let caps = re.captures(url.as_str()).unwrap();
    match caps.get(0).unwrap().as_str() {
        "" => String::from(""),
        _ => String::from(caps.get(0).unwrap().as_str()),
    }
}

#[shuttle_runtime::main]
async fn main() -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    let config = move |cfg: &mut ServiceConfig| {
        cfg.service(Files::new("/dist", "./static/dist"))
            .service(index)
            .service(forward_to_secure)
            .service(forward_to);
    };

    Ok(config.into())
}
