use std::{collections::HashMap, hash::Hash, sync::Arc};

use actix_files::{Files, NamedFile};
use actix_web::{
    get,
    http::header,
    put,
    web::ServiceConfig,
    web::{self, Path},
    HttpRequest, HttpResponse, Responder,
};
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha256::{digest, try_digest};
use shuttle_actix_web::ShuttleActixWeb;
use tokio::sync::Mutex;
use url::Url;

#[derive(Deserialize)]
struct RedirectRequest {
    public_key: Option<String>,
    tail: String,
}
#[derive(Debug, Deserialize)]
struct ImminentRequest {
    code: Option<String>,
    state: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponseBody {
    error: String,
}

#[derive(Serialize)]
struct ResponseBody {
    message: String,
}

#[derive(Serialize, Clone, Debug, Deserialize)]
struct ImminentRecord {
    url: String,
    base64_public_key: String,
}
#[derive(Debug, Clone)]
struct State {
    redirect_map: Arc<Mutex<HashMap<String, ImminentRecord>>>,
}

#[get("/")]
async fn index() -> impl Responder {
    NamedFile::open_async("./static/index.html")
        .await
        .map_err(actix_web::error::ErrorInternalServerError)
}

#[put("/imminent/{public_key}/{tail:.*}")]
async fn index_register_secure(
    path: Path<RedirectRequest>,
    state: web::Data<State>,
) -> impl Responder {
    let public_key = match path.public_key.clone() {
        Some(key) => key,
        None => {
            return HttpResponse::BadRequest().json(ErrorResponseBody {
                error: String::from("No public key found"),
            });
        }
    };
    let hash_of_public_key = match sha256::try_digest(public_key) {
        Ok(hash) => hash,
        Err(_e) => {
            return HttpResponse::BadRequest().json(ErrorResponseBody {
                error: String::from("Invalid public key"),
            });
        }
    };

    let mut redirect_map = state.redirect_map.lock().await;
    redirect_map.insert(
        hash_of_public_key,
        ImminentRecord {
            url: path.tail.clone(),
            base64_public_key: path.public_key.clone().unwrap(),
        },
    );
    HttpResponse::Ok().finish()
}
#[get("/imminent/oauth")]
async fn process_immenent_request(
    req: HttpRequest,
    query: web::Query<ImminentRequest>,
    state: web::Data<State>,
) -> impl Responder {
    //get the query string, state
    match req.uri().query() {
        Some(_) => {}
        None => {
            return HttpResponse::UnprocessableEntity().json(ErrorResponseBody {
                error: String::from("No query string found"),
            });
        }
    };
    println!("query: {:?}", query);
    let hash = match query.state.clone() {
        Some(hash) => hash,
        None => {
            return HttpResponse::UnprocessableEntity().json(ErrorResponseBody {
                error: String::from("No code found"),
            });
        }
    };
    let mut redirect_map = state.redirect_map.lock().await;
    let redirect_url_from_map = match redirect_map.get(&hash) {
        Some(url) => url,
        None => {
            return HttpResponse::UnprocessableEntity().json(ErrorResponseBody {
                error: String::from("No redirect url found"),
            });
        }
    };
    HttpResponse::Ok().json(ResponseBody {
        message: String::from(query_string),
    })
}

#[get("/https/{tail:.*}")]
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
            let code = if url.clone().to_string().contains("?") {
                extract_code_from_url(url.clone().to_string())
            } else {
                String::from("")
            };

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
    let state = State {
        redirect_map: Arc::new(Mutex::new(HashMap::new())),
    };
    let config = move |cfg: &mut ServiceConfig| {
        cfg.app_data(state)
            .service(Files::new("/dist", "./static/dist")) // serving files should be the first
            // service or it doesn't serve the files at all
            .service(process_immenent_request)
            .service(index_register_secure)
            .service(forward_to_secure)
            .service(forward_to)
            .service(index)
            // serving files from '/' will prevent any other services after it from functioning properly
            // Ensure that this is the last service to be loaded
            .service(Files::new("/", "./static").index_file("index.html"));
    };

    Ok(config.into())
}
