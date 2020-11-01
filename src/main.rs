#![feature(decl_macro)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

use std::env;

use dotenv::dotenv;
use oauth::{Builder, Credentials};
use reqwest::blocking::Client;
use rocket::http::RawStr;
use rocket::response::Redirect;

#[macro_use]
extern crate rocket;

#[derive(oauth::Request)]
struct Request {
    scope: &'static str,
    expiry: &'static str,
}

#[derive(oauth::Request)]
struct Access<'a> {
    oauth_token: &'a str,
}

const SCOPE: &str = "urn:websignon.warwick.ac.uk:sso:service";
const EXPIRY: &str = "forever";
const OAUTH_CALLBACK: &str = "http://localhost:8000/authorised";

fn parse_token(token: &str) -> &str {
    let index = token.find('=').unwrap();
    &token.split_at(index).1[1..]
}

fn parse_tokens(request_token: &str) -> (&str, &str) {
    let tokens: Vec<&str> = request_token.split('&').collect();
    (parse_token(tokens[0]), parse_token(tokens[1]))
}

#[get("/")]
fn index() -> Redirect {
    let consumer_key = env::var("CONSUMER_KEY").unwrap();
    let consumer_secret = env::var("CONSUMER_SECRET").unwrap();

    let request_token = obtain_request_token(&consumer_key, &consumer_secret);
    log::info!("Request token obtained: {}", request_token);

    let base = "https://websignon.warwick.ac.uk/oauth/authorise";
    let (token, secret) = parse_tokens(&request_token);

    std::fs::write("secret.txt", secret).unwrap();

    let url = format!(
        "{}?oauth_token={}&oauth_callback={}",
        base, token, OAUTH_CALLBACK
    );

    Redirect::to(url)
}

#[get("/authorised?<oauth_token>&<user_id>&<oauth_verifier>")]
fn authorised(oauth_token: &RawStr, user_id: &RawStr, oauth_verifier: &RawStr) -> String {
    let request_token = oauth_token.as_str();
    let user_id = user_id.as_str();
    let oauth_verifier = oauth_verifier.as_str();

    log::info!("Request token authorized: {}", request_token);
    log::info!("User ID: {}", user_id);
    log::info!("OAuth Verifier: {}", oauth_verifier);

    let consumer_key = env::var("CONSUMER_KEY").unwrap();
    let consumer_secret = env::var("CONSUMER_SECRET").unwrap();
    let access_token = exchange_request_for_access(
        &consumer_key,
        &consumer_secret,
        request_token,
        oauth_verifier,
    );

    log::info!("Access token received: {}", access_token);

    access_token
}

fn obtain_request_token(consumer_key: &str, consumer_secret: &str) -> String {
    let url = "https://websignon.warwick.ac.uk/oauth/requestToken";

    let credentials = Credentials::new(consumer_key, consumer_secret);
    let request = Request {
        scope: SCOPE,
        expiry: EXPIRY,
    };
    let auth = Builder::<_, _>::new(credentials, oauth::HmacSha1)
        .callback(OAUTH_CALLBACK)
        .post(&url, &request);

    let client = Client::new();
    let request = client
        .post(url)
        .header("Authorization", auth)
        .header("User-Agent", "Cinnamon")
        .query(&[("scope", SCOPE), ("expiry", EXPIRY)]);

    log::info!("Request to send: {:#?}", request);

    let response = request.send().unwrap();

    log::info!("Response code: {}", response.status());

    response.text().unwrap()
}

fn exchange_request_for_access(
    consumer_key: &str,
    consumer_secret: &str,
    oauth_token: &str,
    oauth_verifier: &str,
) -> String {
    let url = "https://websignon.warwick.ac.uk/oauth/accessToken";

    let secret = &std::fs::read_to_string("secret.txt").unwrap();
    let token = oauth::Credentials::new(oauth_token, secret);

    let credentials = Credentials::new(consumer_key, consumer_secret);
    let auth = Builder::<_, _>::new(credentials, oauth::HmacSha1)
        .verifier(oauth_verifier)
        .token(Some(token))
        .post(&url, &());

    log::info!("Authorization header: {}", auth);

    let client = Client::new();
    let request = client
        .post(url)
        .header("Authorization", auth)
        .header("User-Agent", "Cinnamon");

    log::info!("Request to send: {:#?}", request);

    let response = request.send().unwrap();
    let status = response.status();

    log::info!("Response code: {}", status);

    response.text().unwrap()
}

fn main() {
    pretty_env_logger::init();
    dotenv().unwrap();

    rocket::ignite()
        .mount("/", routes![index, authorised])
        .launch();
}
