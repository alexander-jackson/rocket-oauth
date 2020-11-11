#![feature(decl_macro)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

use std::collections::HashMap;
use std::env;

use oauth::{Builder, Credentials};
use reqwest::blocking::Client;
use rocket::http::RawStr;
use rocket::response::Redirect;
use url::form_urlencoded;

#[macro_use]
extern crate rocket;

#[derive(oauth::Request)]
struct Request {
    scope: &'static str,
    expiry: &'static str,
}

const SCOPE: &str = "urn:websignon.warwick.ac.uk:sso:service";
const EXPIRY: &str = "forever";
const OAUTH_CALLBACK: &str = "http://localhost:8000/authorised";

const REQUEST_TOKEN_URL: &str = "https://websignon.warwick.ac.uk/oauth/requestToken";
const AUTHORISE_TOKEN_URL: &str = "https://websignon.warwick.ac.uk/oauth/authorise";
const ACCESS_TOKEN_URL: &str = "https://websignon.warwick.ac.uk/oauth/accessToken";

/// Represents the root of the website. Users are immediately redirected to sign in.
///
/// Gets the `CONSUMER_KEY` and `CONSUMER_SECRET` values from the environment and requests a new
/// token from the SSO provider. The secret is then written to disk currently, and the token is
/// used to form a redirect, which is returned to the user so they can sign in through the
/// provider.
#[get("/")]
fn index() -> Redirect {
    let consumer_key = env::var("CONSUMER_KEY").unwrap();
    let consumer_secret = env::var("CONSUMER_SECRET").unwrap();

    let request_token = obtain_request_token(&consumer_key, &consumer_secret);
    log::info!("Request token obtained: {}", request_token);

    let query_params: HashMap<_, _> = form_urlencoded::parse(&request_token.as_bytes()).collect();
    let token = &query_params["oauth_token"];
    let secret = &query_params["oauth_token_secret"];

    std::fs::write("secret.txt", &**secret).unwrap();

    let url = format!(
        "{}?oauth_token={}&oauth_callback={}",
        AUTHORISE_TOKEN_URL, token, OAUTH_CALLBACK
    );

    Redirect::to(url)
}

/// Represents the callback of the website. Users are sent here after signing in through SSO.
///
/// Gets the parameters from the query string and logs them to the terminal before requesting to
/// exchange the request token for an access token. If this succeeds, logs the token and displays
/// it on the frontend to the user.
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

/// Obtains a request token from the OAuth provider, corresponding to Stage 1.
///
/// Using the `consumer_key` and `consumer_secret`, signs a request to the SSO service and requests
/// a new request token. This can then be used later on to become an access token.
fn obtain_request_token(consumer_key: &str, consumer_secret: &str) -> String {
    let credentials = Credentials::new(consumer_key, consumer_secret);
    let request = Request {
        scope: SCOPE,
        expiry: EXPIRY,
    };
    let auth = Builder::<_, _>::new(credentials, oauth::HmacSha1)
        .callback(OAUTH_CALLBACK)
        .post(&REQUEST_TOKEN_URL, &request);

    let client = Client::new();
    let request = client
        .post(REQUEST_TOKEN_URL)
        .header("Authorization", auth)
        .header("User-Agent", "Cinnamon")
        .query(&[("scope", SCOPE), ("expiry", EXPIRY)]);

    log::info!("Request to send: {:#?}", request);

    let response = request.send().unwrap();

    log::info!("Response code: {}", response.status());

    response.text().unwrap()
}

/// Exchanges a request token for an access token, corresponding to Stage 3.
///
/// Using the `consumer_key`, `consumer_secret`, `oauth_token` and `oauth_verifier`, signs a
/// request to the SSO service and requests for the request token received previously to become an
/// access token. This requires the client secret from Stage 1 as well.
fn exchange_request_for_access(
    consumer_key: &str,
    consumer_secret: &str,
    oauth_token: &str,
    oauth_verifier: &str,
) -> String {
    let secret = &std::fs::read_to_string("secret.txt").unwrap();
    let token = oauth::Credentials::new(oauth_token, secret);

    let credentials = Credentials::new(consumer_key, consumer_secret);
    let auth = Builder::<_, _>::new(credentials, oauth::HmacSha1)
        .verifier(oauth_verifier)
        .token(Some(token))
        .post(&ACCESS_TOKEN_URL, &());

    log::info!("Authorization header: {}", auth);

    let client = Client::new();
    let request = client
        .post(ACCESS_TOKEN_URL)
        .header("Authorization", auth)
        .header("User-Agent", "Cinnamon");

    log::info!("Request to send: {:#?}", request);

    let response = request.send().unwrap();
    let status = response.status();

    log::info!("Response code: {}", status);

    response.text().unwrap()
}

/// Builds the web server routing and returns it ready to be launched.
pub fn build_rocket() -> rocket::Rocket {
    rocket::ignite().mount("/", routes![index, authorised])
}
