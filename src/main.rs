fn main() {
    pretty_env_logger::init();
    dotenv::dotenv().unwrap();

    let rocket = rocket_oauth::build_rocket();
    rocket.launch();
}
