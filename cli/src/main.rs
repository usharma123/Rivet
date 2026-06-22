fn main() {
    if let Err(err) = rivet::run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
