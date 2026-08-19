//! Asks this machine to prove somebody is here, and prints what came back.
//!
//! Run it to see the sheet with your own eyes:
//!
//! ```sh
//! cargo run -p selfhost-presence --example prove
//! ```
//!
//! It exists because the interesting half of this crate cannot be asserted in a
//! test — a test suite that puts a Touch ID sheet in front of whoever runs it is
//! a test suite nobody runs. So the ceremony is proved here, by a person, and the
//! answer is printed rather than recorded.

fn main() {
    match selfhost_presence::askable() {
        Ok(()) => println!("this machine can be asked"),
        Err(why) => println!("this machine cannot be asked: {why}"),
    }
    // Off the main thread, exactly as the console does it: the sheet is the
    // system's, and the thread that would draw a window must stay free to draw
    // it.
    let asked = std::thread::spawn(|| selfhost_presence::demand("open the selfhost console"));
    println!("{:?}", asked.join().expect("the asking thread finished"));
}
