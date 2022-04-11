// Hyperscan example program 1: simplegrep
//
// This is a simple example of Hyperscan's most basic functionality: it will
// search a given input file for a pattern supplied as a command-line argument.
// It is intended to demonstrate correct usage of the hs_compile and hs_scan
// functions of Hyperscan.
//
// Patterns are scanned in 'DOTALL' mode, which is equivalent to PCRE's '/s'
// modifier. This behaviour can be changed by modifying the "flags" argument to
// hs_compile.
//
// Build instructions:
//
//     cargo run --example simplegrep
//
// Usage:
//
//     ./simplegrep <pattern> <input file>
//
// Example:
//
//     ./simplegrep int simplegrep.c
//
//

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use structopt::StructOpt;

use hyperscan::prelude::*;
use hyperscan::*;

#[derive(Debug, StructOpt)]
#[structopt(name = "simplegrep", about = "An example search a given input file for a pattern.")]
struct Opt {
    /// Input file
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    // First, we attempt to compile the pattern provided on the command line.
    // We assume 'DOTALL' semantics, meaning that the '.' meta-character will
    // match newline characters. The compiler will analyse the given pattern and
    // either return a compiled Hyperscan database, or an error message
    // explaining why the pattern didn't compile.
    let pattern1 = r#"(?<us_currency>\$[+-]?[0-9]{1,3}(?:,?[0-9]{3})*(?:\.[0-9]{2}))"#;
    let pattern2 = r#"(?<us_social_security_number>[0-8][0-9]{2}(-|\s)?[0-9]{2}(-|\s)[0-9]{4})"#;
    let pattern3 = r#"(?<credit_card>\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)"#;
    let pattern4 = r#"(?<credit_card>\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)"#;
    let pattern5 = r#"(?<credit_card>\b6011[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)"#;
    let pattern6 = r#"(?<credit_card>\b3[4,7]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b)"#;
    let pattern7 = r#"(?:[a-z0-9!#$%&''*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&''*+\/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#;
    let pattern8 = r#"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"#;
    let pattern9 = r#"\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})"#;
    let patterns = patterns!(pattern1, pattern2, pattern3, pattern4, pattern5, pattern6, pattern7, pattern8, pattern9; CASELESS | DOTALL | SOM_LEFTMOST);
    let db: BlockDatabase = patterns.build().unwrap();

    // Next, we read the input data file into a buffer.
    let input_data = fs::read_to_string(opt.input).with_context(|| "read input file")?;

    // Finally, we issue a call to hs_scan, which will search the input buffer
    // for the pattern represented in the bytecode. Note that in order to do
    // this, scratch space needs to be allocated with the hs_alloc_scratch
    // function. In typical usage, you would reuse this scratch space for many
    // calls to hs_scan, but as we're only doing one, we'll be allocating it
    // and deallocating it as soon as our matching is done.
    //
    // When matches occur, the specified callback function (eventHandler in
    // this file) will be called. Note that although it is reminiscent of
    // asynchronous APIs, Hyperscan operates synchronously: all matches will be
    // found, and all callbacks issued, *before* hs_scan returns.
    //
    // In this example, we provide the input pattern as the context pointer so
    // that the callback is able to print out the pattern that matched on each
    // match event.
    //

    let scratch = db.alloc_scratch().with_context(|| "allocate scratch space")?;
    
    println!("Scanning {} bytes with Hyperscan", input_data.len());
    db
        .scan(&input_data, &scratch, |id, from, to, flags| {
            println!(
                "Match for pattern \"{}\" at offset {}..{}: {}",
                id,
                from,
                to,
                &input_data[from as usize..to as usize]
            );

            Matching::Continue
        })
        .with_context(|| "scan input buffer")
}
