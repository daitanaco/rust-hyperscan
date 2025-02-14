// Author: Jonathan Eisenzopf
// Copyright 2022, All Rights Reserved

// Build instructions:
//
//     cargo run --example vectorgrep
//
// Usage:
//
//     ./vectorgrep <input file>
//
// Example:
//
//     ./simplegrep input.csv
//
//
use std::fs::*;
use std::path::PathBuf;

use anyhow::{Context, Result};
use structopt::StructOpt;

use hyperscan::prelude::*;
use hyperscan::*;

#[derive(Debug, StructOpt)]
#[structopt(name = "vectorgrep", about = "An example search a given input file for a pattern set.")]
struct Opt {
    /// Input file
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();
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
    let db: VectoredDatabase = patterns.build().unwrap();
    let scratch = db.alloc_scratch().with_context(|| "allocate scratch space")?;
    let mut matches = vec![];
    let file = File::open(&opt.input)?;
    let mut rdr = csv::Reader::from_reader(file);
    for result in rdr.records() {
        match result {
            Ok(row) => {
                db.scan(&row, &scratch, |id, from, to, flags| {
                    matches.push(from..to);
                    let s: String = row.into_iter().flat_map(|c|c.chars()).collect();
                    println!(
                        "Match for pattern \"{}\" at offset {}..{}: {}",
                        id,
                        from,
                        to,
                        &s[from as usize..to as usize]
                    );
                    Matching::Continue
                }).unwrap();
            },
            Err(e) => println!("CSV read error: {}", e),
        }
    }
    Ok(())
}
