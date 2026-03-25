use std::env;
use watt_did::{Did, DidKey, DidResolver, DidWeb, DidWebResolver};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> watt_did::Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_default();

    match command.as_str() {
        "inspect" => {
            let did = Did::parse(&args.next().unwrap_or_default())?;
            println!("did={did}");
            println!("method={}", did.method());
            println!("id={}", did.id());
            if did.method() == "key" {
                let did_key = DidKey::from_did(did)?;
                println!("public_key_multibase={}", did_key.public_key_multibase);
                println!("decoded_key={:?}", did_key.decode_public_key()?);
            } else if did.method() == "web" {
                let did_web = DidWeb::from_did(did)?;
                println!("host={}", did_web.host);
                println!("path_segments={:?}", did_web.path_segments);
                println!("document_url={}", did_web.to_url());
            }
            Ok(())
        }
        "resolve" => {
            let did = Did::parse(&args.next().unwrap_or_default())?;
            let resolver = DidWebResolver::default();
            let result = resolver.resolve(&did)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&result).map_err(|error| {
                    watt_did::DidError::InvalidDocument(format!("serialize result failed: {error}"))
                })?
            );
            Ok(())
        }
        "document" => {
            let did = Did::parse(&args.next().unwrap_or_default())?;
            let document = if did.method() == "key" {
                DidKey::from_did(did)?.to_document()?
            } else {
                return Err(watt_did::DidError::UnsupportedMethod(
                    "document command currently supports did:key".into(),
                ));
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&document).map_err(|error| {
                    watt_did::DidError::InvalidDocument(format!(
                        "serialize document failed: {error}"
                    ))
                })?
            );
            Ok(())
        }
        "help" | "" => {
            print_help();
            Ok(())
        }
        _ => Err(watt_did::DidError::InvalidDidSyntax(
            "unknown command; use inspect | resolve | document".into(),
        )),
    }
}

fn print_help() {
    println!("watt-did");
    println!();
    println!("Commands:");
    println!("  inspect <did>     Parse and inspect a DID");
    println!("  resolve <did>     Resolve a did:web document over HTTP");
    println!("  document <did>    Build a minimal DID document for did:key");
}
