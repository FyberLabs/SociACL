//! Native vault transport CLI. Credentials arrive over stdin, never argv.
#[cfg(unix)]
fn main() {
    if let Err(error) = unix::run() {
        eprintln!("sociacl-vault: {error}");
        std::process::exit(1);
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("sociacl-vault requires Unix");
    std::process::exit(1);
}

#[cfg(unix)]
mod unix {
    use base64ct::{Base64, Base64UrlUnpadded, Encoding};
    use serde_json::{json, Value};
    use sociacl_encdisc::{parse_vault_sync_head, seal_native_vault_head, NativeVaultHttp};
    use std::{fs::File, io::{self, Read}, path::Path};
    use zeroize::Zeroizing;

    const MAX_BYTES: usize = 8 * 1024 * 1024;
    const USAGE: &str = "usage: sociacl-vault read | publish FILE (create|CAS) | get-object DIGEST | put-object FILE | seal-head JSON-FILE";

    fn input(limit: usize) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let mut bytes = Zeroizing::new(Vec::new());
        io::stdin().take((limit + 1) as u64).read_to_end(&mut bytes).map_err(|_| "cannot read credential input")?;
        if bytes.len() > limit { return Err("credential input too large"); }
        Ok(bytes)
    }

    fn file(path: &str, limit: usize) -> Result<Vec<u8>, &'static str> {
        let mut bytes = Vec::new();
        File::open(Path::new(path)).and_then(|file| file.take((limit + 1) as u64).read_to_end(&mut bytes))
            .map_err(|_| "cannot read input file")?;
        if bytes.is_empty() || bytes.len() > limit { return Err("invalid input file size"); }
        Ok(bytes)
    }

    pub fn run() -> Result<(), &'static str> {
        let args: Vec<String> = std::env::args_os().skip(1).map(|arg| arg.into_string().map_err(|_| USAGE))
            .collect::<Result<_, _>>()?;
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        if args.as_slice() == ["--help"] {
            println!("{USAGE}");
            return Ok(());
        }
        if let ["seal-head", path] = args.as_slice() {
            let password = input(4096)?;
            let password = std::str::from_utf8(&password).map_err(|_| "invalid passphrase input")?;
            let bytes = Zeroizing::new(file(path, 8192)?);
            let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid head JSON")?;
            let head = parse_vault_sync_head(&value).map_err(|_| "invalid signed head shape")?;
            let sealed = seal_native_vault_head(&head, password).map_err(|_| "head sealing refused")?;
            println!("{}", json!({"bytes": Base64::encode_string(sealed.bytes())}));
            return Ok(());
        }
        if !matches!(args.as_slice(), ["read"] | ["publish", _, _] | ["get-object", _] | ["put-object", _]) {
            return Err(USAGE);
        }
        let credentials = input(16384)?;
        let mut fields = credentials.split(|b| *b == b'\n');
        let mut field = || -> Result<&str, &'static str> {
            std::str::from_utf8(fields.next().ok_or("incomplete credential input")?).map_err(|_| "invalid credential input")
        };
        let origin = field()?;
        let owner = field()?;
        let vault = field()?;
        let session_key = field()?;
        let cookie = Zeroizing::new(field()?.to_owned());
        let scalar = Zeroizing::new(Base64UrlUnpadded::decode_vec(field()?).map_err(|_| "invalid signing scalar")?);
        if !matches!(fields.next(), None | Some([])) || fields.next().is_some() { return Err("unexpected credential input"); }
        let client = NativeVaultHttp::new(origin, owner, vault, session_key, cookie, scalar)
            .map_err(|_| "invalid transport configuration")?;
        let failed = |_| "vault request refused or unavailable; retain input bytes for reconciliation";
        let output = match args.as_slice() {
            ["read"] => client.read().map_err(failed)?.map(|head| json!({"bytes":Base64::encode_string(&head.bytes),"revision":head.revision})),
            ["publish", path, expected] => {
                let expected = (*expected != "create").then_some(*expected);
                Some(json!({"revision":client.publish(&file(path, MAX_BYTES)?, expected).map_err(failed)?}))
            }
            ["get-object", id] => client.get_object(id).map_err(failed)?.map(|bytes| json!({"bytes":Base64::encode_string(&bytes)})),
            ["put-object", path] => Some(json!({"digest":client.put_object(&file(path, MAX_BYTES)?).map_err(failed)?})),
            _ => return Err(USAGE),
        };
        println!("{}", output.map_or(Value::Null, |value| value));
        Ok(())
    }
}
