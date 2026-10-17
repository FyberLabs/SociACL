// Keep this literal grammar aligned with typescript/ids/src/uri.js.
pub(crate) fn public_host(host: &str) -> bool {
    let labels: Vec<_> = host.split('.').collect();
    host.len() <= 253
        && labels.len() > 1
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with("xn--")
                && l.as_bytes()[0].is_ascii_alphanumeric()
                && l.as_bytes()[l.len() - 1].is_ascii_alphanumeric()
                && l.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
        && labels
            .last()
            .unwrap()
            .bytes()
            .all(|c| c.is_ascii_lowercase())
        && ![
            "localhost",
            "local",
            "internal",
            "home.arpa",
            "test",
            "invalid",
            "example",
            "onion",
            "alt",
        ]
        .iter()
        .any(|s| host == *s || host.ends_with(&format!(".{s}")))
}
pub(crate) fn web_uri(s: &str, origin: bool, https_only: bool) -> bool {
    let (scheme, rest) = match s.split_once("://") {
        Some(v) => v,
        None => return false,
    };
    if scheme != "https" && (https_only || scheme != "http") {
        return false;
    }
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, None), |(a, p)| (a, Some(p)));
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    if !public_host(host) {
        return false;
    }
    if let Some(p) = port {
        if !p.bytes().all(|c| c.is_ascii_digit())
            || !p.parse::<u16>().is_ok_and(|n| n > 0 && n.to_string() == p)
            || p == if scheme == "https" { "443" } else { "80" }
        {
            return false;
        }
    }
    if origin {
        return path.is_none();
    }
    let Some(path) = path else {
        return false;
    };
    let b = path.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_alphanumeric() || b"._~!$&'()*+,;=:@/-".contains(&b[i]) {
            i += 1;
        } else if b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1..i + 3]
                .iter()
                .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c))
        {
            let n = u8::from_str_radix(&path[i + 1..i + 3], 16).expect("checked hex");
            if n < 32 || n == 127 || n.is_ascii_alphanumeric() || b"._~-".contains(&n) {
                return false;
            }
            i += 3;
        } else {
            return false;
        }
    }
    path.split('/').all(|p| {
        let d = p.replace("%2E", ".");
        d != "." && d != ".."
    })
}
