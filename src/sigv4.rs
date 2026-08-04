use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::config::Storage;

fn hmac(key: &[u8], msg: &str) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(msg.as_bytes());
    m.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn amz_date(secs: u64) -> (String, String) {
    let (days, rem) = (secs / 86400, secs % 86400);
    let (h, mi, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        format!("{y:04}{m:02}{d:02}"),
        format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z"),
    )
}

fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut o = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                o.push(b as char)
            }
            b'/' if !encode_slash => o.push('/'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn presign(s: &Storage, method: &str, extra: &str, key: &str, ttl: u32, now: u64) -> String {
    let (date, ts) = amz_date(now);
    let scope = format!("{date}/{}/s3/aws4_request", s.region);
    let uri = uri_encode(&format!("/{}/{key}", s.bucket), false);
    let query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}&X-Amz-Date={ts}\
         &X-Amz-Expires={ttl}&X-Amz-SignedHeaders=host{extra}",
        uri_encode(&format!("{}/{scope}", s.access_key), true)
    );
    let creq = format!(
        "{method}\n{uri}\n{query}\nhost:{}\n\nhost\nUNSIGNED-PAYLOAD",
        s.endpoint.rsplit("://").next().unwrap()
    );
    let sts = format!(
        "AWS4-HMAC-SHA256\n{ts}\n{scope}\n{}",
        hex(&Sha256::digest(creq.as_bytes()))
    );
    let k = hmac(format!("AWS4{}", s.secret_key).as_bytes(), &date);
    let k = hmac(&k, &s.region);
    let k = hmac(&k, "s3");
    let k = hmac(&k, "aws4_request");
    format!(
        "{}{uri}?{query}&X-Amz-Signature={}",
        s.endpoint,
        hex(&hmac(&k, &sts))
    )
}

pub fn presign_url(s: &Storage, method: &str, key: &str, ttl: u32) -> String {
    let extra = if method == "GET" {
        "&response-content-disposition=attachment"
    } else {
        ""
    };
    let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
    presign(s, method, extra, key, ttl, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_aws_path_style_vector() {
        let s = Storage {
            endpoint: "https://s3.amazonaws.com".into(),
            bucket: "examplebucket".into(),
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            region: "us-east-1".into(),
        };
        assert_eq!(
            presign(&s, "GET", "", "test.txt", 86400, 1369353600),
            "https://s3.amazonaws.com/examplebucket/test.txt\
             ?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\
             &X-Amz-Signature=733255ef022bec3f2a8701cd61d4b371f3f28c9f193a1f02279211d48d5193d7"
        );
    }

    #[test]
    fn formats_dates() {
        assert_eq!(amz_date(0).1, "19700101T000000Z");
        assert_eq!(amz_date(1369353600).0, "20130524");
        assert_eq!(amz_date(1709164799).1, "20240228T235959Z");
        assert_eq!(amz_date(1709164800).1, "20240229T000000Z");
        assert_eq!(amz_date(1754308496).1, "20250804T115456Z");
        assert_eq!(amz_date(4102444800).1, "21000101T000000Z");
    }

    #[test]
    fn encodes_uri() {
        assert_eq!(
            uri_encode("a b+c=d/e~f.zst", false),
            "a%20b%2Bc%3Dd/e~f.zst"
        );
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
    }
}
