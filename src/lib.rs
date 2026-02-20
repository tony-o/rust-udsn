#[derive(Debug, PartialEq)]
pub enum Resource {
    URI(String),
    Path(String),
}

pub struct DSN {
    pub protocol: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub resource: Option<Resource>,
    pub port: Option<u16>,
    pub database: Option<String>,
    pub params: Option<Vec<(String, Option<String>)>>,
}

impl DSN {
    pub fn new(
        protocol: String,
        username: Option<String>,
        password: Option<String>,
        resource: Option<Resource>,
        port: Option<u16>,
        database: Option<String>,
        params: Option<Vec<(String, Option<String>)>>,
    ) -> DSN {
        Self {
            protocol,
            username,
            password,
            resource,
            port,
            database,
            params,
        }
    }

    pub fn parse(dsn: String) -> Option<DSN> {
        let mut idx = 0;
        let protocol: &str;
        let mut username: Option<String> = None;
        let mut password: Option<String> = None;
        let resource: Option<Resource>;
        let mut port: Option<u16> = None;
        let database: Option<String>;
        let mut params: Option<Vec<(String, Option<String>)>> = None;
        match dsn.find("://") {
            Some(x) => {
                protocol = &dsn[idx..x];
                idx = x + 3;
            }
            None => {
                return None;
            }
        };
        let rest: Vec<&str> = dsn[idx..].split('@').collect();
        let mut scnd = rest[0];
        if rest.len() > 1 {
            //get user & pass
            let user_pass: Vec<&str> = rest[0].split(':').collect();
            username = if user_pass[0].is_empty() {
                None
            } else {
                Some(percent_decode(&user_pass[0].to_string()))
            };
            if user_pass.len() > 1 {
                password = Some(percent_decode(&user_pass[1].to_string()));
            }
            scnd = rest[1];
        }

        // get hostname & port
        match scnd.find(&[':', '/']) {
            Some(v) => {
                if (scnd.as_bytes()[v] == b'/' && v == 0)
                    || (v > 0 && v < scnd.len() - 1 && &scnd[(v - 1)..v + 1] == "./")
                {
                    let parse: Vec<&str> = scnd.split('/').collect();
                    let pstr = if parse.len() == 2 && parse[0].is_empty() {
                        &"/".to_string()
                    } else {
                        &parse[..parse.len() - 1].join("/")
                    };
                    resource = Some(Resource::Path(pstr.to_string()));
                    scnd = if parse.len() > 1 {
                        parse[parse.len() - 1]
                    } else {
                        ""
                    };
                } else {
                    resource = Some(Resource::URI(percent_decode(&scnd[0..v].to_string())));
                    if scnd.as_bytes()[v] == b':' {
                        match scnd[(v + 1)..].find(&['/', '?']) {
                            Some(p) => {
                                port = match scnd[(v + 1)..(v + 1 + p)].parse::<u16>() {
                                    Ok(i) => Some(i),
                                    Err(_e) => None,
                                };
                                scnd = &scnd[(v + p + 2)..];
                            }
                            None => {
                                // we've consumed everything
                                port = match scnd[(v + 1)..scnd.len()].parse::<u16>() {
                                    Ok(i) => Some(i),
                                    Err(_e) => return None,
                                };
                                scnd = &scnd[scnd.len()..];
                            }
                        }
                    } else {
                        scnd = &scnd[(v + 1)..];
                    }
                }
            }
            None => {
                if scnd.is_empty() {
                    return None;
                }
                let parse: Vec<&str> = scnd.splitn(2, '?').collect();
                resource = Some(Resource::URI(percent_decode(&parse[0].to_string())));
                scnd = if parse.len() > 1 {
                    &scnd[parse[0].len()..]
                } else {
                    ""
                };
            }
        }

        // get db & params
        match scnd.find('?') {
            Some(sp) => {
                database = if sp == 0 {
                    None
                } else {
                    Some(percent_decode(&scnd[..sp].to_string()))
                };
                let param_v: Vec<&str> = scnd[(sp + 1)..].split('&').collect();
                let mut param_pv = Vec::new();
                for param in param_v {
                    match param.find('=') {
                        Some(eq) => param_pv.push((
                            percent_decode(&param[..eq].to_string()),
                            Some(percent_decode(&param[(eq + 1)..].to_string())),
                        )),
                        None => param_pv.push((param.to_string(), None)),
                    }
                }
                params = Some(param_pv);
            }
            None => {
                database = if scnd.is_empty() {
                    None
                } else {
                    Some(percent_decode(&scnd.to_string()))
                }
            }
        };

        Some(DSN {
            protocol: protocol.to_string(),
            username,
            password,
            resource,
            port,
            database,
            params,
        })
    }

    pub fn to_string(&self) -> String {
        let mut out = String::with_capacity(1024);
        let mut need_at = false;
        let mut root_path = false;
        out.push_str(self.protocol.as_str());
        out.push_str("://");
        if let Some(user) = &self.username {
            out.push_str(percent_encode(&user).as_str());
            need_at = true;
        }
        if let Some(pass) = &self.password {
            out.push_str(":");
            out.push_str(percent_encode(&pass).as_str());
            need_at = true;
        }
        if need_at {
            out.push_str("@");
        }
        match &self.resource {
            Some(Resource::URI(v)) => out.push_str(percent_encode(&v).as_str()),
            Some(Resource::Path(v)) => {
                root_path = v == "/";
                out.push_str(v.as_str());
            }
            None => (),
        }
        if let Some(port) = self.port {
            out.push_str(":");
            out.push_str(port.to_string().as_str());
        }
        if let Some(db) = &self.database {
            if !root_path {
                out.push_str("/");
            }
            out.push_str(percent_encode(&db).as_str());
        }
        if let Some(params) = &self.params {
            out.push_str("?");
            let mut param_iter = params.into_iter().peekable();
            while let Some((k, v)) = param_iter.next() {
                out.push_str(percent_encode(&k).as_str());
                if let Some(iv) = v {
                    out.push_str("=");
                    out.push_str(percent_encode(&iv).as_str());
                }
                if !param_iter.peek().is_none() {
                    out.push_str("&");
                }
            }
        }

        out
    }
}

pub fn percent_encode(s: &String) -> String {
    static HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = s.as_bytes();
    let mut encoded = String::with_capacity(bytes.len() * 11 / 10);

    for &b in bytes {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char);
            }
            _ => {
                encoded.push('%');
                encoded.push(HEX_CHARS[(b >> 4) as usize] as char);
                encoded.push(HEX_CHARS[(b & 0x0F) as usize] as char);
            }
        }
    }
    encoded
}
pub fn percent_decode(s: &String) -> String {
    let bytes = s.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            // Extract the next two hex characters
            let h = decode_hex_byte(bytes[i + 1], bytes[i + 2]).unwrap();
            decoded.push(h);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8(decoded).unwrap()
}

/// Fast hex-to-byte conversion using bit manipulation
#[inline]
fn decode_hex_byte(h: u8, l: u8) -> Option<u8> {
    let high = hex_to_int(h)?;
    let low = hex_to_int(l)?;
    Some((high << 4) | low)
}

#[inline]
fn hex_to_int(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! mk_test_pos {
        ($($name:ident: $test_str:expr, $protocol:expr, $user:expr, $pass:expr, $rsrc:expr, $port:expr, $db:expr, $params:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let test_str = $test_str;
                let dsn = match DSN::parse(test_str.to_string()) {
                    Some(d) => d,
                    None => panic!("Failed to parse DSN: {}", $test_str),
                };
                assert_eq!(dsn.username, $user, "username");
                assert_eq!(dsn.password, $pass, "password");
                assert_eq!(dsn.resource, $rsrc, "resource");
                assert_eq!(dsn.port, $port, "port");
                assert_eq!(dsn.database, $db, "database");
                assert_eq!(dsn.params, $params, "params");
                assert_eq!(
                    dsn.to_string(),
                    test_str.to_string(),
                );
            }
        )*
        }
    }

    mk_test_pos! {
        base:
          "postgres://user:pass@localhost:5431/db?param1=value1",
          "postgres",
          Some("user".to_string()),
          Some("pass".to_string()),
          Some(Resource::URI("localhost".to_string())),
          Some(5431),
          Some("db".to_string()),
          Some(vec![("param1".to_string(), Some("value1".to_string()))]),
        base_file:
          "sqlite:///tmp/test-db.sqlite3",
          "sqlite",
          None,
          None,
          Some(Resource::Path("/tmp".to_string())),
          None,
          Some("test-db.sqlite3".to_string()),
          None,
        sqlite_encoded_path:
          "sqlite:///path/to/my%20db.sqlite?mode=read%20only",
          "sqlite",
          None, None,
          Some(Resource::Path("/path/to".to_string())),
          None, Some("my db.sqlite".to_string()),
          Some(vec![("mode".to_string(), Some("read only".to_string()))]),

        sqlite_relative_path:
          "sqlite://./data/store.db",
          "sqlite",
          None, None,
          Some(Resource::Path("./data".to_string())),
          None, Some("store.db".to_string()), None,

        sqlite_root_dir:
          "sqlite:///root_db.sqlite",
          "sqlite",
          None, None,
          Some(Resource::Path("/".to_string())),
          None, Some("root_db.sqlite".to_string()), None,

        // --- PERCENT ENCODING CASES ---
        encoded_auth_complex:
          "postgresql://user%3A%40:p%40ss%23%25@localhost/db%20name",
          "postgresql",
          Some("user:@".to_string()), Some("p@ss#%".to_string()),
          Some(Resource::URI("localhost".to_string())),
          None, Some("db name".to_string()), None,

        encoded_params_special:
          "mysql://host/db?key=val%20with%20%26%20and%20%3D",
          "mysql",
          None, None,
          Some(Resource::URI("host".to_string())),
          None, Some("db".to_string()),
          Some(vec![("key".to_string(), Some("val with & and =".to_string()))]),

        // --- UNIX SOCKETS (Path-heavy) ---
        unix_socket_split:
          "unix:///var/run/postgresql/socket_file",
          "unix",
          None, None,
          Some(Resource::Path("/var/run/postgresql".to_string())),
          None, Some("socket_file".to_string()), None,

        // --- NETWORK URIS (Host as Resource::URI) ---
        postgres_standard:
          "postgres://admin@db.example.com:5432/prod_db",
          "postgres",
          Some("admin".to_string()), None,
          Some(Resource::URI("db.example.com".to_string())),
          Some(5432), Some("prod_db".to_string()), None,

        mongodb_srv:
          "mongodb+srv://user:pass@cluster.mongodb.net/test?authSource=admin",
          "mongodb+srv",
          Some("user".to_string()), Some("pass".to_string()),
          Some(Resource::URI("cluster.mongodb.net".to_string())),
          None, Some("test".to_string()),
          Some(vec![("authSource".to_string(), Some("admin".to_string()))]),

        // --- SOCKS PROXIES ---
        socks5_encoded_user:
          "socks5://proxy%20admin:secret@127.0.0.1:1080",
          "socks5",
          Some("proxy admin".to_string()), Some("secret".to_string()),
          Some(Resource::URI("127.0.0.1".to_string())),
          Some(1080), None, None,

        // --- REDIS / KEY-VALUE ---
        redis_no_user:
          "redis://:strong%20password@localhost:6379/0",
          "redis",
          None, Some("strong password".to_string()),
          Some(Resource::URI("localhost".to_string())),
          Some(6379), Some("0".to_string()), None,

        // --- AMQP / CLOUD ---
        rabbitmq_vhost_encoded:
          "amqp://guest:guest@localhost:5672/%2Fmy%20vhost",
          "amqp",
          Some("guest".to_string()), Some("guest".to_string()),
          Some(Resource::URI("localhost".to_string())),
          Some(5672), Some("/my vhost".to_string()), None,

        // --- EDGE CASES ---
        no_path_no_db:
          "scheme://host:1234",
          "scheme",
          None, None,
          Some(Resource::URI("host".to_string())),
          Some(1234), None, None,

        query_only_no_db:
          "scheme://host?query=true",
          "scheme",
          None, None,
          Some(Resource::URI("host".to_string())),
          None, None, Some(vec![("query".to_string(), Some("true".to_string()))]),

        encoded_database_only:
          "scheme://host/my%2Fencoded%2Fdb",
          "scheme",
          None, None,
          Some(Resource::URI("host".to_string())),
          None, Some("my/encoded/db".to_string()), None,
        // --- PERCENT ENCODING: AUTH & PATHS ---
        enc_auth_1: "proto://user%3A%40:p%40ss%23%25@host", "proto", Some("user:@".to_string()), Some("p@ss#%".to_string()), Some(Resource::URI("host".to_string())), None, None, None,
        enc_auth_2: "proto://%20space%20:%20space%20@host", "proto", Some(" space ".to_string()), Some(" space ".to_string()), Some(Resource::URI("host".to_string())), None, None, None,
        enc_auth_3: "proto://%F0%9F%A6%80:pass@host", "proto", Some("🦀".to_string()), Some("pass".to_string()), Some(Resource::URI("host".to_string())), None, None, None,
        enc_db_1: "proto://host/db%20name", "proto", None, None, Some(Resource::URI("host".to_string())), None, Some("db name".to_string()), None,
        enc_db_2: "proto:///host/dir/my%2Fnested%2Fdb", "proto", None, None, Some(Resource::Path("/host/dir".to_string())), None, Some("my/nested/db".to_string()), None,
        enc_param_1: "proto://host?key=val%2Bplus", "proto", None, None, Some(Resource::URI("host".to_string())), None, None, Some(vec![("key".to_string(), Some("val+plus".to_string()))]),

        // --- SQLITE / FILE PATH DEPTHS ---
        file_depth_0: "sqlite:///db.sqlite", "sqlite", None, None, Some(Resource::Path("/".to_string())), None, Some("db.sqlite".to_string()), None,
        file_depth_1: "sqlite:///opt/db.sqlite", "sqlite", None, None, Some(Resource::Path("/opt".to_string())), None, Some("db.sqlite".to_string()), None,
        file_depth_2: "sqlite:///var/lib/data.db", "sqlite", None, None, Some(Resource::Path("/var/lib".to_string())), None, Some("data.db".to_string()), None,
        file_depth_3: "sqlite:///home/user/projects/app/dev.db", "sqlite", None, None, Some(Resource::Path("/home/user/projects/app".to_string())), None, Some("dev.db".to_string()), None,
        file_rel_1: "sqlite://./local.db", "sqlite", None, None, Some(Resource::Path(".".to_string())), None, Some("local.db".to_string()), None,
        file_rel_2: "sqlite://../parent/data.db", "sqlite", None, None, Some(Resource::Path("../parent".to_string())), None, Some("data.db".to_string()), None,
        file_win_style: "sqlite:///C:/Users/db.sqlite", "sqlite", None, None, Some(Resource::Path("/C:/Users".to_string())), None, Some("db.sqlite".to_string()), None,

        // --- SOCKS & NETWORK PROXIES ---
        socks_basic: "socks5://127.0.0.1:1080", "socks5", None, None, Some(Resource::URI("127.0.0.1".to_string())), Some(1080), None, None,
        socks_auth: "socks5://admin:secret@proxy.com:1080", "socks5", Some("admin".to_string()), Some("secret".to_string()), Some(Resource::URI("proxy.com".to_string())), Some(1080), None, None,
        socks_h: "socks5h://remote-dns-proxy:8080", "socks5h", None, None, Some(Resource::URI("remote-dns-proxy".to_string())), Some(8080), None, None,
        socks_enc: "socks4://user%201:pass%402@10.0.0.5", "socks4", Some("user 1".to_string()), Some("pass@2".to_string()), Some(Resource::URI("10.0.0.5".to_string())), None, None, None,

        // --- POSTGRES VARIATIONS ---
        pg_no_port: "postgresql://user@localhost/dbname", "postgresql", Some("user".to_string()), None, Some(Resource::URI("localhost".to_string())), None, Some("dbname".to_string()), None,
        pg_with_port: "postgresql://user:pass@localhost:5432/dbname", "postgresql", Some("user".to_string()), Some("pass".to_string()), Some(Resource::URI("localhost".to_string())), Some(5432), Some("dbname".to_string()), None,
        pg_options: "postgresql://localhost/db?sslmode=verify-full&connect_timeout=10", "postgresql", None, None, Some(Resource::URI("localhost".to_string())), None, Some("db".to_string()), Some(vec![("sslmode".to_string(), Some("verify-full".to_string())), ("connect_timeout".to_string(), Some("10".to_string()))]),

        // --- MONGO & REDIS ---
        mongo_srv: "mongodb+srv://atlas-user:password@cluster0.mongodb.net/admin", "mongodb+srv", Some("atlas-user".to_string()), Some("password".to_string()), Some(Resource::URI("cluster0.mongodb.net".to_string())), None, Some("admin".to_string()), None,
        redis_db: "redis://localhost:6379/15", "redis", None, None, Some(Resource::URI("localhost".to_string())), Some(6379), Some("15".to_string()), None,
        redis_auth: "redis://:pwd@localhost", "redis", None, Some("pwd".to_string()), Some(Resource::URI("localhost".to_string())), None, None, None,

        // --- REPEATED GENERATED SAMPLES (Pattern: protocol, user, pass, host, port, path, db, params) ---
        gen_1: "mysql://u:p@1.1.1.1:3306/d", "mysql", Some("u".to_string()), Some("p".to_string()), Some(Resource::URI("1.1.1.1".to_string())), Some(3306), Some("d".to_string()), None,
        gen_2: "mysql://u:p@1.1.1.1/d", "mysql", Some("u".to_string()), Some("p".to_string()), Some(Resource::URI("1.1.1.1".to_string())), None, Some("d".to_string()), None,
        gen_3: "mysql://u@1.1.1.1/d", "mysql", Some("u".to_string()), None, Some(Resource::URI("1.1.1.1".to_string())), None, Some("d".to_string()), None,
        gen_4: "mysql://1.1.1.1/d", "mysql", None, None, Some(Resource::URI("1.1.1.1".to_string())), None, Some("d".to_string()), None,
        gen_5: "mysql://1.1.1.1", "mysql", None, None, Some(Resource::URI("1.1.1.1".to_string())), None, None, None,

        // --- COMPLEX QUERY PARAMS ---
        query_multi: "proto://host/db?a=1&b=2&c=3&d=4", "proto", None, None, Some(Resource::URI("host".to_string())), None, Some("db".to_string()), Some(vec![("a".to_string(), Some("1".to_string())), ("b".to_string(), Some("2".to_string())), ("c".to_string(), Some("3".to_string())), ("d".to_string(), Some("4".to_string()))]),
        query_enc_keys: "proto://host?%24key=val", "proto", None, None, Some(Resource::URI("host".to_string())), None, None, Some(vec![("$key".to_string(), Some("val".to_string()))]),
        query_empty_vals: "proto://host?key1=&key2", "proto", None, None, Some(Resource::URI("host".to_string())), None, None, Some(vec![("key1".to_string(), Some("".to_string())), ("key2".to_string(), None)]),

        // --- UNIX DOMAIN SOCKETS ---
        unix_1: "unix:///tmp/pg.sock", "unix", None, None, Some(Resource::Path("/tmp".to_string())), None, Some("pg.sock".to_string()), None,
        unix_2: "unix:///var/run/redis/redis.sock", "unix", None, None, Some(Resource::Path("/var/run/redis".to_string())), None, Some("redis.sock".to_string()), None,
        unix_enc: "unix:///var/lib/my%20app/socket", "unix", None, None, Some(Resource::Path("/var/lib/my%20app".to_string())), None, Some("socket".to_string()), None,

        // --- IPv6 ---
        // NYI
        //ipv6_1: "http://[::1]:80", "http", None, None, Some(Resource::URI("[::1]".to_string())), Some(80), None, None,
        //ipv6_2: "http://2001:db8:85a3::8a2e:370:7334", "http", None, None, Some(Resource::URI("[2001:db8:85a3::8a2e:370:7334]".to_string())), None, Some("db".to_string()), None,
        //ipv6_auth: "http://::1", "http", Some("u".to_string()), Some("p".to_string()), Some(Resource::URI("[::1]".to_string())), None, Some("db".to_string()), None,

        // --- EXOTIC SCHEMES ---
        amqp_full: "amqp://user:pass@localhost:5672/vhost?heartbeat=60", "amqp", Some("user".to_string()), Some("pass".to_string()), Some(Resource::URI("localhost".to_string())), Some(5672), Some("vhost".to_string()), Some(vec![("heartbeat".to_string(), Some("60".to_string()))]),
        mqtt_ss: "mqtts://broker.hivemq.com:8883", "mqtts", None, None, Some(Resource::URI("broker.hivemq.com".to_string())), Some(8883), None, None,
        // NYI kafka_node: "kafka://broker1:9092,broker2:9092", "kafka", None, None, Some(Resource::URI("broker1:9092,broker2:9092".to_string())), None, None, None,

        // --- MINIMAL / EMPTY ---
        min_1: "a://b", "a", None, None, Some(Resource::URI("b".to_string())), None, None, None,
        min_2: "a:///b", "a", None, None, Some(Resource::Path("/".to_string())), None, Some("b".to_string()), None,
        min_3: "a://user@host", "a", Some("user".to_string()), None, Some(Resource::URI("host".to_string())), None, None, None,
        min_4: "a://:pass@host", "a", None, Some("pass".to_string()), Some(Resource::URI("host".to_string())), None, None, None,

        // --- PORT BOUNDARIES ---
        port_low: "p://h:1", "p", None, None, Some(Resource::URI("h".to_string())), Some(1), None, None,
        port_high: "p://h:65535", "p", None, None, Some(Resource::URI("h".to_string())), Some(65535), None, None,
        port_common: "p://h:8080", "p", None, None, Some(Resource::URI("h".to_string())), Some(8080), None, None,

        // --- MORE PERCENT ENCODING MIXES ---
        mix_enc_1: "p://u%201:p%201@h%201:123/d%201?q%201=v%201", "p", Some("u 1".to_string()), Some("p 1".to_string()), Some(Resource::URI("h 1".to_string())), Some(123), Some("d 1".to_string()), Some(vec![("q 1".to_string(), Some("v 1".to_string()))]),
        mix_enc_2: "p://%23%23:%24%24@%25%25/%5E%5E", "p", Some("##".to_string()), Some("$$".to_string()), Some(Resource::URI("%%".to_string())), None, Some("^^".to_string()), None,
    }
}
