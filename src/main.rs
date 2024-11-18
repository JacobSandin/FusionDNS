use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RData, Record, RecordType};
use trust_dns_proto::rr::rdata::{A, CNAME};
use mysql_async::{Pool, prelude::*};
use log::{info, warn, error};
use serde::{Deserialize, Serialize};

// Configuration struct
#[derive(Deserialize)]
struct Config {
    log_level: String,
    db_settings: String,
    upstream_dns: String,
    bind_address: String,
    port: u16,
}

// DNS Record Cache Structs
#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsRecord {
    record_type: String,
    value: String,
    ttl: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct Cache {
    records: HashMap<String, DnsRecord>,
}

impl Cache {
    fn load(path: &str) -> Self {
        match fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_else(|_| Cache {
                records: HashMap::new(),
            }),
            Err(_) => Cache {
                records: HashMap::new(),
            },
        }
    }

    fn save(&self, path: &str) {
        if let Ok(content) = serde_json::to_string_pretty(&self) {
            let _ = fs::write(path, content);
        }
    }

    fn get(&self, key: &str) -> Option<DnsRecord> {
        self.records.get(key).cloned()
    }

    fn insert(&mut self, key: String, record: DnsRecord) {
        self.records.insert(key, record);
    }

    fn remove(&mut self, key: &str) {
        self.records.remove(key);
    }
}

// Load configuration from a JSON file
fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let config_content = fs::read_to_string(path)?;
    let config: Config = serde_json::from_str(&config_content)?;
    Ok(config)
}

// Handle DNS queries
async fn handle_query(query: Query, pool: &Pool, cache: &mut Cache, cache_file: &str) -> Option<Record> {
    let qname = query.name().to_string().trim_end_matches('.').to_string();
    let qtype = query.query_type();

    info!("Handling query: {} {:?}", qname, qtype);

    let mut conn = match pool.get_conn().await {
        Ok(conn) => conn,
        Err(_) => {
            warn!("Database connection failed, checking cache...");
            return cache.get(&qname).and_then(|cached| {
                if (cached.record_type == "A" && qtype == RecordType::A)
                    || (cached.record_type == "CNAME" && qtype == RecordType::CNAME)
                {
                    let name = query.name().clone();
                    let ttl = cached.ttl;
                    if cached.record_type == "A" {
                        if let Ok(addr) = cached.value.parse::<std::net::Ipv4Addr>() {
                            return Some(Record::from_rdata(name, ttl, RData::A(A(addr))));
                        }
                    } else if cached.record_type == "CNAME" {
                        if let Ok(cname) = Name::parse(&cached.value, None) {
                            return Some(Record::from_rdata(name, ttl, RData::CNAME(CNAME(cname))));
                        }
                    }
                }
                None
            });
        }
    };

    let sql_query = "SELECT `type`, `value` FROM `dns-override` WHERE `address` = ?";
    let result: Option<(String, String)> = match conn.exec_first(sql_query, (qname.clone(),)).await {
        Ok(res) => res,
        Err(e) => {
            warn!("Database query error: {}", e);
            return None;
        }
    };

    if let Some((record_type, value)) = result {
        info!("Database result: {} -> {} {}", qname, record_type, value);

        let name = query.name().clone();
        let ttl = 3600;

        cache.insert(
            qname.clone(),
            DnsRecord {
                record_type: record_type.clone(),
                value: value.clone(),
                ttl,
            },
        );
        cache.save(cache_file);

        if record_type == "A" && qtype == RecordType::A {
            if let Ok(addr) = value.parse::<std::net::Ipv4Addr>() {
                return Some(Record::from_rdata(name, ttl, RData::A(A(addr))));
            }
        } else if record_type == "CNAME" && qtype == RecordType::CNAME {
            if let Ok(cname) = Name::parse(&value, None) {
                return Some(Record::from_rdata(name, ttl, RData::CNAME(CNAME(cname))));
            }
        }
    } else {
        cache.remove(&qname);
        cache.save(cache_file);
    }

    None
}

// Run the DNS proxy
async fn run_proxy(
    listen_addr: &str,
    db_url: &str,
    upstream_dns: &str,
    cache_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = Pool::new(db_url);
    let socket = UdpSocket::bind(listen_addr).await?;
    let mut buf = [0u8; 512];
    let upstream_addr: SocketAddr = upstream_dns.parse()?;
    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;

    let mut cache = Cache::load(cache_file);

    info!("DNS proxy listening on {}", listen_addr);

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let message = Message::from_vec(&buf[..len])?;
        let mut response = Message::new();
        response.set_id(message.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_recursion_desired(true);

        let mut handled = false;

        for query in message.queries() {
            info!("Received query from {}: {:?}", src, query);
            if let Some(record) = handle_query(query.clone(), &pool, &mut cache, cache_file).await {
                response.add_answer(record);
                handled = true;
                info!("Query handled from database or cache: {:?}", query.name());
            }
        }

        if handled {
            let response_buf = response.to_vec()?;
            socket.send_to(&response_buf, src).await?;
        } else {
            upstream_socket.send_to(&buf[..len], upstream_addr).await?;
            let (upstream_len, _) = upstream_socket.recv_from(&mut buf).await?;
            socket.send_to(&buf[..upstream_len], src).await?;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config("config.json")?;
    env_logger::Builder::new().parse_filters(&config.log_level).init();

    let listen_addr = format!("{}:{}", config.bind_address, config.port);
    let db_url = config.db_settings;
    let upstream_dns = config.upstream_dns;
    let cache_file = "dns_cache.json";

    run_proxy(&listen_addr, &db_url, &upstream_dns, cache_file).await
}

