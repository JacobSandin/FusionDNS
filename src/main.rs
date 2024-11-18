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
use std::future::Future;
use std::pin::Pin;

// Configuration struct
#[derive(Deserialize)]
struct Config {
    log_level: String,
    db_settings: String,
    sql_query: String,
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


// Define a helper type for a boxed future
type BoxedFuture<'a> = Pin<Box<dyn Future<Output = Vec<Record>> + Send + 'a>>;

fn handle_query_recursive<'a>(
    query: Query,
    pool: &'a Pool,
    cache: &'a mut Cache,
    cache_file: &'a str,
    sql_query: &'a str,
) -> BoxedFuture<'a> {
    Box::pin(async move {
        let mut records = Vec::new();
        let qname = query.name().to_string().trim_end_matches('.').to_string();
        let qtype = query.query_type();

        info!("Handling query: {} {:?}", qname, qtype);

        // Step 1: Check the cache first
        if let Some(cached) = cache.get(&qname) {
            let name = query.name().clone();
            let ttl = cached.ttl;

            if cached.record_type == "A" && qtype == RecordType::A {
                if let Ok(addr) = cached.value.parse::<std::net::Ipv4Addr>() {
                    records.push(Record::from_rdata(name, ttl, RData::A(A(addr))));
                }
            } else if cached.record_type == "CNAME" && qtype == RecordType::CNAME {
                if let Ok(cname) = Name::parse(&cached.value, None) {
                    records.push(Record::from_rdata(name.clone(), ttl, RData::CNAME(CNAME(cname.clone()))));

                    // Recursively fetch the A record for the CNAME
                    let a_query = Query::query(cname.clone(), RecordType::A);
                    let a_records = handle_query_recursive(a_query, pool, cache, cache_file, sql_query).await;
                    records.extend(a_records);
                }
            }
            return records;
        }

        // Step 2: Query the database
        let mut conn = match pool.get_conn().await {
            Ok(conn) => conn,
            Err(_) => {
                warn!("Database connection failed; returning cache result if available.");
                return records;
            }
        };

        let result: Option<(String, String)> = match conn.exec_first(sql_query, (qname.clone(),)).await {
            Ok(res) => res,
            Err(e) => {
                warn!("Database query error: {}", e);
                return records;
            }
        };

        if let Some((record_type, value)) = result {
            info!("Database result: {} -> {} {}", qname, record_type, value);

            let name = query.name().clone();
            let ttl = 3600;

            // Update the cache
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
                    records.push(Record::from_rdata(name, ttl, RData::A(A(addr))));
                }
            } else if record_type == "CNAME" {
                if let Ok(cname) = Name::parse(&value, None) {
                    records.push(Record::from_rdata(name.clone(), ttl, RData::CNAME(CNAME(cname.clone()))));

                    // Recursively fetch the A record for the CNAME
                    let a_query = Query::query(cname.clone(), RecordType::A);
                    let a_records = handle_query_recursive(a_query, pool, cache, cache_file, sql_query).await;
                    records.extend(a_records);
                }
            }
        } else {
            // No result, remove from cache
            cache.remove(&qname);
            cache.save(cache_file);
        }

        records
    })
}

async fn handle_query(
    query: Query,
    pool: &Pool,
    cache: &mut Cache,
    cache_file: &str,
    sql_query: &str,
) -> Vec<Record> {
    let mut records = Vec::new();
    let qname = query.name().to_string().trim_end_matches('.').to_string();
    let qtype = query.query_type();

    info!("Handling query: {} {:?}", qname, qtype);

    // Check the cache first
    if let Some(cached) = cache.get(&qname) {
        info!("Cache hit for {}: {:?}", qname, cached);

        let name = query.name().clone();
        let ttl = cached.ttl;

        if cached.record_type == "A" && qtype == RecordType::A {
            if let Ok(addr) = cached.value.parse::<std::net::Ipv4Addr>() {
                records.push(Record::from_rdata(name, ttl, RData::A(A(addr))));
            }
        } else if cached.record_type == "CNAME" {
            if let Ok(cname) = Name::parse(&cached.value, None) {
                records.push(Record::from_rdata(name.clone(), ttl, RData::CNAME(CNAME(cname.clone()))));

                // Recursively resolve the A record for the CNAME
                let a_query = Query::query(cname.clone(), RecordType::A);
                let a_records = handle_query_recursive(a_query, pool, cache, cache_file, sql_query).await;
                records.extend(a_records);
            }
        }
        return records;
    }

    // Query the database
    let mut conn = match pool.get_conn().await {
        Ok(conn) => conn,
        Err(_) => {
            warn!("Database connection failed.");
            return records; // Return empty records if the database is unreachable
        }
    };

    let result: Option<(String, String)> = match conn.exec_first(sql_query, (qname.clone(),)).await {
        Ok(res) => res,
        Err(e) => {
            warn!("Database query error: {}", e);
            return records;
        }
    };

    if let Some((record_type, value)) = result {
        info!("Database result: {} -> {} {}", qname, record_type, value);

        let name = query.name().clone();
        let ttl = 3600;

        // Update the cache
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
                records.push(Record::from_rdata(name, ttl, RData::A(A(addr))));
            }
        } else if record_type == "CNAME" {
            if let Ok(cname) = Name::parse(&value, None) {
                records.push(Record::from_rdata(name.clone(), ttl, RData::CNAME(CNAME(cname.clone()))));

                // Recursively resolve the A record for the CNAME
                let a_query = Query::query(cname.clone(), RecordType::A);
                let a_records = handle_query_recursive(a_query, pool, cache, cache_file, sql_query).await;
                records.extend(a_records);
            }
        }
    }

    records
}

async fn run_proxy(
    listen_addr: &str,
    db_url: &str,
    upstream_dns: &str,
    cache_file: &str,
    sql_query: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = Pool::new(db_url);
    let socket = UdpSocket::bind(listen_addr).await?;
    let mut buf = [0u8; 512];
    let upstream_addr: SocketAddr = upstream_dns.parse()?;
    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Load cache
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
        
            // Fetch records from handle_query
            let records = handle_query(query.clone(), &pool, &mut cache, cache_file, sql_query).await;
        
            if !records.is_empty() {
                for record in &records {  // Use a reference to avoid consuming the Vec
                    response.add_answer(record.clone()); // Clone the record if needed
                }
                handled = true;
                info!("Query resolved locally: {:?}", records);
            } else {
                info!("No local result for {}, forwarding to upstream DNS.", query.name());
            }
        }


        
        if handled {
            // Send the response if the query was handled locally
            let response_buf = response.to_vec()?;
            socket.send_to(&response_buf, src).await?;
            info!("Response sent to {} from database/cache", src);
        } else {
            // Forward the query to the upstream DNS server
            upstream_socket.send_to(&buf[..len], upstream_addr).await?;
            info!("Forwarded query to upstream DNS: {}", upstream_dns);
        
            // Receive the response from the upstream server
            let (upstream_len, _) = upstream_socket.recv_from(&mut buf).await?;
            socket.send_to(&buf[..upstream_len], src).await?;
            info!("Response sent to {} from upstream DNS", src);
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
    let sql_query = config.sql_query; 
        //"SELECT `type`, `value` FROM `dns_override` WHERE `address` = ?";

    run_proxy(&listen_addr, &db_url, &upstream_dns, cache_file, &sql_query).await
}

