# DNS Proxy Application Documentation

## Introduction

This DNS Proxy application forwards DNS queries to an upstream DNS server, with caching and database integration for enhanced performance and resilience. The proxy ensures persistence by maintaining a cache file and uses a MySQL database for dynamic DNS record updates.

---

## Features

1. Forwards DNS queries to an upstream DNS server.
2. Caches responses to a JSON file (`dns_cache.json`), enabling persistence across restarts.
3. Queries a MySQL database (`dns-override` table) for DNS records.
4. Logs activities such as database lookups, cache usage, and query forwarding.
5. Configurable via a `config.json` file.

---

## Requirements

- **Rust Toolchain**: Install via [rustup](https://rustup.rs/).
- **MySQL/MariaDB**: Set up with the required table.
- **`config.json`**: Configuration file with necessary settings.

---

## Setup Instructions

### 1. Install Dependencies

- Install Rust:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- Install MySQL or MariaDB and set up the `dns-override` table:

  ```sql
  CREATE TABLE `dns-override` (
      `address` VARCHAR(255) NOT NULL,
      `type` SET('A','CNAME') NOT NULL DEFAULT 'A',
      `value` VARCHAR(255) NOT NULL,
      PRIMARY KEY (`address`)
  ) ENGINE=InnoDB;
  ```

### 2. Create Configuration File

Create `config.json` in the same directory as the binary with the following structure:

```json
{
    "log_level": "info",
    "db_settings": "mysql://user:password@localhost:3306/dnsdb",
    "upstream_dns": "8.8.8.8:53",
    "bind_address": "0.0.0.0",
    "port": 5353
}
```

- **log_level**: Logging level (`debug`, `info`, `warn`, etc.).
- **db_settings**: MySQL connection string.
- **upstream_dns**: IP and port of the upstream DNS server.
- **bind_address**: Local IP to bind to.
- **port**: Port for the DNS proxy.

### 3. Build the Application

Clone the repository or copy the code into a Rust project. Then build the binary:

```bash
cargo build --release
```

The binary will be located at `target/release/<binary_name>`.

### 4. Run the Application

Run the DNS proxy with the configuration file:

```bash
./target/release/<binary_name>
```

---

## Testing

Use `dig` to test the proxy:

### 1. Query with Cache and Database
Ensure the database has an entry:

```sql
INSERT INTO `dns-override` (address, type, value) VALUES ('example.com', 'A', '127.0.0.2');
```

Query the proxy:

```bash
dig @127.0.0.1 -p 5353 example.com
```

### 2. Query with Cache Fallback
Stop the MySQL server and test the cached response:

```bash
dig @127.0.0.1 -p 5353 example.com
```

---

## Logs

Logs are controlled via `log_level` in `config.json`. Adjust as needed.

### Example Logs
```plaintext
INFO: Starting DNS Proxy...
INFO: Listening on 0.0.0.0:5353
INFO: Using upstream DNS: 8.8.8.8:53
INFO: Handling query: example.com A
INFO: Database result: example.com -> A 127.0.0.2
```

---

## Troubleshooting

1. **Database Connection Issues**:
   - Verify `db_settings` in `config.json`.
   - Ensure the MySQL server is running and reachable.

2. **Cache Not Updating**:
   - Check write permissions for `dns_cache.json`.
   - Verify the database query returns valid results.

---

## Contributors

This program was developed to facilitate dynamic DNS query handling with database integration and persistent caching.

---

## License

This project is licensed under the MIT License.


