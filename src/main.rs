use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

#[derive(Parser)]
#[command(about = "Dynamic DNS updater for Cloudflare")]
struct Args {
    #[arg(long, env = "CLOUDFLARE_API_TOKEN")]
    api_token: String,
    #[arg(long, env = "ZONE_ID")]
    zone_id: String,
    #[arg(long, env = "DOMAIN_NAME")]
    domain: String,
    #[arg(long, env = "IP_TYPE", help = "Which IP to update: v4 (A record) or v6 (AAAA record)")]
    ip_type: IpType,
    #[arg(short, long, help = "Run as a background daemon")]
    daemon: bool,
}

#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum IpType {
    V4,
    V6,
}

#[derive(Deserialize)]
struct CfResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct CfError {
    #[serde(default)]
    code: u32,
    message: String,
}

#[derive(Deserialize)]
struct DnsRecord {
    id: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
}

#[derive(Serialize)]
struct DnsRecordPayload {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
    proxied: bool,
}

struct TrackedRecord {
    id: String,
    current_ip: String,
}

fn daemonize() {
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!("[error]   first fork failed");
            std::process::exit(1);
        }
        0 => {}
        _ => std::process::exit(0),
    }

    if unsafe { libc::setsid() } == -1 {
        eprintln!("[error]   setsid failed");
        std::process::exit(1);
    }

    match unsafe { libc::fork() } {
        -1 => {
            eprintln!("[error]   second fork failed");
            std::process::exit(1);
        }
        0 => {}
        _ => std::process::exit(0),
    }

    unsafe {
        let dev_null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if dev_null != -1 {
            libc::dup2(dev_null, libc::STDIN_FILENO);
            libc::dup2(dev_null, libc::STDOUT_FILENO);
            if dev_null > 2 {
                libc::close(dev_null);
            }
        }
        libc::chdir(c"/".as_ptr());
    }
}

fn get_ipv6() -> Option<Ipv6Addr> {
    let socket = UdpSocket::bind("[::]:0").ok()?;
    socket.connect("[2001:4860:4860::8888]:53").ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V6(addr) => Some(*addr.ip()),
        _ => None,
    }
}

fn get_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .ok()?;

    // STUN Binding Request (RFC 5389)
    let stun_server: SocketAddr = "74.125.250.129:19302".parse().ok()?;
    let txn_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut request = [0u8; 20];
    request[0] = 0x00;
    request[1] = 0x01;
    request[4] = 0x21;
    request[5] = 0x12;
    request[6] = 0xA4;
    request[7] = 0x42;
    request[8..20].copy_from_slice(&txn_id);

    socket.send_to(&request, stun_server).ok()?;

    let mut buf = [0u8; 512];
    let n = socket.recv(&mut buf).ok()?;
    if n < 20 {
        return None;
    }

    let mut pos = 20;
    while pos + 4 <= n {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let attr_value_start = pos + 4;

        if attr_type == 0x0020 && attr_len >= 8 {
            let family = buf[attr_value_start + 1];
            if family == 0x01 {
                let xored = [
                    buf[attr_value_start + 4] ^ 0x21,
                    buf[attr_value_start + 5] ^ 0x12,
                    buf[attr_value_start + 6] ^ 0xA4,
                    buf[attr_value_start + 7] ^ 0x42,
                ];
                return Some(Ipv4Addr::new(xored[0], xored[1], xored[2], xored[3]));
            }
        }

        if attr_type == 0x0001 && attr_len >= 8 {
            let family = buf[attr_value_start + 1];
            if family == 0x01 {
                return Some(Ipv4Addr::new(
                    buf[attr_value_start + 4],
                    buf[attr_value_start + 5],
                    buf[attr_value_start + 6],
                    buf[attr_value_start + 7],
                ));
            }
        }

        pos = attr_value_start + ((attr_len + 3) & !3);
    }

    None
}

fn cf_result<T>(resp: CfResponse<T>) -> Result<T, String> {
    if !resp.success {
        let msgs: Vec<_> = resp.errors.iter().map(|e| format!("[{}] {}", e.code, e.message)).collect();
        return Err(format!("Cloudflare API error: {}", msgs.join(", ")));
    }
    resp.result.ok_or_else(|| "Cloudflare API returned null result".to_string())
}

fn cf_client(api_token: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {api_token}").parse().unwrap(),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

async fn list_dns_records(
    client: &reqwest::Client,
    zone_id: &str,
    domain: &str,
) -> Result<Vec<DnsRecord>, String> {
    let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={domain}");
    let resp: CfResponse<Vec<DnsRecord>> = client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    cf_result(resp)
}

async fn create_dns_record(
    client: &reqwest::Client,
    zone_id: &str,
    domain: &str,
    record_type: &str,
    ip: &str,
) -> Result<String, String> {
    let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");
    let payload = DnsRecordPayload {
        record_type: record_type.to_string(),
        name: domain.to_string(),
        content: ip.to_string(),
        ttl: 1,
        proxied: true,
    };
    let resp: CfResponse<DnsRecord> = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let record = cf_result(resp)?;
    println!("[created] {record_type} {domain} -> {ip} (id: {})", record.id);
    Ok(record.id)
}

async fn delete_dns_record(
    client: &reqwest::Client,
    zone_id: &str,
    record_id: &str,
    record_type: &str,
    content: &str,
) -> Result<(), String> {
    let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}");
    let resp = client
        .delete(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("failed to delete record {record_id}"));
    }
    println!("[deleted] {record_type} {content} (id: {record_id})");
    Ok(())
}

async fn update_dns_record(
    client: &reqwest::Client,
    zone_id: &str,
    record_id: &str,
    domain: &str,
    record_type: &str,
    ip: &str,
) -> Result<(), String> {
    let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}");
    let payload = DnsRecordPayload {
        record_type: record_type.to_string(),
        name: domain.to_string(),
        content: ip.to_string(),
        ttl: 1,
        proxied: true,
    };
    let resp: CfResponse<DnsRecord> = client
        .put(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    cf_result(resp)?;
    println!("[updated] {record_type} {domain} -> {ip}");
    Ok(())
}

fn resolve_ip(ip_type: IpType) -> Option<String> {
    match ip_type {
        IpType::V4 => match get_ipv4() {
            Some(ip) => {
                println!("[detect]  A    -> {ip}");
                Some(ip.to_string())
            }
            None => {
                eprintln!("[warn]    failed to detect IPv4");
                None
            }
        },
        IpType::V6 => match get_ipv6() {
            Some(ip) => {
                println!("[detect]  AAAA -> {ip}");
                Some(ip.to_string())
            }
            None => {
                eprintln!("[warn]    failed to detect IPv6");
                None
            }
        },
    }
}

fn record_type_for(ip_type: IpType) -> &'static str {
    match ip_type {
        IpType::V4 => "A",
        IpType::V6 => "AAAA",
    }
}

async fn ensure_record(
    client: &reqwest::Client,
    zone_id: &str,
    domain: &str,
    existing: &[DnsRecord],
    record_type: &str,
    ip: &str,
) -> Result<TrackedRecord, String> {
    let opposite = if record_type == "A" { "AAAA" } else { "A" };
    for stale in existing.iter().filter(|r| r.record_type == opposite) {
        if let Err(e) = delete_dns_record(client, zone_id, &stale.id, opposite, &stale.content).await {
            eprintln!("[warn]    failed to delete {opposite} record: {e}");
        }
    }

    let matches: Vec<_> = existing.iter().filter(|r| r.record_type == record_type).collect();

    for dup in matches.iter().skip(1) {
        if let Err(e) = delete_dns_record(client, zone_id, &dup.id, record_type, &dup.content).await {
            eprintln!("[warn]    failed to delete duplicate {record_type}: {e}");
        }
    }

    if let Some(keep) = matches.first() {
        if keep.content != ip {
            update_dns_record(client, zone_id, &keep.id, domain, record_type, ip).await?;
        } else {
            println!("[ok]      {record_type} {domain} already {ip}");
        }
        Ok(TrackedRecord {
            id: keep.id.clone(),
            current_ip: ip.to_string(),
        })
    } else {
        let id = create_dns_record(client, zone_id, domain, record_type, ip).await?;
        Ok(TrackedRecord {
            id,
            current_ip: ip.to_string(),
        })
    }
}

fn main() {
    let args = Args::parse();

    if args.daemon {
        daemonize();
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(args));
}

async fn run(args: Args) {
    let client = cf_client(&args.api_token);
    let rtype = record_type_for(args.ip_type);

    let ip = resolve_ip(args.ip_type).unwrap_or_else(|| {
        eprintln!("[error]   failed to detect IP — exiting");
        std::process::exit(1);
    });

    let existing = list_dns_records(&client, &args.zone_id, &args.domain)
        .await
        .unwrap_or_else(|e| {
            eprintln!("[error]   {e}");
            std::process::exit(1);
        });

    let mut tracked = ensure_record(&client, &args.zone_id, &args.domain, &existing, rtype, &ip)
        .await
        .unwrap_or_else(|e| {
            eprintln!("[error]   {rtype} record: {e}");
            std::process::exit(1);
        });

    println!("[loop]    watching for IP changes every 1s ...");

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let Some(new_ip) = resolve_ip(args.ip_type) else {
            continue;
        };

        if new_ip != tracked.current_ip {
            println!("[change]  {rtype} {} -> {new_ip}", tracked.current_ip);
            match update_dns_record(
                &client,
                &args.zone_id,
                &tracked.id,
                &args.domain,
                rtype,
                &new_ip,
            )
            .await
            {
                Ok(()) => tracked.current_ip = new_ip,
                Err(e) => eprintln!("[error]   update {rtype}: {e}"),
            }
        }
    }
}
