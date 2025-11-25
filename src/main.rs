use async_std::net::TcpStream;
use async_std::sync::{Arc, Mutex};
use csv::WriterBuilder;
use ipnetwork::IpNetwork;
use serde_json::{json, to_string_pretty};
use std::{
    env,
    fs::File,
    io::Write,
    net::{IpAddr, SocketAddr},
};
use tokio::time::{Duration, Instant};
use std::collections::HashMap;


// Refactored enum to hold UDP probes
// enum UdpProbe {
//     DNS(&'static [u8]),
//         DHCP(&'static [u8]),
//         TFTP(&'static [u8]),
//         NTP(&'static [u8]),
//         SNMP(&'static [u8]),
//         IKE(&'static [u8]),
//         Syslog(&'static [u8]),
//         RADIUS(&'static [u8]),
//         UPnP(&'static [u8]),
//         IPSec(&'static [u8]),
//         http_OPTIONS_req(&'static [u8]),
//         http_post_req(&'static [u8]),
//         https(&'static [u8]),
//     // Add other probes here
// }

// const UDP_PROBES: [UdpProbe; 13] = [
//     UdpProbe::DNS(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"),
//     UdpProbe::DHCP(b"\x01\x01\x06\x00\x00\x0a\x02\x0a\x0a\x14\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
//     UdpProbe::TFTP(b"\x00\x01filename\x00mode\x00"),
//     UdpProbe::NTP(b"\x17\x00\x02\x2a\x00\x00\x00\x00"),
//     UdpProbe::SNMP(b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x37\xc1\xb9\x46\x02\x01\x00\x02\x01\x7F\x30\x00\x30\x12\x30\x10\x06\x0a\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"),
//     UdpProbe::IKE(b"\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
//     UdpProbe::Syslog(b"\x00"),
//     UdpProbe::RADIUS(b"\x01\x01\x00\x1e\x55\xff\xff\xff\xff\xf0\x8d\xf7\xd5\x12\x6f\x89\x72\x90\x63\x86\xf8\x45\xa9\x6e\x0e\xcf\x4d\xe3\xf1\xc3\x6a\x5e"),
//     UdpProbe::UPnP(b"\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x4f\x53\x54\x3a\x20\x31\x39\x32\x2e\x31\x36\x38\x2e\x31\x2e\x31\x3a\x35\x30\x30\x31\x0d\x0a\x4d\x41\x4e\x3a\x20\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x53\x54\x3a\x20\x75\x70\x6e\x70\x3a\x72\x6f\x6f\x74\x64\x65\x76\x69\x63\x65\x0d\x0a\x0d\x0a"),
//     UdpProbe::IPSec(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
//     UdpProbe::http_OPTIONS_req(b"\x4f\x50\x54\x49\x4f\x4e\x53\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x38\x30\x0d\x0a\x0d\x0a"),
//     UdpProbe::http_post_req(b"\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x38\x30\x0d\x0a\x0d\x0a"),
//     UdpProbe::https(b"\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x38\x30\x0d\x0a\x0d\x0a"),
//     // Initialize other probes similarly
// ];

// // Refactored argument parsing using struct and FromStr trait
// #[derive(Debug, PartialEq)]
// enum OutputType {
//     Txt,
//     Csv,
//     Json,
// }

// impl FromStr for OutputType {
//     type Err = ();

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         match s {
//             "txt" => Ok(OutputType::Txt),
//             "csv" => Ok(OutputType::Csv),
//             "json" => Ok(OutputType::Json),
//             _ => Err(()),
//         }
//     }
// }

// #[derive(Debug)]
// enum ProtocolType {
//     Tcp,
//     Udp,
// }

// impl FromStr for ProtocolType {
//     type Err = ();

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         match s {
//             "tcp" => Ok(ProtocolType::Tcp),
//             "udp" => Ok(ProtocolType::Udp),
//             _ => Err(()),
//         }
//     }
// }

//---------------------------------------------------------------------------//
const DNS: &[u8] =
    b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03";
const DHCP: &[u8] = b"\x01\x01\x06\x00\x00\x0a\x02\x0a\x0a\x14\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const TFTP: &[u8] = b"\x00\x01filename\x00mode\x00";
const NTP: &[u8] = b"\x17\x00\x02\x2a\x00\x00\x00\x00";
const SNMP: &[u8] = b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x37\xc1\xb9\x46\x02\x01\x00\x02\x01\x7F\x30\x00\x30\x12\x30\x10\x06\x0a\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00";
const IKE: &[u8] = b"\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const SYSLOG: &[u8] = b"\x00";
const RADIUS: &[u8] = b"\x01\x01\x00\x1e\x55\xff\xff\xff\xff\xf0\x8d\xf7\xd5\x12\x6f\x89\x72\x90\x63\x86\xf8\x45\xa9\x6e\x0e\xcf\x4d\xe3\xf1\xc3\x6a\x5e";
const UPNP: &[u8] = b"\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x4f\x53\x54\x3a\x20\x31\x39\x32\x2e\x31\x36\x38\x2e\x31\x2e\x31\x3a\x35\x30\x30\x31\x0d\x0a\x4d\x41\x4e\x3a\x20\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x53\x54\x3a\x20\x75\x70\x6e\x70\x3a\x72\x6f\x6f\x74\x64\x65\x76\x69\x63\x65\x0d\x0a\x0d\x0a";
const IPSEC: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const HTTP_OPTIONS_REQ: &[u8] = b"\x4f\x50\x54\x49\x4f\x4e\x53\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x38\x30\x0d\x0a\x0d\x0a";
const HTTP_POST_REQ: &[u8] = b"\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x38\x30\x0d\x0a\x0d\x0a";
const HTTPS: &[u8] = b"\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x38\x30\x0d\x0a\x0d\x0a";
//---------------------------------------------------------------------------//

//--------------------------------------------------------------------------//
// Define a HashMap with service descriptions for respective ports
fn get_service_descriptions() -> HashMap<u16, &'static str> {
    let mut services = HashMap::new();

    services.insert(20, "FTP");
    services.insert(21, "FTP");
    services.insert(22, "SSH");
    services.insert(23, "Telnet");
    services.insert(25, "SMTP");
    services.insert(53, "DNS");
    services.insert(80, "HTTP");
    services.insert(110, "POP3");
    services.insert(443, "HTTPS");
    services.insert(161, "SNMP");
    services.insert(162, "SNMP");
    services.insert(389, "LDAP");
    services.insert(445, "SMB");
    services.insert(3389, "RDP");
    services.insert(123, "NTP");
    services.insert(143, "IMAP");
    services.insert(67, "DHCP");
    services.insert(68, "DHCP");

    // Registered Ports (1024-49151)
    services.insert(3306, "MySQL");
    services.insert(5432, "PostgreSQL");
    services.insert(1521, "Oracle");
    services.insert(27017, "MongoDB");
    services.insert(6379, "Redis");
    services.insert(5900, "VNC");
    services.insert(5901, "VNC");
    services.insert(9418, "Git");
    services.insert(88, "Kerberos");
    services.insert(2049, "NFS");
    services.insert(6667, "IRC");
    services.insert(5060, "SIP");
    services.insert(5061, "SIP");
    services.insert(5222, "XMPP");
    services.insert(5223, "XMPP");
    services.insert(989, "FTPS");
    services.insert(990, "FTPS");
    services.insert(3283, "Apple Remote Desktop");
    services.insert(135, "MS Exchange");
    services.insert(587, "MS Exchange");
    services.insert(995, "MS Exchange");
    services.insert(162, "SNMP Trap");
    services.insert(636, "LDAP Secure");
    services.insert(464, "Kerberos");
    services.insert(137, "NetBIOS Name Service");
    services.insert(138, "NetBIOS Datagram Service");
    services.insert(139, "NetBIOS Session Service");
    services.insert(1812, "RADIUS");
    services.insert(1813, "RADIUS");
    services.insert(546, "DHCPv6");
    services.insert(547, "DHCPv6");
    services.insert(1701, "L2TP");
    services.insert(1723, "PPTP");
    services.insert(1433, "MS SQL Server");
    services.insert(1433, "MS SQL Server");
    services.insert(5060, "Asterisk");
    services.insert(5061, "Asterisk");
    services.insert(111, "NFS");
    services.insert(179, "BGP");
    services.insert(500, "IKE");
    services.insert(89, "OSPF");
    services.insert(520, "RIP");
    services.insert(162, "SNMP Trap");
    services.insert(49, "TACACS+");
    services.insert(636, "LDAP over TLS/SSL (LDAPS)");
    services.insert(853, "DNS over TLS");
    services.insert(548, "Apple Filing Protocol (AFP)");
    services.insert(5353, "Zeroconf/Bonjour");

    // Messaging and Collaboration
    services.insert(25, "Exchange Server");
    services.insert(110, "Exchange Server");
    services.insert(143, "Exchange Server");
    services.insert(587, "Exchange Server");
    services.insert(993, "Exchange Server");
    services.insert(5222, "XMPP");
    services.insert(5223, "XMPP");
    services.insert(5269, "XMPP");
    services.insert(5060, "SIP");
    services.insert(5061, "SIP");
    services.insert(465, "SMTPS");
    services.insert(993, "IMAPS");
    services.insert(995, "POP3S");
    services.insert(8008, "CalDAV");
    services.insert(8443, "CalDAV");
    services.insert(8800, "CardDAV");
    services.insert(8843, "CardDAV");

    // Streaming and Media
    services.insert(1935, "RTMP");
    services.insert(554, "RTSP");
    services.insert(8000, "Icecast");
    services.insert(8000, "Shoutcast");

    // Database and Data Services
    services.insert(3306, "MariaDB");
    services.insert(8091, "Couchbase");
    services.insert(5984, "CouchDB");
    services.insert(9200, "Elasticsearch");
    services.insert(9300, "Elasticsearch");
    services.insert(8086, "InfluxDB");
    services.insert(11211, "Memcached");
    services.insert(27017, "MongoDB");
    services.insert(27018, "MongoDB");
    services.insert(27019, "MongoDB");
    services.insert(1186, "MySQL Cluster");
    services.insert(26379, "Redis Sentinel");

    // Remote Access and Control
    services.insert(5938, "TeamViewer");
    services.insert(443, "LogMeIn");
    services.insert(7070, "AnyDesk");
    services.insert(5631, "PCAnywhere");
    services.insert(5632, "PCAnywhere");
    services.insert(3389, "Remote Desktop Gateway");

    services
}
//--------------------------------------------------------------------------//

//---------------------------------------------handler for connections for reducing resources used in project--------------//
async fn handle_addresses(
    addresses: Vec<SocketAddr>,
    timeout: Duration,
    protocol: u8,
    rl: usize,
) -> Vec<SocketAddr> {
    let successful_connections: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));
    let successful_udp_connections: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));

    for addr_chunk in addresses.chunks(rl) {
        let mut tasks = vec![];

        for &addrrr in addr_chunk {
            let successful_connections_clone = Arc::clone(&successful_connections); // Clone the Arc
            let _udp_connections_clone = Arc::clone(&successful_udp_connections); // Clone the Arc for UDP

            let task = async move {
                if protocol == 0 {
                    match async_std::future::timeout(timeout, TcpStream::connect(addrrr)).await {
                        Ok(Ok(stream)) => {
                            println!("Connected to: {:?}", addrrr);
                            let mut locked_connections = successful_connections_clone.lock().await;
                            locked_connections.push(addrrr);
                            drop(stream);
                        }
                        _ => {
                            // println!("Failed to connect to: {:?}", addrrr);
                        }
                    }
                } else {
                    // Handle UDP connections similarly

                    let probes = vec![
                        DNS,
                        DHCP,
                        TFTP,
                        NTP,
                        SNMP,
                        IKE,
                        SYSLOG,
                        RADIUS,
                        UPNP,
                        IPSEC,
                        HTTP_OPTIONS_REQ,
                        HTTP_POST_REQ,
                        HTTPS,
                    ];

                    for probe in &probes {
                        let result = async_std::future::timeout(timeout, async {
                            let socket = match async_std::net::UdpSocket::bind("0.0.0.0:0").await {
                                Ok(socket) => socket,
                                Err(err) => {
                                    eprintln!("Error creating UDP socket: {}", err);
                                    return None;
                                }
                            };

                            if let Err(err) = socket.connect(&addrrr).await {
                                eprintln!("Error connecting UDP socket: {}", err);
                                return None;
                            }

                            if let Err(err) = socket.send(probe).await {
                                eprintln!("Error sending UDP probe: {}", err);
                                return None;
                            }

                            let mut buf = vec![0u8; 65535];
                            let response = socket.recv_from(&mut buf).await;

                            match response {
                                Ok((size, addr)) => {
                                    println!(
                                        "Received {} bytes from {} on port {}",
                                        size,
                                        addr,
                                        addrrr.port()
                                    );
                                    buf.truncate(size);
                                    Some(addr)
                                }
                                // Err(err) => {
                                //     if err.kind() == std::io::ErrorKind::TimedOut {
                                //         eprintln!(
                                //             "Timed out while waiting for UDP response on port {}",
                                //             addrrr.port()
                                //         );
                                //     } else {
                                //         eprintln!("Error receiving UDP response: {}", err);
                                //     }
                                //     None
                                // }
                                _ => {
                                    println!("Failed to connect to: {:?}", addrrr);
                                    None
                                }
                            }
                        })
                        .await;
                        match result {
                            Ok(Some(addr)) => {
                                let mut locked_connections =
                                    successful_connections_clone.lock().await;
                                locked_connections.push(addr);
                            }
                            Ok(None) => {
                                // Handle if the UDP response is None (timeout or error)
                            }
                            Err(_) => {
                                // Handle the timeout error here
                            }
                        }
                    }
                }
            };
            tasks.push(tokio::spawn(task));
        }

        for task in tasks {
            let _ = task.await; // Wait for tasks to complete without sleeping
        }
    }

    // Extract and return the locked_connections vector
    let locked_connections = successful_connections.lock().await;
    locked_connections.clone()
}
//---------------------------------------------End of handler for connections for reducing resources used in project-------//

//---------------------------------------------function for generating ips & ports one by one from different mods----------//
fn generate_socket_addrs(
    ip: Option<IpAddr>,
    cidr: Option<IpNetwork>,
    ports: Vec<u16>,
) -> Vec<SocketAddr> {
    let default_ports = (1..=65535).collect::<Vec<_>>();
    let resolved_ports = if ports.is_empty() {
        &default_ports
    } else {
        &ports
    };

    // println!("{:?}", &ports);

    match (ip, cidr) {
        (Some(ip_addr), _) => resolved_ports
            .iter()
            .map(|port| SocketAddr::new(ip_addr, *port))
            .collect(),
        (_, Some(cidr_network)) => cidr_network
            .iter()
            .flat_map(|ip| {
                resolved_ports
                    .iter()
                    .map(move |&port| SocketAddr::new(ip, port))
            })
            .collect(),
        _ => panic!("Either --ip or --cidr is necessary."),
    }
}
//---------------------------------------------End of function for generating ips & ports one by one from different mods---//

//---------------------------------------------function for help users-----------------------------------------------------//
fn print_help(program_name: &str) {
    println!("Usage: {} [options]", program_name);
    println!("Options:");
    println!("  --port-range start_port-end_port   Search ports within a range");
    println!("  --ports port1,port2,...            Search specific ports");
    println!("  --ip IP_ADDRESS                    Specify a single IP to scan");
    println!("  --cidr CIDR_NOTATION               Specify a CIDR notation for IP range");
    println!("  --timeout SECONDS                  Set timeout duration in seconds");
    println!(
        "  --sleep-ms-chunk MILLISECONDS      Set sleep duration between chunks in milliseconds"
    );
    println!("  --output OUTPUT_TYPE               Set output type (txt, csv, json)"); // Changed flag name
    println!("  --protocol PROTOCOL_TYPE           Set protocol type (tcp, udp)"); // Added protocol flag
    println!("  -h                                 Display this help message");
}
//---------------------------------------------End of function for help users---------------------------------------------//

fn print_banner() {
    println!(
        r#"                                                                                                    "#
    );
    println!(
        r#"     ___              __         ___              __         ____                                   "#
    );
    println!(
        r#"    / _ \ __ __  ___ / /_       / _ \ ___   ____ / /_       / __/ ____ ___ _  ___   ___  ___   ____ "#
    );
    println!(
        r#"   / , _// // / (_-</ __/      / ___// _ \ / __// __/      _\ \  / __// _ `/ / _ \ / _ \/ -_) / __/ "#
    );
    println!(
        r#"  /_/|_| \_,_/ /___/\__/      /_/    \___//_/   \__/      /___/  \__/ \_,_/ /_//_//_//_/\__/ /_/    "#
    );
    println!(
        r#"                                                                                                    "#
    );
}

#[tokio::main]
async fn main() {
    print_banner();

    //getting parameters from command line.
    let args: Vec<String> = env::args().collect();

    //if -h is in command print help and exit.
    if args.contains(&"-h".to_string()) {
        print_help(&args[0]);
        return;
    }

    //define some variables for inputs from command line.
    let (
        mut ip,
        mut cidr,
        mut ports,
        mut _timeout,
        mut output_type,
        mut port_flag,
        mut port_range_flag,
        mut protocol,
        mut rl,
    ) = (
        None,
        None,
        Vec::new(),
        Duration::from_millis(1000),
        String::new(),
        false,
        false,
        0,
        100,
    );

    //---------------------------------------------------------------------------//
    //getting parameters from command line to vaiables and seperate conditions.
    for i in 1..args.len() {
        match args[i].as_str() {
            //if we want to search ports from n to m
            "--port-range" => {
                if port_flag {
                    eprintln!("Please provide either --port-range or --ports, not both.");
                    return;
                }
                port_range_flag = true;
                if let Some(range) = args.get(i + 1).map(|r| r.split('-').collect::<Vec<_>>()) {
                    if range.len() == 2 {
                        if let (Ok(start_port), Ok(end_port)) =
                            (range[0].parse::<u16>(), range[1].parse::<u16>())
                        {
                            ports.extend(start_port..=end_port);
                        }
                    }
                }
            }
            //if we want to search ports from  a list seperated by commas `80,443,8080,...`
            "--ports" => {
                if port_range_flag {
                    eprintln!("Please provide either --port-range or --ports, not both.");
                    return;
                }
                port_flag = true;
                if let Some(ports_list) = args.get(i + 1) {
                    let parsed_ports: Vec<u16> = ports_list
                        .split(',')
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    ports.extend(parsed_ports);
                }
            }
            //if we want to search ports just for one ip.
            "--ip" => {
                ip = args.get(i + 1).and_then(|ip_str| ip_str.parse().ok());
            }
            //if we want to search ports for range of ips.
            "--cidr" => {
                cidr = args.get(i + 1).and_then(|cidr_str| cidr_str.parse().ok());
            }
            //parameter for waiting for response of requests.
            "--timeout" => {
                _timeout = args
                    .get(i + 1)
                    .and_then(|timeout_str| timeout_str.parse().ok())
                    .map(Duration::from_millis)
                    .unwrap_or_else(|| {
                        eprintln!("Invalid timeout value, using default (5 seconds).");
                        Duration::from_millis(1000)
                    });
            }
            //out put type of results. that can be (txt,csv,json).
            "--o-type" => {
                output_type = args[i + 1].clone();
            }
            //Selects protocol type
            "--p" => {
                if let Some(value) = args.get(i + 1) {
                    if value == "udp" {
                        protocol = 1; // Set protocol to UDP
                    }
                }
            }

            // Sets chunk size in each operation
            "--rl" => {
                if let Some(value) = args.get(i + 1) {
                    if let Ok(parsed_rl) = value.parse::<usize>() {
                        rl = parsed_rl; // Set rl to the parsed value
                    }
                }
            }
            _ => {}
        }
    }
    //---------------------------------------------------------------------------//

    //---------------------------------------------------------------------------//
    let socket_addrs = generate_socket_addrs(ip, cidr, ports);
    //---------------------------------------------------------------------------//

    let start_time = Instant::now();

    //---------------------------------------------------------------------------//
    let results = handle_addresses(socket_addrs, _timeout, protocol, rl).await;
    //---------------------------------------------------------------------------//

    //--------------------------------------------------------------------------//
    let services = get_service_descriptions();

    if args.contains(&"-s".to_string()) {
        println!("//======================Services:==========================//\n");
        for addr in results.iter() {
            if let Some(service) = services.get(&addr.port()) {
                
                println!("Port {} is for {}", addr.port(), service);
                println!("//...............................................");
            }
        }
        println!("\n//======================End Of Services:=====================//\n");
    }
    //--------------------------------------------------------------------------//
    

    //---------------------------------------------------------------------------//
    match output_type.as_str() {
        "txt" => {
            if let Ok(mut file) = File::create("output.txt") {
                writeln!(
                    &mut file,
                    "Number of detected open ports: {}",
                    results.len()
                )
                .unwrap();
                for addr in &results {
                    if let Err(e) = writeln!(&mut file, "{:?}", addr) {
                        eprintln!("Couldn't write to file: {}", e);
                        return;
                    }
                }
                writeln!(
                    &mut file,
                    "\nNumber of detected open ports: {}",
                    results.len()
                )
                .unwrap();
                println!("File output.txt is generated in the project path.");
            } else {
                eprintln!("Unable to create output.txt file.");
                return;
            }
        }
        "csv" => {
            if let Ok(file) = File::create("output.csv") {
                let mut csv_writer = WriterBuilder::new().from_writer(file);

                // Writing column names
                csv_writer.write_record(&["ip", "port"]).unwrap();

                // Writing IP addresses and ports
                for addr in &results {
                    let ip = addr.ip();
                    let port = addr.port();
                    if let Err(e) = csv_writer.serialize((&ip.to_string(), port)) {
                        eprintln!("Couldn't write to file: {}", e);
                        return;
                    }
                }

                csv_writer.flush().unwrap();
                println!("File output.csv is generated in the project path.");
            } else {
                eprintln!("Unable to create output.csv file.");
                return;
            }
        }
        "json" => {
            let json_output: Vec<_> = results
                .iter()
                .map(|addr| {
                    let ip = addr.ip().to_string();
                    let port = addr.port();
                    json!({
                        "ip": ip,
                        "port": port,
                        "status": "open"
                    })
                })
                .collect();

            if let Ok(mut file) = File::create("output.json") {
                if let Err(e) = writeln!(&mut file, "{}", to_string_pretty(&json_output).unwrap()) {
                    eprintln!("Couldn't write to file: {}", e);
                    return;
                }
                println!("File output.json is generated in the project path.");
            } else {
                eprintln!("Unable to create output.json file.");
                return;
            }
        }
        _ => {
            println!("  >>>>>>>>>>>>> Number of detects: {:?}", results.len());
        }
    };
    //---------------------------------------------------------------------------//


    
    let elapsed = start_time.elapsed();
    println!("  >>>>>>>>>>>>> Elapsed time: {:?} \n\n\n", elapsed);
    
}
