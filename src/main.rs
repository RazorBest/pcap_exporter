mod crypto;
mod mask;

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use etherparse::{
    InternetSlice::{Ipv4, Ipv6},
    SlicedPacket,
    TransportSlice::Tcp,
};
use getrandom;
use pcap::{Capture, Device};
use prometheus::{
    Encoder, IntCounterVec, Opts, Registry, TextEncoder,
    core::{MetricVec, MetricVecBuilder},
};

use crate::mask::{Ipv4PortMask, PortMask, Seed};

// About 10 MBs
const CAPTURE_BUFFER_SIZE_BYTES: i32 = 10000000;
const DEFAULT_DATADIR: &str = "./data";
const HTML_DIR: &str = "html";
const SEED_FILE: &str = ".seed";
const DEFAULT_METRICS_UPDATE_INTERVAL_MS: u64 = 100;

#[derive(Parser)]
#[command(name = "pcap_exporter")]
#[command(about = "CLI tool for turning packet captures into prometheus metrics")]
struct CliOptions {
    /// Network interface to listen to
    #[arg(short, long, required_unless_present = "list")]
    iface: Option<String>,

    /// List the avaiable interfaces
    #[arg(short, long, default_value_t = false)]
    list: bool,

    /// Barkley-Packet-Filter, similar to tcpdump
    filter: Option<String>,

    /// Directory for storing data across runs
    #[arg(long, default_value_t = DEFAULT_DATADIR.to_string())]
    datadir: String,

    /// If set to true, uniquely encrypt the (IP, port) tuples to another (IP, port) tuple.
    /// Same tuple always gets encrypted to the same tuple, between runs, as long as the data
    /// directory is preserved.
    #[arg(long, default_value_t = false)]
    mask_ip_ports: bool,

    /// Manually maps IP1 to IP2 before serializing them. These IPs skip the mask_ip_ports option.
    #[arg(long, value_parser = parse_key_val_ip)]
    map_ips: Vec<(String, String)>,
}

fn parse_key_val_ip(s: &str) -> Result<(String, String), String> {
    let (k, v) = s.split_once('=').ok_or("expected IP1=IP2")?;
    Ok((k.to_string(), v.to_string()))
}

#[derive(Clone, Debug)]
struct ExporterOptions {
    device: Device,
    bpf: Option<String>,
    datadir: PathBuf,
    mask_ip_ports: bool,
    map_ips: HashMap<IpAddr, IpAddr>,
}

fn validate_cli_args(args: &CliOptions) -> Result<ExporterOptions, Box<dyn Error>> {
    // The error shouldn't trigger, because the case is handled by clap
    let iface = args
        .iface
        .as_ref()
        .expect("iface argument must be specified");
    let devices = Device::list()?;

    let Some(device) = devices.iter().find(|device| device.name == *iface) else {
        return Err(format!(
            "Interface {} not found. Use argument --list to display available interfaces.",
            iface
        )
        .into());
    };

    let mut datadir = PathBuf::new();
    datadir.push(&args.datadir);

    let map_ips: HashMap<_, _> = args
        .map_ips
        .iter()
        .map(|(ip1, ip2)| {
            let parsed1 = IpAddr::from_str(ip1).map_err(|_| "IP parse error")?;
            let parsed2 = IpAddr::from_str(ip2).map_err(|_| "IP parse error")?;

            if parsed1.is_ipv4() && !parsed2.is_ipv4() || parsed1.is_ipv6() && !parsed2.is_ipv6() {
                return Err("New IP must be of the same type (IPv4/IPv6) as mapped ip");
            }

            Ok((parsed1, parsed2))
        })
        .collect::<Result<HashMap<_, _>, _>>()?;

    Ok(ExporterOptions {
        device: device.clone(),
        bpf: args.filter.clone(),
        datadir: datadir,
        mask_ip_ports: args.mask_ip_ports,
        map_ips: map_ips,
    })
}

fn get_seed(opts: &ExporterOptions) -> Seed {
    fs::create_dir_all(&opts.datadir).unwrap();
    let seed_path = opts.datadir.join(SEED_FILE);

    if let Ok(data) = fs::read(&seed_path) {
        return data
            .try_into()
            .expect("Seed read from file has wrong format");
    }

    let mut seed: Seed = [0u8; 64];
    getrandom::fill(&mut seed).unwrap();

    fs::write(&seed_path, &seed).unwrap();

    seed
}

fn get_time() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

fn list_interfaces() -> Result<(), Box<dyn Error>> {
    let devices = Device::list()?;
    if devices.len() == 0 {
        println!("No available interfaces");
        return Ok(());
    }
    let interfaces_str = devices
        .into_iter()
        .map(|device| device.name)
        .collect::<Vec<_>>()
        .join(" ");
    println!("Interfaces: {interfaces_str}");

    return Ok(());
}

fn get_counter<T: MetricVecBuilder>(
    generic_counter: &MetricVec<T>,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
) -> T::M {
    let labels: HashMap<_, _> = [
        ("src_ip", src_ip),
        ("src_port", src_port.to_string()),
        ("dst_ip", dst_ip),
        ("dst_port", dst_port.to_string()),
    ]
    .into_iter()
    .collect();

    generic_counter.with(&labels)
}

struct Exporter<'a> {
    registry: Registry,
    ntm_bytes: IntCounterVec,
    datadir: &'a Path,
    metrics_update_interval_ms: u64,
}

impl<'a> Exporter<'a> {
    fn new(datadir: &'a Path) -> Self {
        let counter_opts = Opts::new("ntm_bytes", "packet bytes counter");
        let ntm_bytes_generic_counter =
            IntCounterVec::new(counter_opts, &["src_ip", "dst_ip", "src_port", "dst_port"])
                .unwrap();

        let registry = Registry::new();
        registry
            .register(Box::new(ntm_bytes_generic_counter.clone()))
            .unwrap();

        Self {
            registry,
            ntm_bytes: ntm_bytes_generic_counter,
            datadir,
            metrics_update_interval_ms: DEFAULT_METRICS_UPDATE_INTERVAL_MS,
        }
    }

    fn write_metrics(&self) {
        let metric_families = self.registry.gather();
        let encoder = TextEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&metric_families, &mut buf).unwrap();

        fs::create_dir_all(self.datadir.join(HTML_DIR)).unwrap();

        let temp_path = self.datadir.join(HTML_DIR).join("index-temp.html");
        let mut file = File::create(&temp_path).unwrap();

        file.write_all(&buf).unwrap();

        let real_path = self.datadir.join(HTML_DIR).join("index.html");
        // This operation is atomic
        fs::rename(temp_path, real_path).unwrap();
    }

    fn live_capture(&self, opts: &ExporterOptions) -> Result<(), Box<dyn Error>> {
        let ipv4_mask = Ipv4PortMask::new(get_seed(opts));
        let port_mask = PortMask::new(get_seed(opts));
        let mut capture = Capture::from_device(opts.device.clone())?
            .immediate_mode(true)
            .promisc(true)
            .buffer_size(CAPTURE_BUFFER_SIZE_BYTES)
            .open()?;

        if let Some(bpf) = &opts.bpf {
            capture.filter(bpf, true)?;
        }

        let mut last_write = get_time();
        // Subtract so we immediately force a write
        last_write -= Duration::from_millis(self.metrics_update_interval_ms);

        println!("Starting capture");

        while let Ok(packet) = capture.next_packet() {
            println!("received packet!");
            if let Ok(val) = SlicedPacket::from_ethernet(packet.data) {
                let Some(Tcp(tcp)) = val.transport else {
                    continue;
                };

                let (src_ip, src_port, dst_ip, dst_port) = match val.net {
                    Some(Ipv4(ip)) => {
                        let src_port = tcp.source_port();
                        let dst_port = tcp.destination_port();

                        let header = ip.header();
                        if opts.mask_ip_ports {
                            let src_ip = header.source_addr();
                            let dst_ip = header.destination_addr();

                            let (mut masked_src_ip, mut masked_src_port) = (src_ip, src_port);
                            if let Some(IpAddr::V4(mapped_ip)) =
                                opts.map_ips.get(&IpAddr::from(src_ip))
                            {
                                masked_src_ip = *mapped_ip;
                                if opts.mask_ip_ports {
                                    masked_src_port = port_mask.apply(src_port);
                                }
                            } else if opts.mask_ip_ports {
                                (masked_src_ip, masked_src_port) =
                                    ipv4_mask.apply(src_ip, src_port);
                            }

                            let (mut masked_dst_ip, mut masked_dst_port) = (dst_ip, dst_port);
                            if let Some(IpAddr::V4(mapped_ip)) =
                                opts.map_ips.get(&IpAddr::from(dst_ip))
                            {
                                masked_dst_ip = *mapped_ip;
                                if opts.mask_ip_ports {
                                    masked_dst_port = port_mask.apply(dst_port);
                                }
                            } else if opts.mask_ip_ports {
                                (masked_dst_ip, masked_dst_port) =
                                    ipv4_mask.apply(dst_ip, dst_port);
                            }

                            (
                                masked_src_ip.to_string(),
                                masked_src_port,
                                masked_dst_ip.to_string(),
                                masked_dst_port,
                            )
                        } else {
                            (
                                header.source_addr().to_string(),
                                src_port,
                                header.destination_addr().to_string(),
                                dst_port,
                            )
                        }
                    }
                    Some(Ipv6(ip)) => {
                        let src_port = tcp.source_port();
                        let dst_port = tcp.destination_port();

                        let header = ip.header();
                        if opts.mask_ip_ports {
                            panic!("Mask not supported for IPv6");
                        }

                        (
                            header.source_addr().to_string(),
                            src_port,
                            header.destination_addr().to_string(),
                            dst_port,
                        )
                    }
                    _ => {
                        continue;
                    }
                };

                let cnt_bytes = get_counter(&self.ntm_bytes, src_ip, src_port, dst_ip, dst_port);
                cnt_bytes.inc_by(tcp.payload().len() as u64);

                let curr_time = get_time();
                if curr_time - last_write > Duration::from_millis(self.metrics_update_interval_ms) {
                    self.write_metrics();
                    last_write = curr_time;
                }
            }
        }

        Ok(())
    }
}

fn run_exporter(opts: &ExporterOptions) -> Result<(), Box<dyn Error>> {
    let exporter = Exporter::new(&opts.datadir);

    exporter.live_capture(&opts)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = CliOptions::parse();

    if args.list {
        list_interfaces()?;
        return Ok(());
    }

    let opts = validate_cli_args(&args);
    let Ok(opts) = opts else {
        return Err(opts.unwrap_err().into());
    };

    let exporter_thread = thread::spawn(move || {
        run_exporter(&opts);
    });
    exporter_thread.join();

    Ok(())
}
