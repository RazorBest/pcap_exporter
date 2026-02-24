mod crypto;
mod mask;

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use clap::Parser;
use etherparse::{
    InternetSlice::{Ipv4, Ipv6},
    SlicedPacket,
    TransportSlice::Tcp,
};
use pcap::{Capture, Device, Savefile};
use prometheus::{
    Encoder, IntCounterVec, Opts, Registry, TextEncoder,
    core::{MetricVec, MetricVecBuilder},
};
use tower_http::services::ServeFile;

use crate::mask::{Ipv4PortMask, PortMask, Seed};

// About 10 MBs
const CAPTURE_BUFFER_SIZE_BYTES: i32 = 10000000;
const DEFAULT_DATADIR: &str = "./data";
const HTML_DIR: &str = "html";
const SEED_FILE: &str = "seed";
const PCAP_FILE: &str = "captured.pcap";
const DEFAULT_METRICS_UPDATE_INTERVAL_MS: u64 = 100;
const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8000;

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
    #[arg(short, long)]
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

    /// Store the captured packets in pcap files in the data directory
    #[arg(long, default_value_t = false)]
    dump_pcap: bool,

    /// Adds the constant LABEL=VALUE to all the metrics
    #[arg(long = "add-label", value_parser = parse_key_val_label)]
    extra_labels: Vec<(String, String)>,

    /// Local host to which the web server listens
    #[arg(long, default_value_t = DEFAULT_HOST.to_string())]
    host: String,

    /// Port to which the web server listens
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
}

fn parse_key_val_ip(s: &str) -> Result<(String, String), String> {
    let (k, v) = s.split_once('=').ok_or("expected IP1=IP2")?;
    Ok((k.to_string(), v.to_string()))
}

fn parse_key_val_label(s: &str) -> Result<(String, String), String> {
    let (k, v) = s.split_once('=').ok_or("expected LABEL=VALUE")?;
    Ok((k.to_string(), v.to_string()))
}

#[derive(Clone, Debug)]
struct ExporterOptions {
    device: Device,
    bpf: Option<String>,
    datadir: PathBuf,
    mask_ip_ports: bool,
    map_ips: HashMap<IpAddr, IpAddr>,
    dump_pcap: bool,
    extra_labels: Vec<(String, String)>,
}

fn validate_cli_args(
    args: &CliOptions,
) -> Result<(ExporterOptions, WebserverOptions), Box<dyn Error>> {
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

    Ok((
        ExporterOptions {
            device: device.clone(),
            bpf: args.filter.clone(),
            datadir: datadir.clone(),
            mask_ip_ports: args.mask_ip_ports,
            map_ips,
            dump_pcap: args.dump_pcap,
            extra_labels: args.extra_labels.clone(),
        },
        WebserverOptions {
            datadir,
            host: args.host.clone(),
            port: args.port,
        },
    ))
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

    fs::write(&seed_path, seed).unwrap();

    seed
}

fn get_time() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

fn list_interfaces() -> Result<(), Box<dyn Error>> {
    let devices = Device::list()?;
    if devices.is_empty() {
        println!("No available interfaces");
        return Ok(());
    }
    let interfaces_str = devices
        .into_iter()
        .map(|device| device.name)
        .collect::<Vec<_>>()
        .join(" ");
    println!("Interfaces: {interfaces_str}");

    Ok(())
}

fn get_counter<T: MetricVecBuilder>(
    generic_counter: &MetricVec<T>,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    extra_labels: &[(String, String)],
) -> T::M {
    let labels: HashMap<_, _> = [
        ("src_ip", src_ip),
        ("src_port", src_port.to_string()),
        ("dst_ip", dst_ip),
        ("dst_port", dst_port.to_string()),
    ]
    .into_iter()
    .chain(
        extra_labels
            .iter()
            .map(|(label, value)| (&label[..], value.clone())),
    )
    .collect();

    generic_counter.with(&labels)
}

fn get_capture_savefile<T: pcap::State + ?Sized + pcap::Activated>(
    capture: &Capture<T>,
    pcap_path: &Path,
) -> Result<Savefile, Box<dyn Error>> {
    {
        let res = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(pcap_path);

        match res {
            // Throw the error if it's not AlreadyExists
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
            _ => Ok(()),
        }?
    }

    Ok(capture.savefile_append(pcap_path)?)
}

struct Exporter<'a> {
    registry: Registry,
    ntm_bytes: IntCounterVec,
    datadir: &'a Path,
    metrics_update_interval_ms: u64,
}

impl<'a> Exporter<'a> {
    fn new(datadir: &'a Path, extra_labels: &[(String, String)]) -> Self {
        let counter_opts = Opts::new("ntm_bytes", "packet bytes counter");
        let ntm_bytes_labels: Vec<&str> = ["src_ip", "dst_ip", "src_port", "dst_port"]
            .into_iter()
            .chain(extra_labels.iter().map(|(key, _)| &key[..]))
            .collect();
        let ntm_bytes_generic_counter =
            IntCounterVec::new(counter_opts, &ntm_bytes_labels).unwrap();

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

    fn live_capture(
        &self,
        opts: &ExporterOptions,
        running: Arc<AtomicBool>,
    ) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(&opts.datadir).unwrap();

        let ipv4_mask = Ipv4PortMask::new(get_seed(opts));
        let port_mask = PortMask::new(get_seed(opts));
        let mut capture = Capture::from_device(opts.device.clone())?
            .immediate_mode(true)
            .promisc(true)
            .buffer_size(CAPTURE_BUFFER_SIZE_BYTES)
            .open()?;

        // ATTENTION: Apply the filter as soon as possible
        if let Some(bpf) = &opts.bpf {
            capture.filter(bpf, true)?;
        }

        let mut savefile = if opts.dump_pcap {
            let pcap_path = opts.datadir.join(PCAP_FILE);
            Some(get_capture_savefile(&capture, &pcap_path).unwrap())
        } else {
            None
        };

        let mut last_write = get_time();
        // Subtract to immediately force a write
        last_write -= Duration::from_millis(self.metrics_update_interval_ms);

        while let Ok(packet) = capture.next_packet() {
            // This part should be as fast as possible. It was triggered by the user requesting the
            // program to stop.
            if !running.load(Ordering::SeqCst) {
                if let Some(savefile) = &mut savefile {
                    let _ = savefile.flush();
                }
                break;
            }

            println!("received packet!");
            let Ok(val) = SlicedPacket::from_ethernet(packet.data) else {
                println!("Can't parse ethernet");
                continue;
            };
            let Some(Tcp(tcp)) = val.transport else {
                continue;
            };

            if let Some(savefile) = &mut savefile {
                savefile.write(&packet);
            }

            let (src_ip, src_port, dst_ip, dst_port) = match val.net {
                Some(Ipv4(ip)) => {
                    let src_port = tcp.source_port();
                    let dst_port = tcp.destination_port();

                    let header = ip.header();
                    if opts.mask_ip_ports {
                        let src_ip = header.source_addr();
                        let dst_ip = header.destination_addr();

                        let (mut masked_src_ip, mut masked_src_port) = (src_ip, src_port);
                        if let Some(IpAddr::V4(mapped_ip)) = opts.map_ips.get(&IpAddr::from(src_ip))
                        {
                            masked_src_ip = *mapped_ip;
                            if opts.mask_ip_ports {
                                masked_src_port = port_mask.apply(src_port);
                            }
                        } else if opts.mask_ip_ports {
                            (masked_src_ip, masked_src_port) = ipv4_mask.apply(src_ip, src_port);
                        }

                        let (mut masked_dst_ip, mut masked_dst_port) = (dst_ip, dst_port);
                        if let Some(IpAddr::V4(mapped_ip)) = opts.map_ips.get(&IpAddr::from(dst_ip))
                        {
                            masked_dst_ip = *mapped_ip;
                            if opts.mask_ip_ports {
                                masked_dst_port = port_mask.apply(dst_port);
                            }
                        } else if opts.mask_ip_ports {
                            (masked_dst_ip, masked_dst_port) = ipv4_mask.apply(dst_ip, dst_port);
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

            let cnt_bytes = get_counter(
                &self.ntm_bytes,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                &opts.extra_labels,
            );
            cnt_bytes.inc_by(tcp.payload().len() as u64);

            let curr_time = get_time();
            if curr_time - last_write >= Duration::from_millis(self.metrics_update_interval_ms) {
                self.write_metrics();
                last_write = curr_time;
            }
        }

        Ok(())
    }
}

fn run_exporter(opts: &ExporterOptions, running: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
    let exporter = Exporter::new(&opts.datadir, &opts.extra_labels);

    exporter.live_capture(opts, running)?;

    Ok(())
}

#[derive(Debug)]
struct WebserverOptions {
    host: String,
    port: u16,
    datadir: PathBuf,
}

impl WebserverOptions {
    fn get_host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

async fn async_webserver(opts: WebserverOptions, running: Arc<AtomicBool>) {
    let metrics_path = opts.datadir.join(HTML_DIR).join("index.html");
    let app = Router::new().route_service("/metrics", ServeFile::new(metrics_path));
    let listener = tokio::net::TcpListener::bind(opts.get_host_port())
        .await
        .unwrap();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(running))
        .await
        .unwrap();
}

async fn shutdown_signal(running: Arc<AtomicBool>) {
    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn run_webserver(opts: WebserverOptions, running: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async_webserver(opts, running));

    Ok(())
}

/// Adds a Ctrl+C handler that changes the "running" variable to false when the
/// signal is received. This variable can be shared by other parts of the code,
/// in order to handle exiting gracefully. The second Ctrl+C generates an exit.
fn set_ctrlc_handler(running: &Arc<AtomicBool>) {
    let state = Arc::new(AtomicUsize::new(0));
    let state_clone = state.clone();
    let running_clone = running.clone();

    ctrlc::set_handler(move || {
        let previous_state = state_clone.fetch_add(1, Ordering::SeqCst);

        if previous_state == 0 {
            println!("Initiating graceful shutdown... Press Ctrl+C again to force quit.");
        } else {
            println!("Force quit triggered. Exiting immediately.");
            std::process::exit(1); // Bypasses all Drop handlers and flushes
        }

        running_clone.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = CliOptions::parse();

    if args.list {
        list_interfaces()?;
        return Ok(());
    }

    let opts = validate_cli_args(&args);
    let Ok((exporter_opts, webserver_opts)) = opts else {
        return Err(opts.unwrap_err());
    };

    let running = Arc::new(AtomicBool::new(true));
    let exporter_running = running.clone();
    set_ctrlc_handler(&running);

    let exporter_thread = thread::spawn(move || {
        let _ = run_exporter(&exporter_opts, exporter_running);
    });
    let webserver_thread = thread::spawn(move || {
        let _ = run_webserver(webserver_opts, running);
    });

    let _ = exporter_thread.join();
    let _ = webserver_thread.join();

    Ok(())
}
