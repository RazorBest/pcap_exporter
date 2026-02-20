use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;

use clap::Parser;
use etherparse::{
    InternetSlice::{Ipv4, Ipv6},
    SlicedPacket,
    TransportSlice::Tcp,
};
use pcap::{Capture, Device};
use prometheus::{
    Encoder, IntCounterVec, Opts, Registry, TextEncoder,
    core::{MetricVec, MetricVecBuilder},
};

// About 10 MBs
const CAPTURE_BUFFER_SIZE_BYTES: i32 = 10000000;
const HTML_DIR: &str = "html";
const DEFAULT_DATADIR: &str = "./data";
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
}

#[derive(Clone, Debug)]
struct ExporterOptions {
    device: Device,
    bpf: Option<String>,
    datadir: PathBuf,
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

    Ok(ExporterOptions {
        device: device.clone(),
        bpf: args.filter.clone(),
        datadir: datadir,
    })
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
        }
    }

    fn write_metrics(&self) {
        let metric_families = self.registry.gather();
        let encoder = TextEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&metric_families, &mut buf).unwrap();

        let temp_path = self.datadir.join(HTML_DIR).join("index-temp.html");
        let mut file = File::create(&temp_path).unwrap();

        file.write_all(&buf).unwrap();

        let real_path = self.datadir.join(HTML_DIR).join("index.html");
        // This operation is atomic
        fs::rename(temp_path, real_path).unwrap();
    }

    fn live_capture(&self, opts: &ExporterOptions) -> Result<(), Box<dyn Error>> {
        let mut capture = Capture::from_device(opts.device.clone())?
            .promisc(true)
            .buffer_size(CAPTURE_BUFFER_SIZE_BYTES)
            .open()?;

        if let Some(bpf) = &opts.bpf {
            capture.filter(bpf, true)?;
        }

        let mut last_write = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        // Subtract so we immediately force a write
        last_write -= self.metrics_update_interval_ms;

        while let Ok(packet) = capture.next_packet() {
            println!("received packet!");
            if let Ok(val) = SlicedPacket::from_ethernet(packet.data) {
                let Some(Tcp(tcp)) = val.transport else {
                    continue;
                };

                let (src_ip, dst_ip) = match val.net {
                    Some(Ipv4(ip)) => {
                        let header = ip.header();
                        (
                            header.source_addr().to_string(),
                            header.destination_addr().to_string(),
                        )
                    }
                    Some(Ipv6(ip)) => {
                        let header = ip.header();
                        (
                            header.source_addr().to_string(),
                            header.destination_addr().to_string(),
                        )
                    }
                    _ => {
                        continue;
                    }
                };

                let cnt_bytes = get_counter(
                    &self.ntm_bytes,
                    src_ip,
                    tcp.source_port(),
                    dst_ip,
                    tcp.destination_port(),
                );
                cnt_bytes.inc_by(tcp.payload().len() as u64);
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
