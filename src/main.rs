use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use clap::Parser;
use etherparse::{InternetSlice::{Ipv4, Ipv6}, SlicedPacket, TransportSlice::Tcp};
use pcap::{Capture, Device};
use prometheus::{Encoder, IntCounterVec, Opts, Registry, TextEncoder, core::{MetricVec, MetricVecBuilder}};
use tower_http::services::ServeFile;
use tokio;

// About 10 MBs
const CAPTURE_BUFFER_SIZE_BYTES: i32 = 10000000;
const HTML_DIR: &str = "html";
const METRICS_DIR: &str = "metrics";
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

    #[arg(long, default_value_t = ("127.0.0.1").to_string())]
    host: String,

    #[arg(short, long, default_value_t = 8000)]
    port: u16,
}

#[derive(Clone, Debug)]
struct ExporterOptions {
    device: Device,
    bpf: Option<String>,
    datadir: PathBuf,
}

#[derive(Clone, Debug)]
struct WebappOptions {
    host: String,
    port: u16,
    datadir: PathBuf,
}

impl WebappOptions {
    fn get_host_port(&self) -> String {
        self.host.clone() + ":" + &self.port.to_string()
    }
}

fn validate_cli_args(args: &CliOptions) -> Result<(ExporterOptions, WebappOptions), Box<dyn Error>> {
    // The error shouldn't trigger, because the case is handled by clap
    let iface = args.iface.as_ref().expect("iface argument must be specified");
    let devices = Device::list()?;

    let Some(device) = devices.iter().find(|device| device.name == *iface) else {
        return Err(format!("Interface {} not found. Use argument --list to display available interfaces.", iface).into());
    };

    let mut datadir = PathBuf::new();
    datadir.push(&args.datadir);

    Ok((
        ExporterOptions { device: device.clone(), bpf: args.filter.clone(), datadir: datadir.clone() },
        WebappOptions { host: args.host.clone(), port: args.port, datadir },
    ))
}

fn list_interfaces() -> Result<(), Box<dyn Error>> {
    let devices = Device::list()?;
    if devices.len() == 0 {
        println!("No available interfaces");
        return Ok(());
    }
    let interfaces_str = devices.into_iter().map(|device| device.name).collect::<Vec<_>>().join(" ");
    println!("Interfaces: {interfaces_str}");

    return Ok(());
}

fn get_counter<T: MetricVecBuilder>(generic_counter: &MetricVec<T>, src_ip: String, src_port: u16, dst_ip: String, dst_port: u16) -> T::M {
    let labels: HashMap<_, _> = [
        ("src_ip", src_ip),
        ("src_port", src_port.to_string()),
        ("dst_ip", dst_ip),
        ("dst_port", dst_port.to_string()),
    ].into_iter().collect();

    generic_counter.with(&labels)
}

struct Exporter<'a> {
    registry: Registry,
    ntm_bytes: IntCounterVec,
    datadir: &'a Path,
    metrics_update_interval_ms: u64,
}

fn get_curr_time() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

impl<'a> Exporter<'a> {
    fn new(datadir: &'a Path, metrics_update_interval_ms: u64) -> Self {
        let counter_opts = Opts::new("ntm_bytes", "packet bytes counter");
        let ntm_bytes_generic_counter = IntCounterVec::new(counter_opts, &["src_ip", "dst_ip", "src_port", "dst_port"]).unwrap();

        let registry = Registry::new();
        registry.register(Box::new(ntm_bytes_generic_counter.clone())).unwrap();

        Self {
            registry,
            ntm_bytes: ntm_bytes_generic_counter,
            datadir,
            metrics_update_interval_ms,
        }
    }

    fn write_metrics(&self) {
        // Serialize the measurements
        let metric_families = self.registry.gather();
        let encoder = TextEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&metric_families, &mut buf).unwrap();

        let metrics_path = self.datadir.join(HTML_DIR).join(METRICS_DIR);
        fs::create_dir_all(&metrics_path).unwrap();

        // Write the results in a temporary file
        let temp_path = metrics_path.join("index-temp.html");
        let mut file = File::create(&temp_path).unwrap();
        file.write_all(&buf).unwrap();

        // Move the file to the real location
        let real_path = metrics_path.join("index.html");
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

        let mut last_write_time = get_curr_time();
        // Subtract so we immediately force a write
        last_write_time -= Duration::from_millis(self.metrics_update_interval_ms);

        while let Ok(packet) = capture.next_packet() {
            if let Ok(val) = SlicedPacket::from_ethernet(packet.data) {
                // We only care about TCP packets
                let Some(Tcp(tcp)) = val.transport else {
                    continue;
                };

                // And only about ipv4 and ipv6
                let (src_ip, dst_ip) = match val.net {
                    Some(Ipv4(ip)) => {
                        let header = ip.header();
                        (header.source_addr().to_string(), header.destination_addr().to_string())
                    },
                    Some(Ipv6(ip)) => {
                        let header = ip.header();
                        (header.source_addr().to_string(), header.destination_addr().to_string())
                    },
                    _ => {
                        continue;
                    },
                };

                let cnt_bytes = get_counter(&self.ntm_bytes, src_ip, tcp.source_port(), dst_ip, tcp.destination_port());
                cnt_bytes.inc_by(tcp.payload().len() as u64);
            }

            let curr_time = get_curr_time();
            if curr_time - last_write_time > Duration::from_millis(self.metrics_update_interval_ms) {
                last_write_time = curr_time;

                self.write_metrics();
            }
        }

        Ok(())
    }
}

fn run_exporter(opts: &ExporterOptions) -> Result<(), Box<dyn Error>> {
    let exporter = Exporter::new(&opts.datadir, DEFAULT_METRICS_UPDATE_INTERVAL_MS);

    exporter.live_capture(&opts)?;

    Ok(())
}

async fn webapp(opts: WebappOptions) {
    let listener = tokio::net::TcpListener::bind(opts.get_host_port()).await.unwrap();

    let metrics_file = opts.datadir.join(HTML_DIR).join(METRICS_DIR).join("index.html");
    
    let app = Router::new().route_service("/metrics", ServeFile::new(metrics_file));

    axum::serve(listener, app).await.unwrap();
}

fn run_webapp(opts: WebappOptions) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        webapp(opts).await
    })

}

fn main() -> Result<(), Box<dyn Error>> {
    let args = CliOptions::parse();

    if args.list {
        list_interfaces()?;
        return Ok(());
    }

    let res = validate_cli_args(&args);
    let Ok((exporter_opts, webapp_opts)) = res else {
        return Err(res.unwrap_err().into());
    };

    println!("Listening on interface: {}", exporter_opts.device.name);
    println!("Data is stored at: {:?}", exporter_opts.datadir);
    println!("Webserver listening on: {}", webapp_opts.get_host_port());

    let exporter_thread = thread::spawn(move || {
        run_exporter(&exporter_opts);
    });
    let webapp_thread = thread::spawn(move || {
        run_webapp(webapp_opts);
    });

    exporter_thread.join();
    webapp_thread.join();

    Ok(())
}
