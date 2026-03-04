use std::error::Error;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::unix::AsyncFd;

#[derive(Debug)]
pub struct InterceptorOptions {
    // TODO: use this field to restrict interception only for this port
    pub _iface: String,
    pub queue_num: u16,
}

pub struct Interceptor {
    queue: nfq::Queue,
    async_fd: AsyncFd<RawFd>,
}

impl Interceptor {
    fn new(opts: &InterceptorOptions) -> Result<Self, Box<dyn Error>> {
        let mut queue = nfq::Queue::open()?;
        queue.bind(opts.queue_num)?;
        queue.set_nonblocking(true);

        let async_fd = AsyncFd::new(queue.as_raw_fd())?;

        Ok(Self { queue, async_fd })
    }

    async fn get_next_msg(&mut self) -> Result<nfq::Message, Box<dyn Error>> {
        loop {
            let mut guard = self.async_fd.readable().await?;

            match self.queue.recv() {
                Ok(msg) => {
                    guard.clear_ready();
                    return Ok(msg);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    async fn verdict(&mut self, msg: nfq::Message) -> Result<(), Box<dyn Error>> {
        let mut guard = self.async_fd.writable().await?;

        match self.queue.verdict(msg) {
            Ok(msg) => {
                guard.clear_ready();
                Ok(msg)
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn live_intercept(&mut self, running: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
        let wait_spawner = async |running: Arc<AtomicBool>| {
            while running.load(Ordering::SeqCst) {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        };
        loop {
            let mut msg = tokio::select! {
                msg = self.get_next_msg() => {
                    msg
                },
                _ = tokio::spawn(wait_spawner(running.clone())) => {
                    return Ok(());
                },
            }?;

            msg.set_verdict(nfq::Verdict::Accept);

            tokio::select! {
                _ = self.verdict(msg) => (),
                _ = tokio::spawn(wait_spawner(running.clone())) => {
                    return Ok(());
                },
            };
        }
    }
}

pub async fn async_run_interceptor(
    opts: &InterceptorOptions,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    let mut interceptor = Interceptor::new(opts)?;

    interceptor.live_intercept(running).await
}

pub fn run_intercept_exporter(
    opts: &InterceptorOptions,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async_run_interceptor(opts, running))?;

    Ok(())
}
