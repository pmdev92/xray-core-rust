#![feature(decl_macro)]
#![allow(warnings)]

use crate::config::config::Config;
use crate::config::log::LogConfig;
use crate::config::stats::StatsConfig;
use crate::core::context::Context;
use crate::core::dispatcher::Dispatcher;
use crate::core::inbound::InboundTcp;
use crate::core::sniffer::SnifferProtocol;
use crate::core::statistics_manager::{StatisticsManager, StatisticsResult};
use crate::inbound::socks::Socks5Inbound;
use futures::executor::block_on;
use futures_util::future::select_ok;
use lazy_static::lazy_static;
use log::{error, info, warn};
use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;

mod common;
mod config;
mod core;
mod inbound;
mod outbound;
mod protos;
mod security;
mod stream;
mod transport;
pub mod version;

type Runner = futures::future::BoxFuture<'static, ()>;

lazy_static! {
    static ref RUNTIME_MANAGER: Mutex<HashMap<u32, RuntimeSession>> = Mutex::new(HashMap::new());
}
struct RuntimeSession {
    sender: Arc<mpsc::Sender<()>>,
    context: Arc<Context>,
}

pub fn start(id: u32, config_json: String, platform: Option<Box<dyn ContextPlatform>>) -> bool {
    let result = config::parse_config_json(config_json);
    let config = match result {
        Ok(config) => config,
        Err(err) => {
            error!("{}", err.to_string());
            return false;
        }
    };

    let context = create_context(&config, platform);
    let context = match context {
        None => {
            return false;
        }
        Some(context) => context,
    };
    let context_clone = context.clone();

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(32);
    let shutdown_tx = Arc::new(shutdown_tx);
    {
        let mut runtime_manager = match RUNTIME_MANAGER.lock() {
            Ok(runtime_manager) => runtime_manager,
            Err(_) => {
                return false;
            }
        };
        let session = RuntimeSession {
            sender: shutdown_tx.clone(),
            context: context_clone,
        };
        runtime_manager.insert(id, session);
    }

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let runtime = match result {
        Ok(runtime) => runtime,
        Err(_) => {
            return false;
        }
    };
    let context_clone = context.clone();
    runtime.block_on(async move {
        tokio::select! {
            _ = start_core(config, context_clone) => {
                info!("finished, exiting runtime");
            }

            _ = shutdown_rx.recv() => {
                info!("shutting down runtime");
            }
        }
        context.destroy().await
    });
    drop(runtime);
    true
}

pub fn shutdown(id: u32) -> bool {
    let mut runtime_manager = match RUNTIME_MANAGER.lock() {
        Ok(runtime_manager) => runtime_manager,
        Err(_) => {
            return false;
        }
    };

    let session = match runtime_manager.remove(&id) {
        Some(value) => value,
        None => {
            return false;
        }
    };
    match session.sender.blocking_send(()) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn statistics(id: u32) -> Option<StatisticsResult> {
    let runtime_manager = match RUNTIME_MANAGER.lock() {
        Ok(runtime_manager) => runtime_manager,
        Err(_) => {
            return None;
        }
    };

    let session = match runtime_manager.get(&id) {
        Some(value) => value.clone(),
        None => {
            return None;
        }
    };
    let context_clone = session.context.clone();
    let statistics_manager = context_clone.get_dispatcher().get_statistics_manager();
    match statistics_manager {
        None => None,
        Some(statistics_manager) => statistics_manager.get_statistics(),
    }
}

async fn start_core(config: Config, context: Arc<Context>) {
    let inbounds = config.build_inbounds().unwrap();
    let mut results: Vec<JoinHandle<()>> = vec![];
    for inbound in inbounds {
        let clone = context.clone();
        let result = tokio::spawn(async move {
            let result = inbound.start(clone).await;
            match result {
                Ok(_) => {}
                Err(e) => {
                    error!("inbound error: {}", e);
                    return;
                }
            }
        });
        results.push(result);
    }
    let _ = select_ok(results).await;
    // let _ = result.await;
}

fn create_context(
    config: &Config,
    platform: Option<Box<dyn ContextPlatform>>,
) -> Option<Arc<Context>> {
    let stats_enable = config
        .stats
        .clone()
        .unwrap_or(StatsConfig::default())
        .enable;
    let log = config.log.clone().unwrap_or(LogConfig::default());
    match log.level.unwrap_or("trace".to_string()).as_str() {
        "none" => {
            log::set_max_level(log::LevelFilter::Off);
        }
        "trace" => {
            log::set_max_level(log::LevelFilter::Trace);
        }
        "debug" => {
            log::set_max_level(log::LevelFilter::Debug);
        }
        "info" => {
            log::set_max_level(log::LevelFilter::Info);
        }
        "warn" => {
            log::set_max_level(log::LevelFilter::Warn);
        }
        "error" => {
            log::set_max_level(log::LevelFilter::Error);
        }
        _ => {
            log::set_max_level(log::LevelFilter::Trace);
        }
    }

    let outbounds = config.build_outbounds();
    let router = config.build_router();

    let outbounds = match outbounds {
        Ok(outbounds) => outbounds,
        Err(err) => {
            error!("build outbounds error: {}", err);
            return None;
        }
    };

    let router = match router {
        Ok(router) => router,
        Err(err) => {
            error!("build router error: {}", err);
            return None;
        }
    };

    let dispatcher = Dispatcher::new(stats_enable, outbounds, router);

    let dispatcher = match dispatcher {
        Ok(dispatcher) => dispatcher,
        Err(err) => {
            error!("create dispatcher error: {}", err);
            return None;
        }
    };

    Some(Arc::new(Context::new(&config.memory, dispatcher, platform)))
}

pub trait ContextPlatform: Send + Sync {
    fn android_protect_fd(&self, id: u64);
    fn can_accept(&self) -> bool;
}
