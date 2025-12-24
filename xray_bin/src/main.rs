mod logger;

use crate::logger::LoggerType;
use clap::{Arg, ArgMatches, Command};
use std::fs::read_to_string;
use xray_lib::ContextPlatform;

const DEFAULT_CONFIG_PATH: &str = "config.json";

fn main() {
    let matches = Command::default()
        .subcommands([
            Command::new("version").about("Show current version"),
            Command::new("run")
                .about("Run application with config, the default command")
                .arg(Arg::new("config").short('c').help("config file path"))
                .arg(Arg::new("verbose").short('v').help("verbose log")), // .arg(Arg::new("link").short('l').help("config link")),
        ])
        .get_matches();

    let sub_command = matches.subcommand();
    match sub_command {
        Some(("version", _)) => {
            println!("xray core rust version is {}", xray_lib::version::VERSION);
        }
        Some(("run", matches)) => {
            command_run(matches);
        }
        _ => {
            run(DEFAULT_CONFIG_PATH.to_string(), false);
        }
    }
}

fn command_run(matches: &ArgMatches) {
    // let config_link = matches.get_one::<String>("link");
    // match config_link {
    //     None => {}
    //     Some(config_link) => {
    //         let config = parse_url(config_link.clone());
    //         match config {
    //             None => {
    //                 println!("can not parse config link '{}'", config_link)
    //             }
    //             Some(config) => {
    //                 println!("config: '{}'", config.to_json_string().unwrap());
    //                 run_config(config.to_json_string().unwrap())
    //             }
    //         }
    //         return;
    //     }
    // }
    let is_verbose = matches.get_one::<bool>("verbose").unwrap_or(&false).clone();
    let config_path = matches.get_one::<String>("config");
    let config_path = match config_path {
        None => DEFAULT_CONFIG_PATH.to_string(),
        Some(config_path) => config_path.clone(),
    };
    run(config_path.clone(), is_verbose);
}

fn run(config_path: String, is_verbose: bool) {
    let config = read_to_string(&config_path);

    match config {
        Ok(config) => {
            run_config(config, is_verbose);
        }
        Err(_) => {
            println!("can not open the config path in '{}'", config_path)
        }
    }
}

fn run_config(config: String, is_verbose: bool) {
    ctrlc::set_handler(move || {
        xray_lib::shutdown(1);
    })
    .unwrap();

    match is_verbose {
        true => {
            logger::init(LoggerType::VERBOSE);
        }
        false => {
            logger::init(LoggerType::SIMPLE);
        }
    }

    xray_lib::start(1, config, Some(Box::new(WindowsPlatform {})));
}

struct WindowsPlatform {}

impl ContextPlatform for WindowsPlatform {
    fn android_protect_fd(&self, _id: u64) {}

    fn can_accept(&self) -> bool {
        true
    }
}
