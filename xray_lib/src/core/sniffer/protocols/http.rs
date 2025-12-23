use crate::core::sniffer::{SniffProtocol, SniffResult, SnifferProtocol};

const HTTP_METHODS: [&str; 7] = ["get", "post", "head", "put", "delete", "options", "connect"];

pub struct Http {}

impl Http {
    fn is_begin_with_http_method(request: String) -> bool {
        for method in HTTP_METHODS.into_iter() {
            let result = request.to_lowercase().starts_with(method);
            if result {
                return true;
            }
        }
        return false;
    }
}

impl SnifferProtocol for Http {
    fn sniff(data: &[u8]) -> (bool, Option<SniffResult>) {
        let request = String::from_utf8_lossy(&data).to_string();
        let is_begin_with_http_method = Http::is_begin_with_http_method(request.clone());
        if is_begin_with_http_method {
            for line in request.lines() {
                let parts: Vec<&str> = line.split(":").collect();
                if parts[0].to_lowercase() == "host" {
                    let result = SniffResult {
                        protocol: SniffProtocol::Http,
                        domains: vec![parts[1].trim().to_string()],
                    };
                    return (true, Some(result));
                }
            }
        }

        return (false, None);
    }
}
