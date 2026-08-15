use std::fmt;

#[derive(Debug, Clone)]
pub struct UrlBuilder {
    scheme: Option<String>,
    host: String,
    port: Option<u16>,
    path_segments: Vec<String>,
    query_params: Vec<(String, String)>,
}

impl UrlBuilder {
    pub fn new() -> Self {
        Self {
            scheme: None,
            host: String::new(),
            port: None,
            path_segments: Vec::new(),
            query_params: Vec::new(),
        }
    }

    pub fn scheme(&mut self, scheme: &str) {
        if scheme.is_empty() {
            self.scheme = None;
        } else {
            self.scheme = Some(scheme.to_string());
        }
    }

    pub fn host(&mut self, host: &str) {
        self.host = host.to_string();
    }

    pub fn port(&mut self, port: u16) {
        self.port = Some(port);
    }

    pub fn path(&mut self, path: &str) {
        self.path_segments.clear();
        for seg in path.split('/') {
            if !seg.is_empty() {
                self.path_segments.push(seg.to_string());
            }
        }
    }

    pub fn append_path(&mut self, segment: &str) {
        for seg in segment.split('/') {
            if !seg.is_empty() {
                self.path_segments.push(seg.to_string());
            }
        }
    }

    pub fn query(&mut self, key: &str, value: &str) {
        self.query_params.push((key.to_string(), value.to_string()));
    }

    pub fn get_path(&self) -> String {
        if self.path_segments.is_empty() {
            return "/".to_string();
        }
        format!("/{}", self.path_segments.join("/"))
    }

    pub fn get_uri(&self) -> String {
        let path = self.get_path();
        if self.query_params.is_empty() {
            return path;
        }
        let query = self.build_query_string();
        format!("{}?{}", path, query)
    }

    pub fn get_host(&self) -> &str {
        &self.host
    }

    pub fn get_host_port(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.host, port),
            None => self.host.clone(),
        }
    }

    pub fn build(&self) -> String {
        let host_port = self.get_host_port();
        let path = self.get_path();
        let query = if self.query_params.is_empty() {
            String::new()
        } else {
            format!("?{}", self.build_query_string())
        };
        match &self.scheme {
            Some(scheme) => format!("{}://{}{}{}", scheme, host_port, path, query),
            None => {
                if host_port.is_empty() {
                    format!("{}{}", path, query)
                } else {
                    format!("{}{}{}", host_port, path, query)
                }
            }
        }
    }

    fn build_query_string(&self) -> String {
        self.query_params
            .iter()
            .map(|(k, v)| {
                if v.is_empty() { k.clone() } else { format!("{}={}", k, v) }
            })
            .collect::<Vec<_>>()
            .join("&")
    }
}

impl fmt::Display for UrlBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.build())
    }
}

impl Default for UrlBuilder {
    fn default() -> Self {
        Self::new()
    }
}
