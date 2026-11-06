use crate::common::asset::get_asset_location;
use std::path::Path;

pub struct GeoPatternParser;

impl GeoPatternParser {
    /// Parse geo pattern like "geo:ir" or "geo:geosite.dat,us"
    /// Returns (file_path, code) or None if invalid
    pub fn parse_geo_pattern(pattern: &str, default_file: &str) -> Option<(String, String)> {
        if !pattern.starts_with("geo:") {
            return None;
        }

        let geo = pattern.replace("geo:", "").clone();
        let parts: Vec<&str> = geo.split(',').collect();

        if parts.is_empty() || parts.len() > 2 {
            return None;
        }

        let (file, code) = if parts.len() == 1 {
            (default_file, parts[0])
        } else {
            (parts[0], parts[1])
        };

        let path = if Path::new(file).is_relative() {
            get_asset_location(file).to_string_lossy().into_owned()
        } else {
            file.to_string()
        };

        Some((path, code.to_string()))
    }

    /// Parse geo:IP pattern (for IP-based geo matching)
    pub fn parse_geoip_pattern(pattern: &str) -> Option<(String, String)> {
        Self::parse_geo_pattern(pattern, "geoip.dat")
    }

    /// Parse geo:domain pattern (for domain-based geo matching)
    pub fn parse_geodomain_pattern(pattern: &str) -> Option<(String, String)> {
        Self::parse_geo_pattern(pattern, "geosite.dat")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_geoip_default() {
        let (file, code) = GeoPatternParser::parse_geoip_pattern("geo:ir").unwrap();
        assert!(file.contains("geoip.dat"));
        assert_eq!(code, "ir");
    }

    #[test]
    fn test_parse_geoip_custom() {
        let (file, code) = GeoPatternParser::parse_geoip_pattern("geo:custom.dat,us").unwrap();
        assert!(file.contains("custom.dat"));
        assert_eq!(code, "us");
    }

    #[test]
    fn test_parse_geodomain_default() {
        let (file, code) = GeoPatternParser::parse_geodomain_pattern("geo:ir").unwrap();
        assert!(file.contains("geosite.dat"));
        assert_eq!(code, "ir");
    }

    #[test]
    fn test_parse_geodomain_custom() {
        let (file, code) = GeoPatternParser::parse_geodomain_pattern("geo:geosite.dat,us").unwrap();
        assert!(file.contains("geosite.dat"));
        assert_eq!(code, "us");
    }

    #[test]
    fn test_parse_invalid() {
        assert!(GeoPatternParser::parse_geo_pattern("not_geo", "default.dat").is_none());
        assert!(GeoPatternParser::parse_geo_pattern("geo:", "default.dat").is_none());
    }
}
