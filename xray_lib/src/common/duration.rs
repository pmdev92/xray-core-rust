use std::io;
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use std::time::Duration;

pub fn parse_duration(s: &str) -> Result<Duration, io::Error> {
    let (value, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .ok_or(Error::new(InvalidData, "invalid interval"))?,
    );
    let value: u64 = value
        .parse()
        .map_err(|_| Error::new(InvalidData, "invalid value"))?;
    if value <= 0 {
        return Err(Error::new(InvalidData, "invalid value"));
    }
    match unit {
        "s" => Ok(Duration::from_secs(value)),
        "m" => Ok(Duration::from_secs(value * 60)),
        "h" => Ok(Duration::from_secs(value * 3600)),
        _ => Err(Error::new(InvalidData, "invalid unit")),
    }
}
