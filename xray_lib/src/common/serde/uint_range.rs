use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy)]
pub struct UIntRange {
    min: usize,
    max: Option<usize>,
}

impl UIntRange {
    pub fn new(min: usize, max: Option<usize>) -> Self {
        let max = match max {
            Some(max) => {
                if max < min { Some(min) } else { Some(max) }
            }
            None => Some(min),
        };
        Self { min, max }
    }

    pub fn random(&self) -> usize {
        match self.max {
            Some(max) => rand::thread_rng().gen_range(self.min..=max),
            None => self.min,
        }
    }

    pub fn min(&self) -> usize { self.min }

    pub fn max(&self) -> usize { self.max.unwrap_or(self.min) }
}

impl<'de> Deserialize<'de> for UIntRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        let mut parts = s.split(['-', ':', '_', ',']);
        let min = parts
            .next()
            .ok_or_else(|| serde::de::Error::custom("empty value"))?
            .trim()
            .parse()
            .map_err(serde::de::Error::custom)?;
        let max = match parts.next() {
            Some(s) if !s.trim().is_empty() => {
                Some(s.trim().parse().map_err(serde::de::Error::custom)?)
            }
            _ => None,
        };
        Ok(Self { min, max })
    }
}

impl Serialize for UIntRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match self.max {
            Some(max) => serializer.serialize_str(&format!("{}-{}", self.min, max)),
            None => serializer.serialize_str(&self.min.to_string()),
        }
    }
}
