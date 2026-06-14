use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CompactSize {
    pub value: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BitcoinError {
    InsufficientBytes,
    InvalidFormat,
}

impl CompactSize {
    pub fn new(value: u64) -> Self {
        CompactSize { value }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self.value {
            0..=0xFC => vec![self.value as u8],
            0xFD..=0xFFFF => {
                let mut bytes = vec![0xFD];
                bytes.extend_from_slice(&(self.value as u16).to_le_bytes());
                bytes
            }
            0x1_0000..=0xFFFF_FFFF => {
                let mut bytes = vec![0xFE];
                bytes.extend_from_slice(&(self.value as u32).to_le_bytes());
                bytes
            }
            _ => {
                let mut bytes = vec![0xFF];
                bytes.extend_from_slice(&self.value.to_le_bytes());
                bytes
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let first = *bytes.first().ok_or(BitcoinError::InsufficientBytes)?;

        match first {
            0xFD => {
                if bytes.len() < 3 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u16::from_le_bytes([bytes[1], bytes[2]]) as u64;
                Ok((CompactSize::new(value), 3))
            }
            0xFE => {
                if bytes.len() < 5 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
                Ok((CompactSize::new(value), 5))
            }
            0xFF => {
                if bytes.len() < 9 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[1..9]);
                Ok((CompactSize::new(u64::from_le_bytes(buf)), 9))
            }
            n => Ok((CompactSize::new(n as u64), 1)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Txid(pub [u8; 32]);

impl Serialize for Txid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Txid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("txid must be 32 bytes"))?;
        Ok(Txid(arr))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        OutPoint {
            txid: Txid(txid),
            vout,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(36);
        bytes.extend_from_slice(&self.txid.0);
        bytes.extend_from_slice(&self.vout.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if bytes.len() < 36 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes[0..32]);
        let vout = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
        Ok((OutPoint::new(txid, vout), 36))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    pub fn new(bytes: Vec<u8>) -> Self {
        Script { bytes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = CompactSize::new(self.bytes.len() as u64).to_bytes();
        out.extend_from_slice(&self.bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let (len, prefix_len) = CompactSize::from_bytes(bytes)?;
        let len = len.value as usize;
        let end = prefix_len + len;
        if bytes.len() < end {
            return Err(BitcoinError::InsufficientBytes);
        }
        let script = Script::new(bytes[prefix_len..end].to_vec());
        Ok((script, end))
    }
}

impl Deref for Script {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

impl TransactionInput {
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        TransactionInput {
            previous_output,
            script_sig,
            sequence,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.previous_output.to_bytes();
        bytes.extend_from_slice(&self.script_sig.to_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let (previous_output, op_len) = OutPoint::from_bytes(bytes)?;
        let (script_sig, script_len) = Script::from_bytes(&bytes[op_len..])?;
        let offset = op_len + script_len;

        if bytes.len() < offset + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let sequence = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);

        Ok((
            TransactionInput::new(previous_output, script_sig, sequence),
            offset + 4,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub version: u32,
    pub inputs: Vec<TransactionInput>,
    pub lock_time: u32,
}

impl BitcoinTransaction {
    pub fn new(version: u32, inputs: Vec<TransactionInput>, lock_time: u32) -> Self {
        BitcoinTransaction {
            version,
            inputs,
            lock_time,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&CompactSize::new(self.inputs.len() as u64).to_bytes());
        for input in &self.inputs {
            bytes.extend_from_slice(&input.to_bytes());
        }
        bytes.extend_from_slice(&self.lock_time.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if bytes.len() < 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut offset = 4;

        let (count, count_len) = CompactSize::from_bytes(&bytes[offset..])?;
        offset += count_len;

        let mut inputs = Vec::with_capacity(count.value as usize);
        for _ in 0..count.value {
            let (input, input_len) = TransactionInput::from_bytes(&bytes[offset..])?;
            offset += input_len;
            inputs.push(input);
        }

        if bytes.len() < offset + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let lock_time = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        Ok((BitcoinTransaction::new(version, inputs, lock_time), offset))
    }
}

impl fmt::Display for BitcoinTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Version: {}", self.version)?;
        writeln!(f, "Inputs: {}", self.inputs.len())?;
        for (i, input) in self.inputs.iter().enumerate() {
            writeln!(f, "Input {}:", i)?;
            writeln!(
                f,
                "  Previous Output Txid: {}",
                hex::encode(input.previous_output.txid.0)
            )?;
            writeln!(f, "  Previous Output Vout: {}", input.previous_output.vout)?;
            writeln!(f, "  ScriptSig Length: {}", input.script_sig.bytes.len())?;
            writeln!(
                f,
                "  ScriptSig Bytes: {}",
                hex::encode(&input.script_sig.bytes)
            )?;
            writeln!(f, "  Sequence: {}", input.sequence)?;
        }
        writeln!(f, "Lock Time: {}", self.lock_time)
    }
}
