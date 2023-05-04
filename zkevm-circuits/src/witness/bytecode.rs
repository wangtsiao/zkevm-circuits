use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::circuit::Value;

use crate::{evm_circuit::util::rlc, table::BytecodeFieldTag, util::Challenges};

/// Bytecode
#[derive(Clone, Debug)]
pub struct Bytecode {
    /// We assume the is_code field is properly set.
    b: eth_types::Bytecode,
}

impl Bytecode {
    /// Assignments for bytecode table
    pub fn table_assignments<F: Field>(
        &self,
        challenges: &Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 5]> {
        let len = self.b.code.len();
        // the +1 is for the header
        let mut rows = Vec::with_capacity(len + 1);
        let hash = challenges
            .evm_word()
            .map(|challenge| rlc::value(&self.b.hash().to_le_bytes(), challenge));

        rows.push([
            hash,
            Value::known(F::from(BytecodeFieldTag::Header as u64)),
            Value::known(F::ZERO),
            Value::known(F::ZERO),
            Value::known(F::from(len as u64)),
        ]);
        for (idx, byte) in self.b.code.iter().enumerate() {
            rows.push([
                hash,
                Value::known(F::from(BytecodeFieldTag::Byte as u64)),
                Value::known(F::from(idx as u64)),
                Value::known(F::from(byte.is_code.into())),
                Value::known(F::from(byte.value.into())),
            ])
        }
        rows
    }

    /// get byte value and is_code pair
    pub fn get(&self, dest: usize) -> [u8; 2] {
        self.b
            .code
            .get(dest)
            .map(|b| [b.value, b.is_code.into()])
            .expect("byte can be found")
    }

    /// The length of the bytecode
    pub fn code_length(&self) -> usize {
        self.b.code.len()
    }

    /// The code hash
    pub fn hash(&self) -> Word {
        self.b.hash()
    }

    /// The code in bytes
    pub fn code(&self) -> Vec<u8> {
        self.b.code()
    }
}

impl From<&eth_types::bytecode::Bytecode> for Bytecode {
    fn from(b: &eth_types::bytecode::Bytecode) -> Self {
        Bytecode { b: b.clone() }
    }
}

impl From<Vec<u8>> for Bytecode {
    fn from(b: Vec<u8>) -> Self {
        b.into()
    }
}
