use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::circuit::Value;
use itertools::Itertools;

use crate::{evm_circuit::util::rlc, table::BytecodeFieldTag, util::Challenges};

/// Bytecode
#[derive(Clone, Debug)]
pub struct BytecodeUnroller {
    /// We assume the is_code field is properly set.
    b: eth_types::Bytecode,
}

impl BytecodeUnroller {
    /// Assignments for bytecode table
    pub fn table_assignments<F: Field>(
        &self,
        challenges: &Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 5]> {
        let hash = challenges
            .evm_word()
            .map(|challenge| rlc::value(&self.hash().to_le_bytes(), challenge));
        self.clone()
            .into_iter()
            .map(|row| {
                [
                    hash,
                    Value::known(F::from(row.index as u64)),
                    Value::known(F::from(row.tag as u64)),
                    Value::known(F::from(row.is_code.into())),
                    Value::known(F::from(row.value)),
                ]
            })
            .collect_vec()
    }

    /// get byte value and is_code pair
    pub fn get(&self, dest: usize) -> Option<(u8, bool)> {
        self.b.code.get(dest).map(|b| (b.value, b.is_code))
    }

    /// The length of the bytecode
    pub fn code_size(&self) -> usize {
        self.b.code.len()
    }

    /// The length of the bytecode table
    pub fn table_len(&self) -> usize {
        self.b.code.len() + 1
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

impl From<&eth_types::bytecode::Bytecode> for BytecodeUnroller {
    fn from(b: &eth_types::bytecode::Bytecode) -> Self {
        Self { b: b.clone() }
    }
}

impl From<Vec<u8>> for BytecodeUnroller {
    fn from(b: Vec<u8>) -> Self {
        b.into()
    }
}

/// Public data for the bytecode
#[derive(Clone, Debug, PartialEq)]
pub struct BytecodeRow {
    pub code_hash: Word,
    pub tag: BytecodeFieldTag,
    pub index: usize,
    pub is_code: bool,
    pub value: u64,
}

impl IntoIterator for BytecodeUnroller {
    type Item = BytecodeRow;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    /// We turn the bytecode in to the circuit row for Bytecode circuit or bytecode table to use.
    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(Self::Item {
            code_hash: self.hash(),
            tag: BytecodeFieldTag::Header,
            index: 0,
            is_code: false,
            value: self.code_size().try_into().unwrap(),
        })
        .chain(
            self.b
                .code
                .iter()
                .enumerate()
                .map(|(index, code)| Self::Item {
                    code_hash: self.hash(),
                    tag: BytecodeFieldTag::Byte,
                    index,
                    is_code: code.is_code,
                    value: code.value.into(),
                }),
        )
        .collect_vec()
        .into_iter()
    }
}
