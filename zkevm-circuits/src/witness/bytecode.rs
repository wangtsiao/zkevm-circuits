use std::collections::HashMap;

use bus_mapping::state_db::CodeDB;
use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::circuit::Value;
use itertools::Itertools;

use crate::{evm_circuit::util::rlc, table::BytecodeFieldTag, util::Challenges};

/// A collection of bytecode to prove
#[derive(Clone, Debug, Default)]
pub struct BytecodeCollection {
    codes: HashMap<Word, BytecodeUnroller>,
}

impl BytecodeCollection {
    /// Construct from codedb
    pub fn from_codedb(code_db: &CodeDB) -> Self {
        Self {
            codes: code_db
                .0
                .values()
                .map(|v| {
                    let bytecode = BytecodeUnroller::from(v.clone());
                    (bytecode.hash(), bytecode)
                })
                .collect(),
        }
    }

    /// Construct from raw bytes
    pub fn from_raw(bytecodes: Vec<Vec<u8>>) -> Self {
        Self {
            codes: HashMap::from_iter(bytecodes.iter().map(|bytecode| {
                let code = BytecodeUnroller::from(bytecode.clone());
                (code.hash(), code)
            })),
        }
    }

    /// Compute number of rows required for bytecode table.
    pub fn num_rows_required_for_bytecode_table(&self) -> usize {
        self.codes
            .values()
            .map(|bytecode| bytecode.table_len())
            .sum()
    }
    /// Query code by hash
    pub fn get(&self, codehash: &Word) -> Option<BytecodeUnroller> {
        self.codes.get(codehash).cloned()
    }

    /// Get raw bytes
    #[deprecated()]
    pub fn to_raw(&self) -> Vec<Vec<u8>> {
        self.codes.values().map(|code| code.code()).collect_vec()
    }
}

impl IntoIterator for BytecodeCollection {
    type Item = BytecodeUnroller;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.codes
            .values()
            .map(|x| x.clone())
            .collect_vec()
            .into_iter()
    }
}
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

    #[deprecated()]
    /// get byte value and is_code pair
    pub fn get(&self, dest: usize) -> Option<(u8, bool)> {
        self.b.code.get(dest).map(|b| (b.value, b.is_code))
    }

    #[deprecated()]
    /// The length of the bytecode
    pub fn codesize(&self) -> usize {
        self.b.code.len()
    }

    #[deprecated()]
    /// The length of the bytecode table
    pub fn table_len(&self) -> usize {
        self.b.code.len() + 1
    }

    #[deprecated()]
    /// The code hash
    pub fn hash(&self) -> Word {
        self.b.hash()
    }

    #[deprecated()]
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
            value: self.codesize().try_into().unwrap(),
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
