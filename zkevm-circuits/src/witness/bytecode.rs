use std::collections::HashMap;

use bus_mapping::state_db::CodeDB;
use eth_types::{Bytecode, Field, ToLittleEndian, Word};
use halo2_proofs::circuit::Value;
use itertools::Itertools;

use crate::{evm_circuit::util::rlc, table::BytecodeFieldTag, util::Challenges};

/// A collection of bytecode to prove
#[derive(Clone, Debug, Default)]
pub struct BytecodeCollection {
    codes: HashMap<Word, Bytecode>,
}

impl BytecodeCollection {
    /// Construct from codedb
    pub fn from_codedb(code_db: &CodeDB) -> Self {
        Self {
            codes: code_db
                .0
                .values()
                .map(|v| {
                    let bytecode = Bytecode::from(v.clone());
                    (bytecode.hash(), bytecode)
                })
                .collect(),
        }
    }

    /// Construct from raw bytes
    pub fn from_raw(bytecodes: Vec<Vec<u8>>) -> Self {
        Self {
            codes: HashMap::from_iter(bytecodes.iter().map(|bytecode| {
                let code = Bytecode::from(bytecode.clone());
                (code.hash(), code)
            })),
        }
    }

    /// Compute number of rows required for bytecode table.
    pub fn num_rows_required_for_bytecode_table(&self) -> usize {
        self.codes
            .values()
            .map(|bytecode| bytecode.codesize() + 1)
            .sum()
    }
    /// Query code by hash
    pub fn get(&self, codehash: &Word) -> Option<Bytecode> {
        self.codes.get(codehash).cloned()
    }

    /// Get raw bytes
    #[deprecated()]
    pub fn to_raw(&self) -> Vec<Vec<u8>> {
        self.codes.values().map(|code| code.code()).collect_vec()
    }
}

impl IntoIterator for BytecodeCollection {
    type Item = Bytecode;
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
pub struct BytecodeUnroller<F: Field> {
    /// We assume the is_code field is properly set.
    bytecode: Bytecode,
    rows: Vec<BytecodeRow<F>>,
}

impl<F: Field> BytecodeUnroller<F> {
    fn to_rows(bytecode: &Bytecode) -> Vec<BytecodeRow<F>> {
        let code_hash = bytecode.hash();
        std::iter::once(BytecodeRow::head(code_hash, bytecode.codesize()))
            .chain(
                bytecode
                    .code_vec()
                    .iter()
                    .enumerate()
                    .map(|(index, &(byte, is_code))| {
                        BytecodeRow::body(code_hash, index, is_code, byte)
                    }),
            )
            .collect_vec()
    }

    /// Derive RLC value for code hash
    pub fn get_code_hash(&self, challenges: &Challenges<Value<F>>) -> Value<F> {
        challenges
            .evm_word()
            .map(|challenge| rlc::value(&self.bytecode.hash().to_le_bytes(), challenge))
    }

    #[deprecated()]
    /// get byte value and is_code pair
    pub fn get(&self, dest: usize) -> Option<(u8, bool)> {
        self.bytecode.get(dest)
    }

    #[deprecated()]
    /// The length of the bytecode
    pub fn codesize(&self) -> usize {
        self.bytecode.codesize()
    }

    /// The length of the bytecode table
    pub fn table_len(&self) -> usize {
        self.rows.len()
    }

    #[deprecated()]
    /// The code hash
    pub fn hash(&self) -> Word {
        self.bytecode.hash()
    }

    #[deprecated()]
    /// The code in bytes
    pub fn code(&self) -> Vec<u8> {
        self.bytecode.code()
    }
}

impl<F: Field> From<&Bytecode> for BytecodeUnroller<F> {
    fn from(bytecode: &Bytecode) -> Self {
        Self {
            bytecode: bytecode.clone(),
            rows: Self::to_rows(bytecode),
        }
    }
}

impl<F: Field> From<Vec<u8>> for BytecodeUnroller<F> {
    fn from(b: Vec<u8>) -> Self {
        b.into()
    }
}

impl<F: Field> IntoIterator for BytecodeUnroller<F> {
    type Item = BytecodeRow<F>;

    type IntoIter = std::vec::IntoIter<BytecodeRow<F>>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

/// Public data for the bytecode
#[derive(Clone, Debug, PartialEq)]
pub struct BytecodeRow<F: Field> {
    /// We don't assign it now
    code_hash: Word,
    pub tag: F,
    pub index: F,
    pub is_code: F,
    pub value: F,
}

impl<F: Field> BytecodeRow<F> {
    pub fn head(code_hash: Word, code_size: usize) -> Self {
        Self {
            code_hash,
            tag: F::from(BytecodeFieldTag::Header as u64),
            index: F::ZERO,
            is_code: F::ZERO,
            value: F::from(code_size as u64),
        }
    }
    pub fn body(code_hash: Word, index: usize, is_code: bool, value: u8) -> Self {
        Self {
            code_hash,
            tag: F::from(BytecodeFieldTag::Byte as u64),
            index: F::from(index as u64),
            is_code: F::from(is_code.into()),
            value: F::from(value.into()),
        }
    }
}
