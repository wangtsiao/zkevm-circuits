use std::marker::PhantomData;

use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::circuit::Value;
use itertools::Itertools;

use crate::{evm_circuit::util::rlc, table::BytecodeFieldTag, util::Challenges};

/// Bytecode
#[derive(Clone, Debug)]
pub struct BytecodeUnroller<F: Field> {
    /// We assume the is_code field is properly set.
    b: eth_types::Bytecode,
    _marker: PhantomData<F>,
}

impl<F: Field> BytecodeUnroller<F> {
    /// Assignments for bytecode table
    pub fn table_assignments(&self, challenges: &Challenges<Value<F>>) -> Vec<[Value<F>; 5]> {
        let hash = challenges
            .evm_word()
            .map(|challenge| rlc::value(&self.hash().to_le_bytes(), challenge));
        self.into_iter()
            .map(|row| {
                [
                    hash,
                    Value::known(row.index),
                    Value::known(row.tag),
                    Value::known(row.is_code),
                    Value::known(row.value),
                ]
            })
            .collect_vec()
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

impl<F: Field> From<&eth_types::bytecode::Bytecode> for BytecodeUnroller<F> {
    fn from(b: &eth_types::bytecode::Bytecode) -> Self {
        Self {
            b: b.clone(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field> From<Vec<u8>> for BytecodeUnroller<F> {
    fn from(b: Vec<u8>) -> Self {
        b.into()
    }
}

/// Public data for the bytecode
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BytecodeRow<F: Field> {
    pub(crate) code_hash: Word,
    pub(crate) tag: F,
    pub(crate) index: F,
    pub(crate) is_code: F,
    pub(crate) value: F,
}

impl<F: Field> IntoIterator for BytecodeUnroller<F> {
    type Item = BytecodeRow<F>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    /// We turn the bytecode in to the circuit row for Bytecode circuit or bytecode table to use.
    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(Self::Item {
            code_hash: self.hash(),
            tag: F::from(BytecodeFieldTag::Header as u64),
            index: F::ZERO,
            is_code: F::ZERO,
            value: F::from(self.code_length() as u64),
        })
        .chain(
            self.b
                .code
                .iter()
                .enumerate()
                .map(|(idx, code)| Self::Item {
                    code_hash: self.hash(),
                    tag: F::from(BytecodeFieldTag::Byte as u64),
                    index: F::from(idx as u64),
                    is_code: F::from(code.is_code.into()),
                    value: F::from(code.value.into()),
                }),
        )
        .collect_vec()
        .into_iter()
    }
}
