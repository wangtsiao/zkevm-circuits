pub mod branch_init;
pub mod branch_key;
pub mod branch_rlc;
pub mod extension_node;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, VirtualCells},
    poly::Rotation,
};
use std::marker::PhantomData;

use super::{helpers::MPTConstraintBuilder, param::ARITY, MPTContext};
use crate::{
    circuit,
    circuit_tools::{DataTransition, RLCable},
    mpt_circuit::account_leaf::AccountLeaf,
    mpt_circuit::helpers::bytes_into_rlc,
    mpt_circuit::{helpers::contains_placeholder_leaf, storage_leaf::StorageLeaf},
    mpt_circuit::{
        helpers::{BranchChildInfo, BranchNodeInfo},
        param::{
            BRANCH_0_C_START, BRANCH_0_KEY_POS, BRANCH_0_S_START, BRANCH_ROWS_NUM, C_RLP_START,
            C_START, DRIFTED_POS, HASH_WIDTH, IS_BRANCH_C_PLACEHOLDER_POS,
            IS_BRANCH_S_PLACEHOLDER_POS, IS_EXT_LONG_EVEN_C16_POS, IS_EXT_LONG_EVEN_C1_POS,
            IS_EXT_LONG_ODD_C16_POS, IS_EXT_LONG_ODD_C1_POS, IS_EXT_SHORT_C16_POS,
            IS_EXT_SHORT_C1_POS, NIBBLES_COUNTER_POS, RLP_NUM, S_RLP_START, S_START,
        },
    },
    mpt_circuit::{param::RLP_HASH_VALUE, witness_row::MptWitnessRow},
    mpt_circuit::{MPTConfig, ProofValues},
};

/*
A branch occupies 19 rows:
BRANCH.IS_INIT
BRANCH.IS_CHILD 0
...
BRANCH.IS_CHILD 15
BRANCH.IS_EXTENSION_NODE_S
BRANCH.IS_EXTENSION_NODE_C

Example:

[1 0 1 0 248 241 0 248 241 0 1 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
[0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
[0 160 164 92 78 34 81 137 173 236 78 208 145 118 128 60 46 5 176 8 229 165 42 222 110 4 252 228 93 243 26 160 241 85 0 160 95 174 59 239 229 74 221 53 227 115 207 137 94 29 119 126 56 209 55 198 212 179 38 213 219 36 111 62 46 43 176 168 1]
[0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
[0 160 60 157 212 182 167 69 206 32 151 2 14 23 149 67 58 187 84 249 195 159 106 68 203 199 199 65 194 33 215 102 71 138 0 160 60 157 212 182 167 69 206 32 151 2 14 23 149 67 58 187 84 249 195 159 106 68 203 199 199 65 194 33 215 102 71 138 1]
[0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
[0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
[0 160 21 230 18 20 253 84 192 151 178 53 157 0 9 105 229 121 222 71 120 109 159 109 9 218 254 1 50 139 117 216 194 252 0 160 21 230 18 20 253 84 192 151 178 53 157 0 9 105 229 121 222 71 120 109 159 109 9 218 254 1 50 139 117 216 194 252 1]
[0 160 229 29 220 149 183 173 68 40 11 103 39 76 251 20 162 242 21 49 103 245 160 99 143 218 74 196 2 61 51 34 105 123 0 160 229 29 220 149 183 173 68 40 11 103 39 76 251 20 162 242 21 49 103 245 160 99 143 218 74 196 2 61 51 34 105 123 1]
[0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
[0 160 0 140 67 252 58 164 68 143 34 163 138 133 54 27 218 38 80 20 142 115 221 100 73 161 165 75 83 53 8 58 236 1 0 160 0 140 67 252 58 164 68 143 34 163 138 133 54 27 218 38 80 20 142 115 221 100 73 161 165 75 83 53 8 58 236 1 1]
[0 160 149 169 206 0 129 86 168 48 42 127 100 73 109 90 171 56 216 28 132 44 167 14 46 189 224 213 37 0 234 165 140 236 0 160 149 169 206 0 129 86 168 48 42 127 100 73 109 90 171 56 216 28 132 44 167 14 46 189 224 213 37 0 234 165 140 236 1]
[0 160 42 63 45 28 165 209 201 220 231 99 153 208 48 174 250 66 196 18 123 250 55 107 64 178 159 49 190 84 159 179 138 235 0 160 42 63 45 28 165 209 201 220 231 99 153 208 48 174 250 66 196 18 123 250 55 107 64 178 159 49 190 84 159 179 138 235 1]
[0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
[0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
[0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
[0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1]
[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 16]
[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 17]

Note that when `BRANCH.IS_CHILD` row presents a nil node, there is only one byte non-zero:
128 at `s_main.bytes[0] / c_main.bytes[0]`.
*/

#[derive(Default, Debug)]
pub(crate) struct Branch {
    pub(crate) is_branch_init: bool,
    pub(crate) is_branch_child: bool,
    pub(crate) is_last_branch_child: bool,
    pub(crate) node_index: u8,
    pub(crate) modified_index: u8,
    pub(crate) drifted_index: u8,
    pub(crate) is_extension_node_s: bool,
    pub(crate) is_extension_node_c: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct BranchCols<F> {
    pub(crate) is_init: Column<Advice>,
    pub(crate) is_child: Column<Advice>,
    pub(crate) is_last_child: Column<Advice>,
    pub(crate) node_index: Column<Advice>,
    pub(crate) is_modified: Column<Advice>, // whether this branch node is modified
    pub(crate) modified_index: Column<Advice>, // index of the modified node
    pub(crate) is_drifted: Column<Advice>,  // needed when leaf is turned into branch
    pub(crate) drifted_index: Column<Advice>, /* needed when leaf is turned into branch - first
                                             * nibble of
                                             * the key stored in a leaf (because the existing
                                             * leaf will
                                             * jump to this position in added branch) */
    pub(crate) is_extension_node_s: Column<Advice>, /* contains extension node key (s_advices)
                                                     * and hash of
                                                     * the branch (c_advices) */
    pub(crate) is_extension_node_c: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BranchCols<F> {
    pub(crate) fn new(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            is_init: meta.advice_column(),
            is_child: meta.advice_column(),
            is_last_child: meta.advice_column(),
            node_index: meta.advice_column(),
            is_modified: meta.advice_column(),
            modified_index: meta.advice_column(),
            is_drifted: meta.advice_column(),
            drifted_index: meta.advice_column(),
            is_extension_node_s: meta.advice_column(),
            is_extension_node_c: meta.advice_column(),
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BranchConfig<F> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BranchConfig<F> {
    pub fn configure(
        meta: &mut VirtualCells<'_, F>,
        cb: &mut MPTConstraintBuilder<F>,
        ctx: MPTContext<F>,
    ) -> Self {
        let position_cols = ctx.position_cols;
        let s_main = ctx.s_main;
        let c_main = ctx.c_main;
        let accs = ctx.accumulators;
        let branch = ctx.branch;
        let r = ctx.r.clone();

        circuit!([meta, cb.base], {
            let q_not_first = f!(position_cols.q_not_first);
            let drifted_index = DataTransition::new(meta, branch.drifted_index);
            let node_index = DataTransition::new(meta, branch.node_index);
            let modified_index = DataTransition::new(meta, branch.modified_index);
            let is_modified = DataTransition::new(meta, branch.is_modified);
            let is_branch_init = DataTransition::new(meta, branch.is_init);
            let is_branch_child = DataTransition::new(meta, branch.is_child);
            let is_last_child = DataTransition::new(meta, branch.is_last_child);
            let is_drifted = DataTransition::new(meta, branch.is_drifted);

            ifx! {f!(position_cols.q_enable) => {
                // These selectors are only stored in branch init rows
                ifx!{is_branch_init => {
                    let branch = BranchNodeInfo::new(meta, ctx.clone(), true, 0);
                    // Boolean checks
                    for selector in [branch.is_placeholder_s(), branch.is_placeholder_c(), branch.is_not_hashed_s(), branch.is_not_hashed_c()] {
                        require!(selector => bool);
                    }
                    // Update the nibble counter
                    ifx!{not!(branch.is_extension()) => {
                        let nibbles_counter_prev = ifx!{not!(branch.is_at_tree_top(meta)) => {
                            branch.nibbles_counter().prev()
                        }};
                        require!(branch.nibbles_counter() => nibbles_counter_prev + 1.expr());
                    }}
                }}
            }}

            ifx! {q_not_first => {
                ifx!{is_branch_child => {
                    // Keep track of how many branch bytes we've processed.
                    for is_s in [true, false] {
                        let child = BranchChildInfo::new(meta, ctx.clone(), is_s, 0);
                        // Get the number of bytes used by the current branch.
                        let num_bytes = child.num_bytes(meta);
                        // Fetch the number of bytes left from the previous row.
                        // TODO(Brecht): just store it in branch init in its own column.
                        let num_bytes_left = ifx!{is_branch_init.prev() => {
                            // Length of full branch
                            BranchNodeInfo::new(meta, ctx.clone(), is_s, -1).len(meta)
                        } elsex {
                            // Simply stored in rlp1 otherwise
                            a!(ctx.main(is_s).rlp1, -1)
                        }};
                        // Update number of bytes left
                        require!(a!(ctx.main(is_s).rlp1) => num_bytes_left - num_bytes.expr());
                        // In the final branch child `rlp1` needs to be 1 (because RLP length
                        // specifies also ValueNode which occupies 1 byte).
                        // TODO: ValueNode
                        ifx!{is_last_child => {
                            require!(a!(ctx.main(is_s).rlp1) => 1);
                        }}
                    }

                    // Check that `is_modified` is enabled for the correct branch child.
                    ifx!{is_modified => {
                        require!(node_index => modified_index);
                    }}
                    // Check that `is_drifted` is enabled for the correct branch child.
                    ifx!{is_drifted => {
                        require!(node_index => drifted_index);
                    }}

                    // Check values that need to remain the same for all branch children.
                    ifx!{a!(branch.node_index) => {
                        // `modified_index` needs to be the same for all branch children.
                        require!(modified_index => modified_index.prev());
                        // `drifted_index` needs to be the same for all branch children.
                        require!(drifted_index => drifted_index.prev());
                        for is_s in [true, false] {
                            // `mod_node_hash_rlc` the same for all branch children
                            let mod_node_hash_rlc = ctx.accumulators.mod_node_rlc(is_s);
                            require!(a!(mod_node_hash_rlc) => a!(mod_node_hash_rlc, -1));
                            // `contains_placeholder_leaf` the same for all branch children
                            require!(contains_placeholder_leaf(meta, ctx.clone(), is_s, 0)
                                => contains_placeholder_leaf(meta, ctx.clone(), is_s, -1));
                        }
                    }}

                    // If we have a branch child, we can only have branch child or branch init in the previous row.
                    require!(or::expr([is_branch_child.prev(), is_branch_init.prev()]) => true);
                    // When `node_index` != 0
                    ifx!{node_index => {
                        // `node_index` increases by 1 for each branch child.
                        require!(node_index => node_index.prev() + 1.expr());
                    }}

                    // We need to ensure that the only change in `S` and `C` proof occurs
                    // at `modified_index` so that only a single change can be done.
                    // We check `s_main.rlp = c_main.rlp` everywhere except at `modified_index`.
                    // (except rlp1, rlp1 is used to keep track of number of bytes processed).
                    let not_at_modification = node_index.expr() - modified_index.expr();
                    ifx!{not_at_modification => {
                        for (s_byte, c_byte) in s_main.rlp_bytes().iter().skip(1)
                            .zip(c_main.rlp_bytes().iter().skip(1))
                        {
                            require!(a!(s_byte) => a!(c_byte));
                        }
                    }}
                }}

                // Make sure `is_branch_child`, `node_index` and `is_last_child` are set correctly.
                ifx!{is_branch_init.prev() => {
                    // First child when previous row is a branch init row
                    require!(is_branch_child => true);
                    require!(node_index => 0);
                } elsex {
                    // When `is_branch_child` changes back to 0, previous `node_index` needs to be 15
                    // and previous `is_last_child` needs to be 1.
                    ifx!{is_branch_child.delta() => {
                        require!(node_index.prev() => 15);
                        require!(is_last_child.prev() => true);
                    }}
                }}

                ifx!{is_last_child => {
                    // Rotations could be avoided but we would need additional is_branch_placeholder column.
                    let mut branch = BranchNodeInfo::new(meta, ctx.clone(), true, -(ARITY as i32));

                    // `is_modified` needs to be set to 1 at exactly 1 branch child
                    let is_modified_values = (0..ARITY).map(|rot| a!(ctx.branch.is_modified, -(rot as i32))).collect::<Vec<_>>();
                    require!(sum::expr(&is_modified_values) => 1);

                    ifx!{branch.is_placeholder() => {
                        // `is_drifted` needs to be set to 1 at exactly 1 branch child
                        let is_drifted_values = (0..ARITY).map(|rot| a!(ctx.branch.is_drifted, -(rot as i32))).collect::<Vec<_>>();
                        require!(sum::expr(&is_drifted_values) => 1);
                    }}

                    // Check if the branch is in its parent.
                    // Extension node is handled in `extension_node.rs`.
                    ifx! {not!(branch.is_extension()) => {
                        branch.require_in_parent(meta, &mut cb.base);
                    }}

                    // - For a branch placeholder we do not have any constraints. However, in the parallel
                    // (regular) branch we have an additional constraint (besides `is_modified` row
                    // corresponding to `mod_nod_hash_rlc`) in this case: `is_drifted` `main.bytes` RLC
                    // is stored in the placeholder `mod_node_hash_rlc`. For example, if there is a placeholder
                    // branch in `S` proof, we have:
                    //   - c_mod_node_hash_rlc := `is_modified` `c_main.bytes RLC`
                    //   - s_mod_node_hash_rlc := `is_drifted` `c_main.bytes RLC`
                    // - When `S` branch is NOT a placeholder:
                    //   - s_mod_node_rlc := `is_modified` `s_main.bytes RLC`
                    // Run over all branch children
                    for rot in -(ARITY as i32)+1..=0 {
                        for is_s in [true, false] {
                            branch.set_is_s(is_s);
                            ifx!{branch.is_placeholder() => {
                                ifx!{a!(ctx.branch.is_drifted, rot) => {
                                    let branch_rlc = ctx.main(!is_s).bytes(meta, rot).rlc(&r);
                                    require!(a!(accs.mod_node_rlc(is_s), rot) => branch_rlc);
                                }}
                            } elsex {
                                ifx!{a!(ctx.branch.is_modified, rot) => {
                                    let branch_rlc = ctx.main(is_s).bytes(meta, rot).rlc(&r);
                                    require!(a!(accs.mod_node_rlc(is_s), rot) => branch_rlc);
                                }}
                            }}
                        }
                    }

                    // When in a placeholder branch, both branches are the same - the placeholder branch and its
                    // parallel counterpart, which is not a placeholder, but a regular branch (newly
                    // added branch). The regular branch has only two non-nil nodes,
                    // because the placeholder branch appears only when an existing
                    // leaf drifts down into a newly added branch. Besides an
                    // existing leaf, we have a leaf that was being added and that caused
                    // a new branch to be added. So we need to check that there are exactly two
                    // non-nil nodes (otherwise the attacker could add more
                    // new leaves at the same time). The non-nil nodes need to be at
                    // `is_modified` and `is_drifted`, elsewhere there have
                    // to be zeros.
                    for is_s in [true, false] {
                        // So many rotation is not optimal, but most of these rotations are used
                        // elsewhere, so it should not be much of an overhead.
                        // Alternative approach would be to have a column specifying
                        // whether there is a placeholder branch or not (we currently have this info
                        // only in branch init). Another alternative would be to have a column where we
                        // add `rlp2` value from the current row in each of the 16
                        // rows. Both alternative would require additional column.
                        let branch = BranchNodeInfo::new(meta, ctx.clone(), is_s, -(ARITY as i32));
                        ifx!{branch.is_placeholder() => {
                            let sum_rlp2 = (0..ARITY).into_iter().fold(0.expr(), |acc, idx| {
                                acc + a!(ctx.main(is_s).rlp2, -(idx as i32))
                            });
                            // There are constraints which ensure there is only 0 or 160 at rlp2 for
                            // branch children.
                            require!(sum_rlp2 => (RLP_HASH_VALUE as u64) * 2);
                        }}
                    }
                }}
            }}
        });

        BranchConfig {
            _marker: PhantomData,
        }
    }

    pub(crate) fn assign_branch_init(
        &self,
        region: &mut Region<'_, F>,
        witness: &[MptWitnessRow<F>],
        mpt_config: &MPTConfig<F>,
        pv: &mut ProofValues<F>,
        offset: usize,
    ) -> Result<(), Error> {
        let row = &witness[offset];

        pv.modified_node = row.get_byte(BRANCH_0_KEY_POS);
        pv.node_index = 0;
        pv.drifted_pos = row.get_byte(DRIFTED_POS);

        // Get the child that is being changed and convert it to words to enable
        // lookups:
        let mut s_hash = witness[offset + 1 + pv.modified_node as usize]
            .s_hash_bytes()
            .to_vec();
        let mut c_hash = witness[offset + 1 + pv.modified_node as usize]
            .c_hash_bytes()
            .to_vec();
        pv.s_mod_node_hash_rlc = bytes_into_rlc(&s_hash, mpt_config.randomness);
        pv.c_mod_node_hash_rlc = bytes_into_rlc(&c_hash, mpt_config.randomness);

        if row.get_byte(IS_BRANCH_S_PLACEHOLDER_POS) == 1 {
            // We put hash of a node that moved down to the added branch.
            // This is needed to check the hash of leaf_in_added_branch.
            s_hash = witness[offset + 1 + pv.drifted_pos as usize]
                .s_hash_bytes()
                .to_vec();
            pv.s_mod_node_hash_rlc = bytes_into_rlc(&s_hash, mpt_config.randomness);
            pv.is_branch_s_placeholder = true
        } else {
            pv.is_branch_s_placeholder = false
        }
        if row.get_byte(IS_BRANCH_C_PLACEHOLDER_POS) == 1 {
            c_hash = witness[offset + 1 + pv.drifted_pos as usize]
                .c_hash_bytes()
                .to_vec();
            pv.c_mod_node_hash_rlc = bytes_into_rlc(&c_hash, mpt_config.randomness);
            pv.is_branch_c_placeholder = true
        } else {
            pv.is_branch_c_placeholder = false
        }
        /*
        If no placeholder branch, we set `drifted_pos = modified_node`. This
        is needed just to make some other constraints (`s_mod_node_hash_rlc`
        and `c_mod_node_hash_rlc` correspond to the proper node) easier to write.
        */
        if row.get_byte(IS_BRANCH_S_PLACEHOLDER_POS) == 0
            && row.get_byte(IS_BRANCH_C_PLACEHOLDER_POS) == 0
        {
            pv.drifted_pos = pv.modified_node
        }

        let account_leaf = AccountLeaf::default();
        let storage_leaf = StorageLeaf::default();
        let branch = Branch {
            is_branch_init: true,
            ..Default::default()
        };

        row.assign(
            region,
            mpt_config,
            account_leaf,
            storage_leaf,
            branch,
            offset,
        )?;

        // reassign (it was assigned to 0 in assign_row) branch_acc and
        // branch_mult to proper values

        // Branch (length 83) with two bytes of RLP meta data
        // [248,81,128,128,...

        // Branch (length 340) with three bytes of RLP meta data
        // [249,1,81,128,16,...

        let s_len = [0, 1, 2].map(|i| row.get_byte(BRANCH_0_S_START + i) as u64);
        pv.acc_s = F::from(s_len[0]);
        pv.acc_mult_s = mpt_config.randomness;

        if s_len[0] == 249 {
            pv.acc_s += F::from(s_len[1]) * pv.acc_mult_s;
            pv.acc_mult_s *= mpt_config.randomness;
            pv.acc_s += F::from(s_len[2]) * pv.acc_mult_s;
            pv.acc_mult_s *= mpt_config.randomness;

            pv.rlp_len_rem_s = s_len[1] as i32 * 256 + s_len[2] as i32;
        } else if s_len[0] == 248 {
            pv.acc_s += F::from(s_len[1]) * pv.acc_mult_s;
            pv.acc_mult_s *= mpt_config.randomness;

            pv.rlp_len_rem_s = s_len[1] as i32;
        } else {
            pv.rlp_len_rem_s = s_len[0] as i32 - 192;
        }

        let c_len = [0, 1, 2].map(|i| row.get_byte(BRANCH_0_C_START + i) as u64);
        pv.acc_c = F::from(c_len[0]);
        pv.acc_mult_c = mpt_config.randomness;

        if c_len[0] == 249 {
            pv.acc_c += F::from(c_len[1]) * pv.acc_mult_c;
            pv.acc_mult_c *= mpt_config.randomness;
            pv.acc_c += F::from(c_len[2]) * pv.acc_mult_c;
            pv.acc_mult_c *= mpt_config.randomness;

            pv.rlp_len_rem_c = c_len[1] as i32 * 256 + c_len[2] as i32;
        } else if c_len[0] == 248 {
            pv.acc_c += F::from(c_len[1]) * pv.acc_mult_c;
            pv.acc_mult_c *= mpt_config.randomness;

            pv.rlp_len_rem_c = c_len[1] as i32;
        } else {
            pv.rlp_len_rem_c = c_len[0] as i32 - 192;
        }

        mpt_config.assign_acc(
            region,
            pv.acc_s,
            pv.acc_mult_s,
            pv.acc_c,
            pv.acc_mult_c,
            offset,
        )?;

        pv.is_even =
            row.get_byte(IS_EXT_LONG_EVEN_C16_POS) + row.get_byte(IS_EXT_LONG_EVEN_C1_POS) == 1;
        pv.is_odd = row.get_byte(IS_EXT_LONG_ODD_C16_POS)
            + row.get_byte(IS_EXT_LONG_ODD_C1_POS)
            + row.get_byte(IS_EXT_SHORT_C16_POS)
            + row.get_byte(IS_EXT_SHORT_C1_POS)
            == 1;
        pv.is_short = row.get_byte(IS_EXT_SHORT_C16_POS) + row.get_byte(IS_EXT_SHORT_C1_POS) == 1;
        pv.is_short_c1 = row.get_byte(IS_EXT_SHORT_C1_POS) == 1;
        pv.is_long = row.get_byte(IS_EXT_LONG_EVEN_C16_POS)
            + row.get_byte(IS_EXT_LONG_EVEN_C1_POS)
            + row.get_byte(IS_EXT_LONG_ODD_C16_POS)
            + row.get_byte(IS_EXT_LONG_ODD_C1_POS)
            == 1;
        pv.is_extension_node = pv.is_even || pv.is_odd;

        // Assign how many nibbles have been used in the previous extension node +
        // branch.
        pv.nibbles_num += 1; // one nibble is used for position in branch
        if pv.is_extension_node {
            // Get into extension node S
            let row_ext = &witness[offset + BRANCH_ROWS_NUM as usize - 2];
            let ext_nibbles: usize;
            if row_ext.get_byte(1) <= 32 {
                ext_nibbles = 1
            } else if row_ext.get_byte(0) < 248 {
                if row_ext.get_byte(2) == 0 {
                    // even number of nibbles
                    ext_nibbles = ((row_ext.get_byte(1) - 128) as usize - 1) * 2;
                } else {
                    ext_nibbles = (row_ext.get_byte(1) - 128) as usize * 2 - 1;
                }
            } else if row_ext.get_byte(3) == 0 {
                // even number of nibbles
                ext_nibbles = ((row_ext.get_byte(2) - 128) as usize - 1) * 2;
            } else {
                ext_nibbles = (row_ext.get_byte(2) - 128) as usize * 2 - 1;
            }

            pv.nibbles_num += ext_nibbles;
        }
        region.assign_advice(
            || "assign number of nibbles".to_string(),
            mpt_config.s_main.bytes[NIBBLES_COUNTER_POS - RLP_NUM],
            offset,
            || Value::known(F::from(pv.nibbles_num as u64)),
        )?;

        Ok(())
    }

    pub(crate) fn assign_branch_child(
        &self,
        region: &mut Region<'_, F>,
        witness: &[MptWitnessRow<F>],
        mpt_config: &MPTConfig<F>,
        pv: &mut ProofValues<F>,
        offset: usize,
    ) -> Result<(), Error> {
        let row = &witness[offset];

        let mut node_mult_diff_s = F::one();
        let mut node_mult_diff_c = F::one();

        let len = if row.get_byte(S_RLP_START + 1) == 160 {
            pv.rlp_len_rem_s -= 33;
            33
        } else if row.get_byte(S_RLP_START + 1) == 0 && row.get_byte(S_START) > 192 {
            let len = 1 + (row.get_byte(S_START) as i32 - 192);
            pv.rlp_len_rem_s -= len;
            len
        } else if row.get_byte(S_RLP_START + 1) == 0 {
            pv.rlp_len_rem_s -= 1;
            1
        } else {
            0
        };
        for _ in 0..len {
            node_mult_diff_s *= mpt_config.randomness;
        }

        let len = if row.get_byte(C_RLP_START + 1) == 160 {
            pv.rlp_len_rem_c -= 33;
            33
        } else if row.get_byte(C_RLP_START + 1) == 0 && row.get_byte(C_START) > 192 {
            let len = 1 + (row.get_byte(C_START) as i32 - 192);
            pv.rlp_len_rem_c -= len;
            len
        } else if row.get_byte(C_RLP_START + 1) == 0 {
            pv.rlp_len_rem_c -= 1;
            1
        } else {
            0
        };
        for _ in 0..len {
            node_mult_diff_c *= mpt_config.randomness;
        }

        region.assign_advice(
            || "node_mult_diff_s".to_string(),
            mpt_config.accumulators.node_mult_diff_s,
            offset,
            || Value::known(node_mult_diff_s),
        )?;
        region.assign_advice(
            || "node_mult_diff_c".to_string(),
            mpt_config.accumulators.node_mult_diff_c,
            offset,
            || Value::known(node_mult_diff_c),
        )?;

        if pv.node_index == 0 {
            // If it's not extension node, rlc and rlc_mult in extension row
            // will be the same as for branch rlc.
            pv.extension_node_rlc = pv.key_rlc;

            pv.key_rlc_prev = pv.key_rlc;
            pv.key_rlc_mult_prev = pv.key_rlc_mult;

            // Extension node
            // We need nibbles here to be able to compute key RLC
            if pv.is_extension_node {
                // For key RLC, we need to first take into account
                // extension node key.
                // witness[offset + 16]
                let ext_row = &witness[offset + 16];
                let mut key_len_pos = 1;
                if ext_row.get_byte(0) == 248 {
                    key_len_pos = 2;
                }

                if pv.key_rlc_sel {
                    // Note: it can't be is_even = 1 && is_short = 1.
                    if pv.is_even && pv.is_long {
                        // extension node part:
                        let key_len = ext_row.get_byte(key_len_pos) as usize - 128 - 1; // -1 because the first byte is 0 (is_even)
                        mpt_config.compute_acc_and_mult(
                            &ext_row.bytes,
                            &mut pv.extension_node_rlc,
                            &mut pv.key_rlc_mult,
                            key_len_pos + 2, /* first position behind key_len_pos
                                              * is 0 (because is_even), we start
                                              * with the next one */
                            key_len,
                        );
                        pv.mult_diff = F::one();
                        for _ in 0..key_len {
                            pv.mult_diff *= mpt_config.randomness;
                        }
                        pv.key_rlc = pv.extension_node_rlc;
                        // branch part:
                        pv.key_rlc +=
                            F::from(pv.modified_node as u64) * F::from(16) * pv.key_rlc_mult;
                        // key_rlc_mult stays the same
                        pv.key_rlc_sel = !pv.key_rlc_sel;
                    } else if pv.is_odd && pv.is_long {
                        // extension node part:
                        pv.extension_node_rlc +=
                            F::from((ext_row.get_byte(key_len_pos + 1) - 16) as u64)
                                * F::from(16)
                                * pv.key_rlc_mult;

                        let ext_row_c = &witness[offset + 17];
                        let key_len = ext_row.get_byte(key_len_pos) as usize - 128;

                        pv.mult_diff = F::one();
                        for k in 0..key_len - 1 {
                            let second_nibble = ext_row_c.get_byte(S_START + k);
                            let first_nibble =
                                (ext_row.get_byte(key_len_pos + 2 + k) - second_nibble) / 16;
                            assert_eq!(
                                first_nibble * 16 + second_nibble,
                                ext_row.get_byte(key_len_pos + 2 + k),
                            );
                            pv.extension_node_rlc += F::from(first_nibble as u64) * pv.key_rlc_mult;

                            pv.key_rlc_mult *= mpt_config.randomness;
                            pv.mult_diff *= mpt_config.randomness;

                            pv.extension_node_rlc +=
                                F::from(second_nibble as u64) * F::from(16) * pv.key_rlc_mult;
                        }

                        pv.key_rlc = pv.extension_node_rlc;
                        // branch part:
                        pv.key_rlc += F::from(pv.modified_node as u64) * pv.key_rlc_mult;
                        pv.key_rlc_mult *= mpt_config.randomness;
                    } else if pv.is_short {
                        pv.extension_node_rlc += F::from((ext_row.get_byte(1) - 16) as u64)
                            * F::from(16)
                            * pv.key_rlc_mult;
                        pv.key_rlc = pv.extension_node_rlc;
                        // branch part:
                        pv.key_rlc += F::from(pv.modified_node as u64) * pv.key_rlc_mult;
                        pv.key_rlc_mult *= mpt_config.randomness;
                        pv.mult_diff = if pv.is_short_c1 {
                            F::one()
                        } else {
                            mpt_config.randomness
                        };
                    }
                } else if pv.is_even && pv.is_long {
                    // extension node part:
                    let ext_row_c = &witness[offset + 17];
                    let key_len = ext_row.get_byte(key_len_pos) as usize - 128 - 1; // -1 because the first byte is 0 (is_even)

                    pv.mult_diff = F::one();
                    for k in 0..key_len {
                        let second_nibble = ext_row_c.get_byte(S_START + k);
                        let first_nibble =
                            (ext_row.get_byte(key_len_pos + 2 + k) - second_nibble) / 16;
                        assert_eq!(
                            first_nibble * 16 + second_nibble,
                            ext_row.get_byte(key_len_pos + 2 + k),
                        );
                        pv.extension_node_rlc += F::from(first_nibble as u64) * pv.key_rlc_mult;

                        pv.key_rlc_mult *= mpt_config.randomness;
                        pv.mult_diff *= mpt_config.randomness;

                        pv.extension_node_rlc +=
                            F::from(16) * F::from(second_nibble as u64) * pv.key_rlc_mult;
                    }

                    pv.key_rlc = pv.extension_node_rlc;
                    // branch part:
                    pv.key_rlc += F::from(pv.modified_node as u64) * pv.key_rlc_mult;
                    pv.key_rlc_mult *= mpt_config.randomness;
                    pv.key_rlc_sel = !pv.key_rlc_sel;
                } else if pv.is_odd && pv.is_long {
                    pv.extension_node_rlc +=
                        F::from((ext_row.get_byte(key_len_pos + 1) - 16) as u64) * pv.key_rlc_mult;

                    pv.key_rlc_mult *= mpt_config.randomness;

                    let key_len = ext_row.get_byte(key_len_pos) as usize - 128;

                    mpt_config.compute_acc_and_mult(
                        &ext_row.bytes,
                        &mut pv.extension_node_rlc,
                        &mut pv.key_rlc_mult,
                        key_len_pos + 2, /* the first position after key_len_pos
                                          * is single nibble which is taken into
                                          * account above, we start
                                          * with fourth */
                        key_len - 1, // one byte is occupied by single nibble
                    );
                    pv.mult_diff = F::one();
                    for _ in 0..key_len {
                        pv.mult_diff *= mpt_config.randomness;
                    }
                    pv.key_rlc = pv.extension_node_rlc;
                    // branch part:
                    pv.key_rlc += F::from(pv.modified_node as u64) * F::from(16) * pv.key_rlc_mult;
                    // key_rlc_mult stays the same
                } else if pv.is_short {
                    pv.extension_node_rlc +=
                        F::from((ext_row.get_byte(1) - 16) as u64) * pv.key_rlc_mult;

                    pv.key_rlc = pv.extension_node_rlc;

                    pv.key_rlc_mult *= mpt_config.randomness;
                    // branch part:
                    pv.key_rlc += F::from(pv.modified_node as u64) * F::from(16) * pv.key_rlc_mult;
                    pv.mult_diff = if pv.is_short_c1 {
                        F::one()
                    } else {
                        mpt_config.randomness
                    };
                }
            } else {
                if pv.key_rlc_sel {
                    pv.key_rlc += F::from(pv.modified_node as u64) * F::from(16) * pv.key_rlc_mult;
                    // key_rlc_mult stays the same
                } else {
                    pv.key_rlc += F::from(pv.modified_node as u64) * pv.key_rlc_mult;
                    pv.key_rlc_mult *= mpt_config.randomness;
                }
                pv.key_rlc_sel = !pv.key_rlc_sel;
                pv.mult_diff = F::one();
            }
            row.assign_branch_row(region, mpt_config, pv, offset)?;
        } else {
            row.assign_branch_row(region, mpt_config, pv, offset)?;
        }

        /*
        `sel1` is to distinguish whether the S node at `modified_node` position is empty.
        `sel2` is to distinguish whether the C node at `modified_node` position is empty.
        Note that 128 comes from the RLP byte denoting empty leaf.
        Having 128 for `*_mod_node_hash_rlc` means there is no node at
        this position in branch - for example,
        `s_mode_node_hash_rlc = 128` and `c_words` is some other value
        when new value is added to the trie
        (as opposed to just updating the value).
        Note that there is a potential attack if a leaf node
        is found with hash `[128, 0, ..., 0]`,
        but the probability is negligible.
        */
        let mut sel1 = F::zero();
        let mut sel2 = F::zero();
        if pv.s_mod_node_hash_rlc == F::from(128_u64) {
            sel1 = F::one();
        }
        if pv.c_mod_node_hash_rlc == F::from(128_u64) {
            sel2 = F::one();
        }

        region.assign_advice(
            || "assign sel1".to_string(),
            mpt_config.denoter.sel1,
            offset,
            || Value::known(sel1),
        )?;
        region.assign_advice(
            || "assign sel2".to_string(),
            mpt_config.denoter.sel2,
            offset,
            || Value::known(sel2),
        )?;

        // reassign (it was assigned to 0 in assign_row) branch_acc and
        // branch_mult to proper values

        // We need to distinguish between empty and non-empty node:
        // empty node at position 1: 0
        // non-empty node at position 1: 160

        let c128 = F::from(128_u64);
        let c160 = F::from(160_u64);

        let compute_branch_acc_and_mult =
            |branch_acc: &mut F, branch_mult: &mut F, rlp_start: usize, start: usize| {
                if row.get_byte(rlp_start + 1) == 0 && row.get_byte(start) == 128 {
                    *branch_acc += c128 * *branch_mult;
                    *branch_mult *= mpt_config.randomness;
                } else if row.get_byte(rlp_start + 1) == 160 {
                    *branch_acc += c160 * *branch_mult;
                    *branch_mult *= mpt_config.randomness;
                    for i in 0..HASH_WIDTH {
                        *branch_acc += F::from(row.get_byte(start + i) as u64) * *branch_mult;
                        *branch_mult *= mpt_config.randomness;
                    }
                } else {
                    *branch_acc += F::from(row.get_byte(start) as u64) * *branch_mult;
                    *branch_mult *= mpt_config.randomness;
                    let len = row.get_byte(start) as usize - 192;
                    for i in 0..len {
                        *branch_acc += F::from(row.get_byte(start + 1 + i) as u64) * *branch_mult;
                        *branch_mult *= mpt_config.randomness;
                    }
                }
            };

        // TODO: add branch ValueNode info

        compute_branch_acc_and_mult(&mut pv.acc_s, &mut pv.acc_mult_s, S_RLP_START, S_START);
        compute_branch_acc_and_mult(&mut pv.acc_c, &mut pv.acc_mult_c, C_RLP_START, C_START);
        mpt_config.assign_acc(
            region,
            pv.acc_s,
            pv.acc_mult_s,
            pv.acc_c,
            pv.acc_mult_c,
            offset,
        )?;

        // This is to avoid Poisoned Constraint in extension_node_key.
        region.assign_advice(
            || "assign key_rlc".to_string(),
            mpt_config.accumulators.key.rlc,
            offset,
            || Value::known(pv.key_rlc),
        )?;
        region.assign_advice(
            || "assign key_rlc_mult".to_string(),
            mpt_config.accumulators.key.mult,
            offset,
            || Value::known(pv.key_rlc_mult),
        )?;

        pv.node_index += 1;

        Ok(())
    }
}
