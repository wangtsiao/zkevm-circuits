use halo2_proofs::{
    circuit::Chip,
    plonk::{Advice, Column, ConstraintSystem, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use pairing::arithmetic::FieldExt;
use std::marker::PhantomData;

use crate::{
    helpers::{
        compute_rlc, get_bool_constraint, get_is_extension_node_one_nibble, key_len_lookup,
        mult_diff_lookup, range_lookups,
    },
    mpt::{FixedTableTag},
    param::{IS_BRANCH_C16_POS, IS_BRANCH_C1_POS, LEAF_DRIFTED_IND, BRANCH_ROWS_NUM, LEAF_KEY_S_IND, LEAF_KEY_C_IND}, columns::{MainCols, AccumulatorCols},
};

use crate::param::{
    HASH_WIDTH, IS_BRANCH_C_PLACEHOLDER_POS, IS_BRANCH_S_PLACEHOLDER_POS, KECCAK_INPUT_WIDTH,
    KECCAK_OUTPUT_WIDTH, RLP_NUM, R_TABLE_LEN,
};

#[derive(Clone, Debug)]
pub(crate) struct LeafKeyInAddedBranchConfig {}

pub(crate) struct LeafKeyInAddedBranchChip<F> {
    config: LeafKeyInAddedBranchConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> LeafKeyInAddedBranchChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl Fn(&mut VirtualCells<'_, F>) -> Expression<F> + Copy,
        s_main: MainCols<F>,
        c_main: MainCols<F>,
        accs: AccumulatorCols<F>,
        drifted_pos: Column<Advice>,
        is_account_leaf_in_added_branch: Column<Advice>,
        r_table: Vec<Expression<F>>,
        fixed_table: [Column<Fixed>; 3],
        keccak_table: [Column<Fixed>; KECCAK_INPUT_WIDTH + KECCAK_OUTPUT_WIDTH],
    ) -> LeafKeyInAddedBranchConfig {
        let config = LeafKeyInAddedBranchConfig {};

        let one = Expression::Constant(F::one());
        let c16 = Expression::Constant(F::from(16_u64));
        let c32 = Expression::Constant(F::from(32_u64));
        let c48 = Expression::Constant(F::from(48_u64));
        let rot_branch_init = -LEAF_DRIFTED_IND - BRANCH_ROWS_NUM;
        let rot_into_account = -LEAF_DRIFTED_IND - 1;

        // NOTE: the leaf value is not stored in this row, it needs to be the same
        // as for the leaf before it drifted down to the new branch, thus, it is
        // retrieved from the row of a leaf before a drift - to check that the hash
        // of a drifted leaf is in the new branch.

        // Checking leaf RLC is ok - RLC is then taken and value (from leaf_value row)
        // is added to RLC, finally lookup is used to check the hash that
        // corresponds to this RLC is in the parent branch at drifted_pos position.
        // This is not to be confused with key RLC checked in another gate (the gate
        // here checks the RLC of all leaf bytes, while the gate below checks the key
        // RLC accumulated in branches/extensions + leaf key).
        meta.create_gate("Storage leaf in added branch RLC", |meta| {
            let q_enable = q_enable(meta);
            let mut constraints = vec![];

            let c248 = Expression::Constant(F::from(248));
            let s_rlp1 = meta.query_advice(s_main.rlp1, Rotation::cur());

            let flag1 = meta.query_advice(accs.s_mod_node_rlc, Rotation::cur());
            let flag2 = meta.query_advice(accs.c_mod_node_rlc, Rotation::cur());
            let last_level = flag1.clone() * flag2.clone();
            let is_long = flag1.clone() * (one.clone() - flag2.clone());
            let is_short = (one.clone() - flag1.clone()) * flag2.clone();

            constraints.push((
                "is_long",
                q_enable.clone() * is_long.clone() * (s_rlp1.clone() - c248),
            ));
            constraints.push((
                "flag1 is boolean",
                get_bool_constraint(q_enable.clone(), flag1.clone()),
            ));
            constraints.push((
                "flag2 is boolean",
                get_bool_constraint(q_enable.clone(), flag2.clone()),
            ));
            
            let is_branch_s_placeholder = meta.query_advice(
                s_main.bytes[IS_BRANCH_S_PLACEHOLDER_POS - RLP_NUM],
                Rotation(rot_branch_init),
            );
            let is_branch_c_placeholder = meta.query_advice(
                s_main.bytes[IS_BRANCH_C_PLACEHOLDER_POS - RLP_NUM],
                Rotation(rot_branch_init),
            );

            // If leaf is in first storage level, there cannot be drifted leaf and placeholder branch
            // and we do not need to trigger any checks. Note that in this case is_branch_*_placeholder
            // is computed wrongly and we cannot rely on it.
            let is_leaf_in_first_storage_level =
                meta.query_advice(is_account_leaf_in_added_branch, Rotation(rot_into_account));

            constraints.push((
                "not both zeros: flag1, flag2",
                q_enable.clone()
                    * (is_branch_s_placeholder.clone() + is_branch_c_placeholder.clone()) // there is no added leaf when no placeholder branch
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * (one.clone() - flag1.clone())
                    * (one.clone() - flag2.clone()),
            ));

            let s_rlp2 = meta.query_advice(s_main.rlp2, Rotation::cur());
            let rlc_last_level = s_rlp1 + s_rlp2 * r_table[0].clone();

            let mut rlc = rlc_last_level.clone() + compute_rlc(meta, s_main.bytes.to_vec(), 1, one.clone(), 0, r_table.clone());

            let c_rlp1 = meta.query_advice(c_main.rlp1, Rotation::cur());
            rlc = rlc + c_rlp1 * r_table[R_TABLE_LEN - 1].clone() * r_table[1].clone();
            let c_rlp2 = meta.query_advice(c_main.rlp2, Rotation::cur());
            rlc = rlc + c_rlp2 * r_table[R_TABLE_LEN - 1].clone() * r_table[2].clone();

            let acc = meta.query_advice(accs.acc_s.rlc, Rotation::cur());
            constraints.push(("Leaf key acc", q_enable.clone()
                    * (is_short + is_long) // activate if is_short or is_long
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * (is_branch_s_placeholder.clone() + is_branch_c_placeholder.clone()) // drifted leaf appears only when there is a placeholder branch
                    * (rlc - acc.clone())));

            constraints.push(("Leaf key acc last level", q_enable
                    * last_level // activate if in last level
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * (is_branch_s_placeholder.clone() + is_branch_c_placeholder.clone()) // drifted leaf appears only when there is a placeholder branch
                    * (rlc_last_level - acc)));

            constraints
        });

        let sel_short = |meta: &mut VirtualCells<F>| {
            let q_enable = q_enable(meta);
            let is_branch_s_placeholder = meta.query_advice(
                s_main.bytes[IS_BRANCH_S_PLACEHOLDER_POS - RLP_NUM],
                Rotation(rot_branch_init),
            );
            let is_branch_c_placeholder = meta.query_advice(
                s_main.bytes[IS_BRANCH_C_PLACEHOLDER_POS - RLP_NUM],
                Rotation(rot_branch_init),
            );
            let is_leaf_in_first_storage_level =
                meta.query_advice(is_account_leaf_in_added_branch, Rotation(rot_into_account));

            let flag1 = meta.query_advice(accs.s_mod_node_rlc, Rotation::cur());
            let flag2 = meta.query_advice(accs.c_mod_node_rlc, Rotation::cur());
            let is_short = (one.clone() - flag1.clone()) * flag2.clone();

            q_enable * is_short * (is_branch_s_placeholder + is_branch_c_placeholder)
                * (one.clone() - is_leaf_in_first_storage_level.clone())
        };
        let sel_long = |meta: &mut VirtualCells<F>| {
            let q_enable = q_enable(meta);
            let is_branch_s_placeholder = meta.query_advice(
                s_main.bytes[IS_BRANCH_S_PLACEHOLDER_POS - RLP_NUM],
                Rotation(rot_branch_init),
            );
            let is_branch_c_placeholder = meta.query_advice(
                s_main.bytes[IS_BRANCH_C_PLACEHOLDER_POS - RLP_NUM],
                Rotation(rot_branch_init),
            );
            let is_leaf_in_first_storage_level =
                meta.query_advice(is_account_leaf_in_added_branch, Rotation(rot_into_account));

            let flag1 = meta.query_advice(accs.s_mod_node_rlc, Rotation::cur());
            let flag2 = meta.query_advice(accs.c_mod_node_rlc, Rotation::cur());
            let is_long = flag1.clone() * (one.clone() - flag2.clone());

            q_enable * is_long * (is_branch_s_placeholder + is_branch_c_placeholder)
                * (one.clone() - is_leaf_in_first_storage_level.clone())
        };

        /*
        There are 0s after key length (this doesn't need to be checked for last_level as
        in this case s_main.bytes are not used).
        for ind in 0..HASH_WIDTH {
            key_len_lookup(
                meta,
                sel_short,
                ind + 1,
                s_main.rlp2,
                s_main.bytes[ind],
                128,
                fixed_table,
            )
        }

        for ind in 1..HASH_WIDTH {
            key_len_lookup(
                meta,
                sel_long,
                ind,
                s_main.bytes[0],
                s_main.bytes[ind],
                128,
                fixed_table,
            )
        }
        key_len_lookup(meta, sel_long, 32, s_main.bytes[0], c_rlp1, 128, fixed_table);
        */

        // acc_mult corresponds to key length (short):
        mult_diff_lookup(meta, sel_short, 2, s_main.rlp2, accs.acc_s.mult, 128, fixed_table);
        // acc_mult corresponds to key length (long):
        mult_diff_lookup(meta, sel_long, 3, s_main.bytes[0], accs.acc_s.mult, 128, fixed_table);

        /*
        Leaf key S
        Leaf value S
        Leaf key C
        Leaf value C
        Drifted leaf (leaf in added branch)

        Add case (S branch is placeholder):
          Branch S           || Branch C             
          Placeholder branch || Added branch
          Leaf S             || Leaf C
                             || Drifted leaf (this is Leaf S drifted into Added branch)

          Leaf S needs to have the same key RLC as Drifted leaf.
          Note that Leaf S key RLC is computed by taking key_rlc from Branch S and
          then adding the bytes in Leaf key S row.
          Drifted leaf RLC is computed by taking key_rlc from Added branch and
          then adding the bytes in Drifted leaf row.

        Delete case (C branch is placeholder):
          Branch S                        || Branch C             
          Branch to be deleted            || Placeholder branch
          Leaf S (leaf to be deleted)     || Leaf C
          Leaf to be drifted one level up || 
        */

        meta.create_gate("Drifted leaf key RLC", |meta| {
            let q_enable = q_enable(meta);
            let mut constraints = vec![];

            // Get back into S or C extension row to retrieve key_rlc. Note that this works
            // for both - extension nodes and branches. That's because branch key RLC is
            // stored in extension node row when there is NO extension node (the
            // constraint is in extension_node_key).
            let key_rlc_cur = meta.query_advice(accs.key.rlc, Rotation(-LEAF_DRIFTED_IND-1));

            // sel1 and sel2 determines whether drifted_pos needs to be
            // multiplied by 16 or not.
            let sel1 = meta.query_advice(
                s_main.bytes[IS_BRANCH_C16_POS - RLP_NUM],
                Rotation(rot_branch_init),
            );
            let sel2 = meta.query_advice(
                s_main.bytes[IS_BRANCH_C1_POS - RLP_NUM],
                Rotation(rot_branch_init),
            );

            // Note: previous key_rlc in sel1/sel2 could be queried instead.
            let branch_rlc_mult = meta.query_advice(accs.key.mult, Rotation(-30));

            let mult_diff = meta.query_advice(accs.mult_diff, Rotation(rot_branch_init + 1));

            let flag1 = meta.query_advice(accs.s_mod_node_rlc, Rotation::cur());
            let flag2 = meta.query_advice(accs.c_mod_node_rlc, Rotation::cur());
            let last_level = flag1.clone() * flag2.clone();
            let is_long = flag1.clone() * (one.clone() - flag2.clone());
            let is_short = (one.clone() - flag1.clone()) * flag2.clone();

            // Key RLC of the drifted leaf needs to be the same as key RLC of the leaf
            // before it drifted down into extension/branch.
            let is_branch_s_placeholder = meta.query_advice(
                s_main.bytes[IS_BRANCH_S_PLACEHOLDER_POS - RLP_NUM],
                Rotation(rot_branch_init),
            );
            let is_branch_c_placeholder = meta.query_advice(
                s_main.bytes[IS_BRANCH_C_PLACEHOLDER_POS - RLP_NUM],
                Rotation(rot_branch_init),
            );

            // We retrieve key_rlc from the leaf that was replaced by a branch. This RLC
            // need to be the same as drifted leaf key RLC.
            let leaf_key_s_rlc = meta.query_advice(accs.key.rlc, Rotation(-(LEAF_DRIFTED_IND - LEAF_KEY_S_IND)));
            let leaf_key_c_rlc = meta.query_advice(accs.key.rlc, Rotation(-(LEAF_DRIFTED_IND - LEAF_KEY_C_IND)));

            // whether placeholder branch is in the first storage level:
            let is_branch_in_first_storage_level = meta.query_advice(
                is_account_leaf_in_added_branch,
                Rotation(rot_branch_init - 1),
            );

            let is_leaf_in_first_storage_level =
                meta.query_advice(is_account_leaf_in_added_branch, Rotation(rot_into_account));

            let is_one_nibble = get_is_extension_node_one_nibble(meta, s_main.bytes, rot_branch_init);

            // Any rotation that lands into branch children can be used.
            let drifted_pos = meta.query_advice(drifted_pos, Rotation(-17));
            let mut key_mult = branch_rlc_mult.clone()
                * mult_diff.clone()
                * (one.clone() - is_branch_in_first_storage_level.clone())
                + is_branch_in_first_storage_level.clone() * is_one_nibble.clone()
                + is_branch_in_first_storage_level.clone()
                    * mult_diff.clone()
                    * (one.clone() - is_one_nibble.clone());
            let drifted_pos_mult =
                key_mult.clone() * c16.clone() * sel1.clone() + key_mult.clone() * sel2.clone();

            // Note: the difference in key_mult for sel1 and sel2 is already taken into
            // account in mult_diff.

            let key_rlc_start = key_rlc_cur.clone() + drifted_pos.clone() * drifted_pos_mult;

            // If sel1 = 1, we have one nibble+48 in s_main.bytes[0].
            let s_advice0 = meta.query_advice(s_main.bytes[0], Rotation::cur());

            // If sel2 = 1, we have 32 in s_main.bytes[0].
            constraints.push((
                "Leaf key acc s_advice0",
                q_enable.clone()
                    * (is_branch_s_placeholder.clone() + is_branch_c_placeholder.clone()) // drifted leaf appears only when there is a placeholder branch
                    * (s_advice0.clone() - c32.clone())
                    * sel2.clone()
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * is_short.clone(),
            ));

            let mut key_rlc_short = key_rlc_start.clone()
                + (s_advice0.clone() - c48.clone()) * sel1.clone() * key_mult.clone();

            for ind in 1..HASH_WIDTH {
                let s = meta.query_advice(s_main.bytes[ind], Rotation::cur());
                key_rlc_short = key_rlc_short + s * key_mult.clone() * r_table[ind - 1].clone();
            }

            // Note: drifted leaf key cannot reach c_rlp1 because it has at most 31 nibbles.
            // In case of 31 nibbles, key occupies 32 bytes (in case of 32 nibbles and no
            // branch above the leaf, the key occupies 33 bytes).

            // No need to distinguish between sel1 and sel2 here as it was already
            // when computing key_rlc.
            // Note: if S placeholder, leaf_key_s_rlc is key_rlc of the leaf before it drifted down
            // in a new branch. This value needs to be the same as key_rlc of the drifted leaf.
            constraints.push((
                "Drifted leaf key S short",
                q_enable.clone()
                    * is_branch_s_placeholder.clone()
                    * is_short.clone()
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * (leaf_key_s_rlc.clone() - key_rlc_short.clone()),
            ));
            constraints.push((
                "Drifted leaf key C short",
                q_enable.clone()
                    * is_branch_c_placeholder.clone()
                    * is_short.clone()
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * (leaf_key_c_rlc.clone() - key_rlc_short.clone()),
            ));

            // Long:
            // Note: long means long leaf RLP, not extension node nibbles.

            // If sel1 = 1, we have one nibble+48 in s_main.bytes[1].
            let s_advice1 = meta.query_advice(s_main.bytes[1], Rotation::cur());

            // If sel2 = 1, we have 32 in s_main.bytes[1].
            constraints.push((
                "Leaf key acc s_advice1",
                q_enable.clone()
                    * (s_advice1.clone() - c32.clone())
                    * sel2.clone()
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * is_long.clone(),
            ));

            let mut key_rlc_long = key_rlc_start.clone()
                + (s_advice1.clone() - c48.clone()) * sel1.clone() * key_mult.clone();

            for ind in 2..HASH_WIDTH {
                let s = meta.query_advice(s_main.bytes[ind], Rotation::cur());
                key_mult = key_mult * r_table[0].clone();
                key_rlc_long = key_rlc_long + s * key_mult.clone();
            }

            key_mult = key_mult * r_table[0].clone();
            let c_rlp1 = meta.query_advice(c_main.rlp1, Rotation::cur());
            key_rlc_long = key_rlc_long + c_rlp1.clone() * key_mult;

            // No need to distinguish between sel1 and sel2 here as it was already
            // when computing key_rlc.
            constraints.push((
                "Drifted leaf key S long",
                q_enable.clone()
                    * is_branch_s_placeholder.clone()
                    * is_long.clone()
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * (leaf_key_s_rlc.clone() - key_rlc_long.clone()),
            ));
            constraints.push((
                "Drifted leaf key C long",
                q_enable.clone()
                    * is_branch_c_placeholder.clone()
                    * is_long.clone()
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * (leaf_key_c_rlc.clone() - key_rlc_long.clone()),
            ));

            // Last level:
            let s_rlp2 = meta.query_advice(s_main.rlp2, Rotation::cur());
            constraints.push((
                "Leaf key acc s_rlp2 = 32 last level",
                q_enable.clone()
                    * (is_branch_s_placeholder.clone() + is_branch_c_placeholder.clone()) // drifted leaf appears only when there is a placeholder branch
                    * (s_rlp2.clone() - c32.clone())
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * last_level.clone(),
            ));

            constraints.push((
                "Drifted leaf key S last level",
                q_enable.clone()
                    * is_branch_s_placeholder.clone()
                    * last_level.clone()
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * (leaf_key_s_rlc.clone() - key_rlc_start.clone()), // no nibbles in drifted leaf
            ));
            constraints.push((
                "Drifted leaf key C last level",
                q_enable.clone()
                    * is_branch_c_placeholder.clone()
                    * last_level.clone()
                    * (one.clone() - is_leaf_in_first_storage_level.clone())
                    * (leaf_key_c_rlc.clone() - key_rlc_start), // no nibbles in drifted leaf
            ));

            constraints
        });

        // Checking accumulated RLC for key is not necessary here for
        // leaf_key_in_added_branch because we check this for leaf_key and here
        // we only check the key in leaf_key_in_added_branch corresponds to the
        // one in leaf_key.

        // In case we have a placeholder branch at position S:
        // (1) branch (17 rows) which contains leaf that turns into branch at
        // is_modified position (S positions) |     branch (17 rows) that
        // contains added branch hash at is_modified position (C positions)
        // (2) placeholder branch (17 rows) (S positions) | added branch (17 rows) (C
        // positions)     S extension node row
        //     C extension node row
        // (3) leaf key S
        // (4) leaf value S ((3)||(4) hash is two levels above in (1) at is_modified)
        // (5) leaf key C
        // (6) leaf value C ((5)||(6) hash is in one level above (2) at is_modified)
        // (7) leaf in added branch - the same as leaf key S in (3), but it has the
        // first nibble removed

        // We need to check that leaf_in_added_branch hash is in (2) at drifted_pos
        // position (drifted_pos is the first nibble in leaf key S (3), because
        // leaf drifts down to this position in new branch)

        // We need to construct RLP of the leaf. We have leaf key in
        // is_leaf_in_added_branch and the value is the same as it is in the
        // leaf value S (3).

        meta.lookup_any("leaf_key_in_added_branch: drifted leaf hash the branch (S)", |meta| {
            let q_enable = q_enable(meta);
            let mut constraints = vec![];

            let mut rlc = meta.query_advice(accs.acc_s.rlc, Rotation::cur());
            let acc_mult = meta.query_advice(accs.acc_s.mult, Rotation::cur());

            // If branch placeholder in S, leaf value is 3 above.
            let rot_val = -3;

            let s_rlp1 = meta.query_advice(s_main.rlp1, Rotation(rot_val));
            rlc = rlc + s_rlp1 * acc_mult.clone();

            let s_rlp2 = meta.query_advice(s_main.rlp2, Rotation(rot_val));
            rlc = rlc + s_rlp2 * acc_mult.clone() * r_table[0].clone();

            // TODO: use already computed RLC value in leaf row
            rlc = rlc
                + compute_rlc(
                    meta,
                    s_main.bytes.to_vec(),
                    1,
                    acc_mult.clone(),
                    rot_val,
                    r_table.clone(),
                );
            // Note: value doesn't reach c_rlp1.

            let is_leaf_in_first_storage_level =
                meta.query_advice(is_account_leaf_in_added_branch, Rotation(rot_into_account));

            // Any rotation that lands into branch children can be used.
            let rot = -17;
            let is_branch_s_placeholder = meta.query_advice(
                s_main.bytes[IS_BRANCH_S_PLACEHOLDER_POS - RLP_NUM],
                Rotation(-23),
            );

            constraints.push((
                q_enable.clone()
                    * rlc
                    * is_branch_s_placeholder.clone()
                    * (one.clone() - is_leaf_in_first_storage_level.clone()),
                meta.query_fixed(keccak_table[0], Rotation::cur()),
            ));

            // s_mod_node_hash_rlc in placeholder branch contains hash of a drifted leaf
            // (that this value corresponds to the value in the non-placeholder branch at drifted_pos
            // is checked in branch_parallel)
            let s_mod_node_hash_rlc = meta.query_advice(accs.s_mod_node_rlc, Rotation(rot));
            let keccak_table_i = meta.query_fixed(keccak_table[1], Rotation::cur());
            constraints.push((
                q_enable.clone()
                    * s_mod_node_hash_rlc
                    * is_branch_s_placeholder.clone()
                    * (one.clone() - is_leaf_in_first_storage_level),
                keccak_table_i,
            ));

            constraints
        });

        meta.lookup_any("leaf_key_in_added_branch: drifted leaf hash the branch (C)", |meta| {
            let q_enable = q_enable(meta);
            let mut constraints = vec![];

            let mut rlc = meta.query_advice(accs.acc_s.rlc, Rotation::cur());
            let acc_mult = meta.query_advice(accs.acc_s.mult, Rotation::cur());

            // If branch placeholder in C, value is 1 above.
            let rot_val = -1;

            let s_rlp1 = meta.query_advice(s_main.rlp1, Rotation(rot_val));
            rlc = rlc + s_rlp1 * acc_mult.clone();

            let s_rlp2 = meta.query_advice(s_main.rlp2, Rotation(rot_val));
            rlc = rlc + s_rlp2 * acc_mult.clone() * r_table[0].clone();

            rlc = rlc
                + compute_rlc(
                    meta,
                    s_main.bytes.to_vec(),
                    1,
                    acc_mult.clone(),
                    rot_val,
                    r_table.clone(),
                );
            // Note: value doesn't reach c_rlp1.

            let is_leaf_in_first_storage_level =
                meta.query_advice(is_account_leaf_in_added_branch, Rotation(rot_into_account));

            // Any rotation that lands into branch children can be used.
            let rot = -17;
            let is_branch_c_placeholder = meta.query_advice(
                s_main.bytes[IS_BRANCH_C_PLACEHOLDER_POS - RLP_NUM],
                Rotation(-23),
            );

            constraints.push((
                q_enable.clone()
                    * rlc
                    * is_branch_c_placeholder.clone()
                    * (one.clone() - is_leaf_in_first_storage_level.clone()),
                meta.query_fixed(keccak_table[0], Rotation::cur()),
            ));

            // c_mod_node_hash_rlc in placeholder branch contains hash of a drifted leaf
            // (that this value corresponds to the value in the non-placeholder branch at drifted_pos
            // is checked in branch_parallel)
            let c_mod_node_hash_rlc = meta.query_advice(accs.c_mod_node_rlc, Rotation(rot));
            let keccak_table_i = meta.query_fixed(keccak_table[1], Rotation::cur());
            constraints.push((
                q_enable.clone()
                    * c_mod_node_hash_rlc
                    * is_branch_c_placeholder.clone()
                    * (one - is_leaf_in_first_storage_level),
                keccak_table_i,
            ));

            constraints
        });

        range_lookups(
            meta,
            q_enable,
            s_main.bytes.to_vec(),
            FixedTableTag::Range256,
            fixed_table,
        );
        range_lookups(
            meta,
            q_enable,
            [s_main.rlp1, s_main.rlp2, c_main.rlp1, c_main.rlp2].to_vec(),
            FixedTableTag::Range256,
            fixed_table,
        );

        config
    }

    pub fn construct(config: LeafKeyInAddedBranchConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
}

impl<F: FieldExt> Chip<F> for LeafKeyInAddedBranchChip<F> {
    type Config = LeafKeyInAddedBranchConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}