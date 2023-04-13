//! Cell manager
use crate::util::Expr;
use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Column, Error, Expression, VirtualCells},
    poly::Rotation,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub(crate) struct Cell<F> {
    // expression for constraint
    expression: Option<Expression<F>>,
    column: Option<Column<Advice>>,
    // relative position to selector for synthesis
    rotation: usize,
}

impl<F: Field> Cell<F> {
    pub(crate) fn new(meta: &mut VirtualCells<F>, column: Column<Advice>, rotation: usize) -> Self {
        Self {
            expression: Some(meta.query_advice(column, Rotation(rotation as i32))),
            column: Some(column),
            rotation,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice(
            || {
                format!(
                    "Cell column: {:?} and rotation: {}",
                    self.column, self.rotation
                )
            },
            self.column.unwrap(),
            offset + self.rotation,
            || Value::known(value),
        )
    }

    pub(crate) fn column(&self) -> Column<Advice> {
        self.column.unwrap()
    }

    pub(crate) fn rotation(&self) -> usize {
        self.rotation
    }

    pub(crate) fn rot(&self, meta: &mut VirtualCells<F>, rot: usize) -> Expression<F> {
        meta.query_advice(self.column.unwrap(), Rotation((self.rotation + rot) as i32))
    }
}

impl<F: Field> Expr<F> for Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.as_ref().unwrap().clone()
    }
}

impl<F: Field> Expr<F> for &Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.as_ref().unwrap().clone()
    }
}

/// CellType
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CellType {
    /// General
    Storage,
}

/// CellColumn
#[derive(Clone, Debug)]
pub struct CellColumn<F> {
    pub(crate) index: usize,
    pub(crate) cell_type: CellType,
    pub(crate) height: usize,
    pub(crate) expr: Expression<F>,
}

impl<F: Field> Expr<F> for CellColumn<F> {
    fn expr(&self) -> Expression<F> {
        self.expr.clone()
    }
}

/// CellManager
#[derive(Clone, Debug)]
pub struct CellManager<F> {
    width: usize,
    height: usize,
    cells: Vec<Cell<F>>,
    columns: Vec<CellColumn<F>>,
    height_limit: usize,
}

impl<F: Field> CellManager<F> {
    pub(crate) fn new(meta: &mut VirtualCells<F>, advice_columns: &[Column<Advice>]) -> Self {
        // Setup the columns and query the cells
        let width = advice_columns.len();
        let height = 32;
        let mut cells = Vec::with_capacity(height * width);
        let mut columns = Vec::with_capacity(width);
        for c in 0..width {
            for r in 0..height {
                cells.push(Cell::new(meta, advice_columns[c], r));
            }
            columns.push(CellColumn {
                index: c,
                cell_type: CellType::Storage,
                height: 0,
                expr: cells[c * height].expr(),
            });
        }

        Self {
            width,
            height,
            cells,
            columns,
            height_limit: height,
        }
    }

    pub(crate) fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        let mut cells = Vec::with_capacity(count);
        while cells.len() < count {
            let column_idx = self.next_column(cell_type);
            let column = &mut self.columns[column_idx];
            cells.push(self.cells[column_idx * self.height + column.height].clone());
            column.height += 1;
        }
        cells
    }

    pub(crate) fn query_cell(&mut self, cell_type: CellType) -> Cell<F> {
        self.query_cells(cell_type, 1)[0].clone()
    }

    pub(crate) fn reset(&mut self, height_limit: usize) {
        assert!(height_limit <= self.height);
        self.height_limit = height_limit;
        for column in self.columns.iter_mut() {
            column.height = 0;
        }
    }

    fn next_column(&self, cell_type: CellType) -> usize {
        let mut best_index: Option<usize> = None;
        let mut best_height = self.height;
        for column in self.columns.iter() {
            if column.cell_type == cell_type && column.height < best_height {
                best_index = Some(column.index);
                best_height = column.height;
            }
        }
        if best_height >= self.height_limit {
            best_index = None;
        }
        match best_index {
            Some(index) => index,
            None => unreachable!("not enough cells for query: {:?}", cell_type),
        }
    }

    pub(crate) fn get_height(&self) -> usize {
        self.columns
            .iter()
            .map(|column| column.height)
            .max()
            .unwrap()
    }

    /// Returns a map of CellType -> (width, height, num_cells)
    pub(crate) fn get_stats(&self) -> BTreeMap<CellType, (usize, usize, usize)> {
        let mut data = BTreeMap::new();
        for column in self.columns.iter() {
            let (mut count, mut height, mut num_cells) =
                data.get(&column.cell_type).unwrap_or(&(0, 0, 0));
            count += 1;
            height = height.max(column.height);
            num_cells += column.height;
            data.insert(column.cell_type, (count, height, num_cells));
        }
        data
    }

    pub(crate) fn columns(&self) -> &[CellColumn<F>] {
        &self.columns
    }
}