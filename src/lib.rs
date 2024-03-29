use std::collections::BTreeMap;
use std::convert::TryInto;
use std::error::Error;
use std::fmt;

use log::*;
use xmas_elf::ElfFile;

use dwarf_dis::{decode, Op};

/// A DwarfVm state snapshot
#[derive(Clone, Debug, Default, Hash, Eq, PartialEq)]
pub struct DwarfVmState {
    pc: u64,
    stack: Vec<u64>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum DwarfVmError {
    Decode,
    Breakpoint,
}

impl fmt::Display for DwarfVmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for DwarfVmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// A Dwarf Stack Virtual Machine
pub struct DwarfVm<'a> {
    pub pc: u64,
    pub stack: Vec<u64>,
    ctx: u64,
    overlay: BTreeMap<u64, Vec<u8>>,
    breakpoints: BTreeMap<u64, Box<dyn FnMut(&mut Self, &mut Op) -> bool>>,
    core: ElfFile<'a>,
}

impl<'a> fmt::Display for DwarfVm<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DwarfVm {{ pc: {:#x}, stack: {:x?} }}",
            self.pc, self.stack
        )
    }
}

impl<'a> DwarfVm<'a> {
    /// Create a new Dwarf VM
    ///
    /// pc: the initial PC value for the dwarf VM from the coredump
    /// ctx: the address of the dwarf context structure. This is an argument to
    /// `execute_stack_op` and the dwarf VM will use it to fetch registers.
    /// core: the backing memory for the emulator, can be created via `gcore`
    /// from gdb.
    pub fn new(pc: u64, ctx: u64, core: &'a [u8]) -> Self {
        let stack = Default::default();
        let core = ElfFile::new(&core).expect("Could not parse core");

        Self {
            pc,
            ctx,
            stack,
            overlay: BTreeMap::default(),
            breakpoints: BTreeMap::default(),
            core,
        }
    }

    /// Execute a single Dwarf VM instruction
    pub fn step(&mut self) -> Result<(), DwarfVmError> {
        let (sz, mut op) = decode(self.target_read(self.pc)).map_err(|_| DwarfVmError::Decode)?;

        let bkpt = self.breakpoints.remove(&self.pc);

        if let Some(mut bkpt) = bkpt {
            let bail = bkpt(self, &mut op);

            self.breakpoints.insert(self.pc, bkpt);

            if bail {
                return Err(DwarfVmError::Breakpoint);
            }
        };

        self.pc += sz as u64;

        match op {
            Op::Addr(a) => self.push(self.target_read_u64(a)),
            Op::Deref => {
                let t = self.pop();
                self.push(self.target_read_u64(t))
            }
            Op::Const1u(v) => self.push(v as u64),
            Op::Const1s(v) => self.push(v as u64),
            Op::Const2u(v) => self.push(v as u64),
            Op::Const2s(v) => self.push(v as u64),
            Op::Const4u(v) => self.push(v as u64),
            Op::Const4s(v) => self.push(v as u64),
            Op::Const8u(v) | Op::Constu(v) => self.push(v as u64),
            Op::Const8s(v) | Op::Consts(v) => self.push(v as u64),
            Op::Dup => {
                let t = self.pop();
                self.push(t);
                self.push(t);
            }
            Op::Drop => {
                let _ = self.pop();
            }
            Op::Over => {
                let t = self.idx(1);
                self.push(t);
            }
            Op::Pick(off) => {
                self.push(self.idx(off as usize));
            }
            Op::Swap => {
                let p = self.pop();
                let q = self.pop();

                self.push(p);
                self.push(q);
            }
            Op::Rot => {
                let x = self.pop();
                let y = self.pop();
                let z = self.pop();

                self.push(x);
                self.push(z);
                self.push(y);
            }
            Op::Abs => {
                let t = self.pop() as i64;
                self.push(t.abs() as u64);
            }
            Op::And => {
                let p = self.pop();
                let q = self.pop();

                self.push(q & p);
            }
            Op::Div => {
                let p = self.pop();
                let q = self.pop();

                self.push(q / p);
            }
            Op::Minus => {
                let p = self.pop();
                let q = self.pop();

                self.push(q.wrapping_sub(p));
            }
            Op::Mod => {
                let p = self.pop();
                let q = self.pop();

                self.push(q % p);
            }
            Op::Mul => {
                let p = self.pop();
                let q = self.pop();

                self.push(q.wrapping_mul(p));
            }
            Op::Neg => {
                let t = self.pop();

                self.push(-(t as i64) as u64);
            }
            Op::Not => {
                let t = self.pop();

                self.push(!t);
            }
            Op::Or => {
                let p = self.pop();
                let q = self.pop();

                self.push(q | p);
            }
            Op::Plus => {
                let p = self.pop();
                let q = self.pop();

                self.push(q.wrapping_add(p));
            }
            Op::PlusConst(v) => {
                let t = self.pop();

                self.push(t.wrapping_add(v));
            }
            Op::Shl => {
                let p = self.pop();
                let q = self.pop();

                self.push(q << p);
            }
            Op::Shr => {
                let p = self.pop();
                let q = self.pop();

                self.push(q >> p);
            }
            Op::Shra => {
                let p = self.pop();
                let q = self.pop();

                self.push(q >> p);
            }
            Op::Xor => {
                let p = self.pop();
                let q = self.pop();

                self.push(q ^ p);
            }
            Op::Bra(off) => {
                if self.pop() != 0 {
                    self.pc = self.pc.wrapping_add(off as i64 as u64);
                }
            }
            Op::Eq => {
                let p = self.pop();
                let q = self.pop();

                self.push(u64::from(q == p));
            }
            Op::Ge => {
                let p = self.pop();
                let q = self.pop();

                self.push(u64::from(q >= p));
            }
            Op::Gt => {
                let p = self.pop();
                let q = self.pop();

                self.push(u64::from(q > p));
            }
            Op::Le => {
                let p = self.pop();
                let q = self.pop();

                self.push(u64::from(q <= p));
            }
            Op::Lt => {
                let p = self.pop();
                let q = self.pop();

                self.push(u64::from(q < p));
            }
            Op::Ne => {
                let p = self.pop();
                let q = self.pop();

                self.push(u64::from(q != p));
            }
            Op::Skip(off) => self.pc = self.pc.wrapping_add(off as i64 as u64),
            Op::Lit(v) => self.push(v as u64),
            Op::Reg(r) => {
                let p = self.target_read_u64(self.ctx + r as u64 * 8);
                let q = self.target_read_u64(p);

                self.push(q);
            }
            Op::BReg(_, _) => todo!(),
            Op::RegX(_) => todo!(),
            Op::BRegX(_, _) => todo!(),
            Op::DerefSize(sz) => {
                let t = self.pop();

                let v = match sz {
                    8 => self.target_read_u64(t),
                    4 => self.target_read_u32(t) as u64,
                    2 => self.target_read_u16(t) as u64,
                    1 => self.target_read_u8(t) as u64,
                    _ => panic!(format!("Bad size to DerefSize ({})", sz)),
                };

                self.push(v);
            }
            Op::Nop => (),
        }

        Ok(())
    }

    /// Execute many Dwarf VM instructions
    pub fn run(&mut self, limit: Option<usize>) -> Result<usize, DwarfVmError> {
        let mut ins = 0;
        loop {
            if let Some(limit) = limit {
                if ins >= limit {
                    return Ok(ins);
                }
            }

            let _ = self.trace_state(3);

            match self.step() {
                Err(DwarfVmError::Breakpoint) => return Ok(ins),
                Err(e) => return Err(e),
                _ => (),
            }

            ins += 1;
        }
    }

    /// Dump the current DwarfVM state
    ///
    /// This avoids dumping the context structure and coredump, as these are
    /// immutable once emulation starts and would add significant overhead.
    pub fn state(&self) -> DwarfVmState {
        DwarfVmState {
            pc: self.pc,
            stack: self.stack.clone(),
        }
    }

    /// Load a DwarfVM state
    pub fn set_state(&mut self, state: &DwarfVmState) {
        self.pc = state.pc;
        self.stack = state.stack.clone();
    }

    fn push(&mut self, v: u64) {
        self.stack.push(v)
    }

    fn pop(&mut self) -> u64 {
        self.stack.pop().expect("Attempt to pop from empty stack!")
    }

    fn idx(&self, n: usize) -> u64 {
        *self
            .stack
            .iter()
            .rev()
            .nth(n)
            .expect("Attempt to index past stack bounds")
    }

    /// Log the current state via warn
    pub fn log_state(&self, stack_amt: usize) -> Result<(), DwarfVmError> {
        let (_, op) = decode(self.target_read(self.pc)).map_err(|_| DwarfVmError::Decode)?;
        warn!("pc: 0x{:04x} [{}]", self.pc, op);
        warn!("sp: 0x{:04x}", self.stack.len() * 8);
        for (ii, vv) in self.stack.iter().rev().take(stack_amt).enumerate() {
            warn!("{:02x} | {:016x}", ii * 8, vv);
        }
        warn!("------------");

        Ok(())
    }

    /// Log the current state via trace
    pub fn trace_state(&self, stack_amt: usize) -> Result<(), DwarfVmError> {
        let (_, op) = decode(self.target_read(self.pc)).map_err(|_| DwarfVmError::Decode)?;
        trace!("pc: 0x{:04x} [{}]", self.pc, op);
        trace!("sp: 0x{:04x}", self.stack.len() * 8);
        for (ii, vv) in self.stack.iter().rev().take(stack_amt).enumerate() {
            trace!("{:02x} | {:016x}", ii * 8, vv);
        }
        trace!("------------");

        Ok(())
    }

    /// Get the current memory overlay BTree
    pub fn overlay(&mut self) -> &mut BTreeMap<u64, Vec<u8>> {
        // Note that memory overlay checks are very inefficient right now, if you
        // need to make heavy use of these please file an issue.
        &mut self.overlay
    }

    /// get the current breakpoints BTree
    pub fn breakpoints(
        &mut self,
    ) -> &mut BTreeMap<u64, Box<dyn FnMut(&mut Self, &mut Op) -> bool>> {
        &mut self.breakpoints
    }

    /// Add a new breakpoint
    pub fn set_breakpoint<F: 'static + FnMut(&mut Self, &mut Op) -> bool>(
        &mut self,
        pc: u64,
        bkpt: F,
    ) {
        self.breakpoints.insert(pc, Box::new(bkpt));
    }

    fn target_read(&self, a: u64) -> &[u8] {
        // first check the overlay
        for (start, v) in &self.overlay {
            let end = *start + v.len() as u64;

            if a >= *start && a < end {
                let off = (a - *start) as usize;
                return &v[off..];
            }
        }

        // then check the core
        let sec = self
            .core
            .section_iter()
            .find(|&x| a >= x.address() && a <= x.address() + x.size())
            .expect(&format!("Could not find section for address {:#x}", a));

        let data = sec.raw_data(&self.core);
        let off = (a - sec.address()) as usize;

        &data[off..]
    }

    fn target_read_u8(&self, a: u64) -> u8 {
        let data = self.target_read(a);

        let v = data[0];

        trace!("read u8  0x{:016x} = 0x{:02x}", a, v);

        v
    }

    fn target_read_u16(&self, a: u64) -> u16 {
        let data = self.target_read(a);

        let v = u16::from_le_bytes(data[..2].try_into().unwrap());

        trace!("read u16 0x{:016x} = 0x{:04x}", a, v);

        v
    }

    fn target_read_u32(&self, a: u64) -> u32 {
        let data = self.target_read(a);

        let v = u32::from_le_bytes(data[..4].try_into().unwrap());

        trace!("read u32 0x{:016x} = 0x{:08x}", a, v);

        v
    }

    fn target_read_u64(&self, a: u64) -> u64 {
        let data = self.target_read(a);

        let v = u64::from_le_bytes(data[..8].try_into().unwrap());

        trace!("read u64 0x{:016x} = 0x{:016x}", a, v);

        v
    }
}
