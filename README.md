# Iris

![Iris the bunny](res/iris.jpg)

Iris is a DWARF emulator.

## Install

Clone `dwarf-dis` and `iris` into the same directory.

[dwarf-dis](https://github.com/yrp604/dwarf-dis)

## Usage

```rust
use iris::DwarfVm;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let argv: Vec<String> = std::env::args().collect();

    let core = std::fs::read(&argv[1])?;

    // pc   = start of dwarf bytecode
    // ctx  = taken from coredump stack trace of execute_stack_op
    // core = coredump of target address space
    let mut dvm = DwarfVm::new(0x400258, 0x7fffffe110, &core);

    // execute 10 instructions
    let exec_ins = dvm.run(Some(10))?;

    Ok(())
}

```

## Docs

`cargo doc --open`
