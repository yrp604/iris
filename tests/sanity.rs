use serde::Deserialize;

use iris::DwarfVm;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq)]
struct TraceState {
    pc: u64,
    stack_sz: usize,
    stack: Vec<u64>,
}

#[test]
fn sanity() {
    let core = include_bytes!("../res/entry2.core");

    // pc  = start of dwarf bytecode
    // ctx = taken from stack trace args
    let mut dvm = DwarfVm::new(0x400258, 0x7fffffe110, core);

    let states: Vec<TraceState> = serde_json::from_str(include_str!("../res/sanity-states.json"))
        .expect("Could not deserialize state trace");

    // we start at the second ins
    let _ = dvm.step();
    let _ = dvm.step();

    let mut ins = 2;

    for state in states {
        println!(
            "ins {}, trace pc {:x}, trace stack sz {}, trace stack {:x?}",
            ins, state.pc, state.stack_sz, state.stack
        );

        let shortstack = dvm
            .stack
            .iter()
            .rev()
            .take(5)
            .rev()
            .map(|x| *x)
            .collect::<Vec<u64>>();
        println!(
            "ins {}, dvm   pc {:x}, dvm   stack sz {}, dvm   stack {:x?}",
            ins,
            dvm.pc,
            dvm.stack.len(),
            shortstack
        );

        assert_eq!(state.pc, dvm.pc);
        assert_eq!(state.stack_sz, dvm.stack.len());
        if dvm.stack.len() > 5 {
            assert_eq!(state.stack, shortstack);
        } else {
            assert_eq!(state.stack, dvm.stack);
        }

        println!("checked step {}...", ins);

        ins += 1;
        let _ = dvm.step();
    }
}
