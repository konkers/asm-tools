use std::collections::HashMap;

use failure::{format_err, Error};

use super::{AddressMode, Mnemonic};

pub(crate) struct Instruction {
    pub mnemonic: Mnemonic,
    pub address_modes: HashMap<AddressMode, u8>,
}

pub(crate) struct InstructionTable {
    pub instructions: HashMap<Mnemonic, Instruction>,
    pub opcodes: HashMap<u8, (Mnemonic, AddressMode)>,
    pub mnemonic_map: HashMap<String, Mnemonic>,
}

impl InstructionTable {
    pub fn new() -> InstructionTable {
        InstructionTable {
            instructions: HashMap::new(),
            opcodes: HashMap::new(),
            mnemonic_map: HashMap::new(),
        }
    }

    pub fn add_op(
        &mut self,
        mnemonic: Mnemonic,
        opcode: u8,
        mode: AddressMode,
    ) -> Result<(), Error> {
        if self.opcodes.contains_key(&opcode) {
            return Err(format_err!(
                "Trying to add duplicate opcode {:02x} for {:?}:{:?}.",
                opcode,
                &mnemonic,
                &mode
            ));
        }

        if !self.instructions.contains_key(&mnemonic) {
            self.instructions.insert(
                mnemonic,
                Instruction {
                    mnemonic,
                    address_modes: HashMap::new(),
                },
            );
        }

        let inst = self.instructions.get_mut(&mnemonic).unwrap();
        if inst.address_modes.contains_key(&mode) {
            return Err(format_err!(
                "Trying to add duplicate addressing mode {:?} for {:?}.",
                &mode,
                &mnemonic
            ));
        }
        inst.address_modes.insert(mode, opcode);
        self.opcodes.insert(opcode, (mnemonic, mode));
        let mnemonic_str: String = mnemonic.into();
        self.mnemonic_map
            .insert(mnemonic_str.to_lowercase(), mnemonic);

        Ok(())
    }
}
