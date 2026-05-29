use std::{env, fs};

use goblin::elf::Elf;
use unicorn_engine::{Arch, Mode, Prot, RegisterARM64, Unicorn};

const FRAG1: &[u8] = include_bytes!("../frag1.bin");
const FRAG2: &[u8] = include_bytes!("../frag2.bin");
const FUN_LEN: usize = 0x1330;

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("no enough arguments: needs 1");
    }
    let file =
        fs::read(args[1].clone()).unwrap_or_else(|_| panic!("no file found: {}", args[1].clone()));
    log::info!("┌───────────────────────┐");
    log::info!("│   scirpophaga 0.1.0   │");
    log::info!("│  qxalaris nofyso ww~  │");
    log::info!("└───────────────────────┘");
    if let Err(e) = start(&file) {
        log::error!("{e}");
    }
}

fn start(input: &[u8]) -> anyhow::Result<()> {
    log::info!("[*] searching in input, len: 0x{:x}", input.len());
    let pos1 = input
        .windows(FRAG1.len())
        .position(|it| it == FRAG1)
        .unwrap();
    log::info!("[+] found C2_pre1 fn offset: 0x{:x}", pos1);
    let pos2 = input
        .windows(FRAG2.len())
        .position(|it| it == FRAG2)
        .unwrap();
    log::info!("[+] found C2_pre2 fn offset: 0x{:x}", pos2);
    log::info!("[*] parsing elf, len: 0x{:x}", input.len());
    let elf = try_parse_elf(input)?;
    log::info!("[+] found elf PT_LOAD segments:");
    for (
        i,
        ElfInit {
            mem_offset,
            file_offset,
            file_sz,
            mem_sz,
            v_data,
        },
    ) in elf.iter().enumerate()
    {
        log::info!(
            "      #{}: file_offset:0x{:x}, file_len: 0x{:x}, mem_offset: 0x{:x}, mem_len: 0x{:x}, data_len:0x{:x}",
            i,
            file_offset,
            file_sz,
            mem_offset,
            mem_sz,
            v_data.len()
        );
    }
    log::info!("[*] running sample1: C2_pre1");
    let output = sim(input, pos1 as u64, FUN_LEN as u64, &elf)?;
    log::info!("[+] running finished");
    log::info!("      Q0: {:x}", output.0);
    log::info!("      Q1: {:x}", output.1);
    log::info!("[*] running sample2: C2_pre2");
    let output2 = sim_2(input, pos2 as u64, 0x2974, &elf)?;
    log::info!("[+] running finished");
    log::info!("      Q0: {:x}", output2.0);
    log::info!("      Q1: {:x}", output2.1);
    log::info!("[+] C2 (predictive) = ");
    log::info!(
        "    {}{}",
        reversed_string(output.0 ^ output2.0),
        reversed_string(output.1 ^ output2.1)
    );
    Ok(())
}

fn reversed_string(i: u128) -> String {
    let mut str = String::new();
    for it in i.to_le_bytes().iter() {
        str += &format!("{:02x}", it);
    }
    str
}

struct ElfInit {
    mem_offset: u64,
    file_offset: u64,
    file_sz: u64,
    mem_sz: u64,
    v_data: Vec<u8>,
}

fn try_parse_elf(bin: &[u8]) -> Result<Vec<ElfInit>, goblin::error::Error> {
    let elf = Elf::parse(bin)?;
    let mut output = vec![];
    for it in &elf.program_headers {
        if it.p_type == goblin::elf64::program_header::PT_LOAD {
            let va = it.p_vaddr;
            let filesz = it.p_filesz;
            let memsz = it.p_memsz;
            let offset = it.p_offset as usize;
            let range = &bin[offset..offset + filesz as usize];
            output.push(ElfInit {
                mem_offset: va,
                file_offset: offset as u64,
                file_sz: filesz,
                mem_sz: memsz,
                v_data: Vec::from(range),
            });
        }
    }
    Ok(output)
}

fn sim(
    bin: &[u8],
    offset: u64,
    len: u64,
    elf_mapping: &[ElfInit],
) -> Result<(u128, u128), unicorn_engine::uc_error> {
    let mut uc = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)?;
    let base_addr = 0x1000_0000;
    let base_size = 0x2000_0000;
    let stack_addr = 0x4000_0000;
    let stack_size = 0x1000_0000;
    let sp_addr = stack_addr + stack_size / 2;
    uc.mem_map(base_addr, base_size, Prot::ALL)?;
    uc.mem_map(stack_addr, stack_size, Prot::ALL)?;
    uc.mem_write(base_addr, bin)?;
    uc.mem_map(0x0000_0000, 0x1000_0000, Prot::ALL)?;
    for ElfInit {
        mem_offset,
        file_sz,
        mem_sz,
        v_data,
        ..
    } in elf_mapping
    {
        uc.mem_write(base_addr + *mem_offset, v_data)?;
        uc.mem_write(
            mem_offset + file_sz,
            &vec![0u8; (mem_sz - file_sz) as usize],
        )?;
    }
    uc.reg_write(RegisterARM64::SP, sp_addr)?;
    uc.emu_start(base_addr + offset, base_addr + offset + len, 0, 0)?;
    Ok((
        uc_print_long_reg(&uc, RegisterARM64::Q0),
        uc_print_long_reg(&uc, RegisterARM64::Q1),
    ))
}

fn sim_2(
    bin: &[u8],
    offset: u64,
    len: u64,
    elf_mapping: &[ElfInit],
) -> Result<(u128, u128), unicorn_engine::uc_error> {
    let mut uc = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)?;
    let base_addr = 0x1000_0000;
    let base_size = 0x2000_0000;
    let stack_addr = 0x4000_0000;
    let stack_size = 0x1000_0000;
    let box_addr = 0x5000_0000;
    let box_size = 0x1000_0000;
    let para_addr = 0x6000_0000;
    let para_size = 0x1000_0000;
    let para1 = 0x0000_1000;
    let para2 = 0x0000_2000;
    let para3 = 0x0000_3000;
    let para4 = 0x0000_4000;

    let sp_addr = stack_addr + stack_size / 2;
    uc.mem_map(base_addr, base_size, Prot::ALL)?;
    uc.mem_map(stack_addr, stack_size, Prot::ALL)?;
    uc.mem_map(box_addr, box_size, Prot::ALL)?;
    uc.mem_map(para_addr, para_size, Prot::ALL)?;
    uc.mem_write(base_addr, bin)?;
    uc.mem_map(0x0000_0000, 0x1000_0000, Prot::ALL)?;
    for ElfInit {
        mem_offset,
        file_sz,
        mem_sz,
        v_data,
        ..
    } in elf_mapping
    {
        uc.mem_write(base_addr + *mem_offset, v_data)?;
        uc.mem_write(
            base_addr + mem_offset + file_sz,
            &vec![0u8; (mem_sz - file_sz) as usize],
        )?;
    }
    uc.reg_write(RegisterARM64::X0, para_addr + para1)?;
    uc.reg_write(RegisterARM64::X1, para_addr + para2)?;
    uc.reg_write(RegisterARM64::X2, para_addr + para3)?;
    uc.reg_write(RegisterARM64::X3, para_addr + para4)?;
    uc.reg_write(RegisterARM64::SP, sp_addr + 0x5b0)?;
    uc_fill(
        &mut uc,
        base_addr + offset + 0x14e4,
        base_addr + offset + 0x15bc,
    )?;
    // uc_dump(&uc, box_addr, 0x800)?;
    uc.emu_start(base_addr + offset, base_addr + offset + len, 0, 0)?;
    Ok((
        uc_print_long_reg(&uc, RegisterARM64::Q0),
        uc_print_long_reg(&uc, RegisterARM64::Q1),
    ))
}

fn uc_fill(uc: &mut Unicorn<'_, ()>, from: u64, to: u64) -> Result<(), unicorn_engine::uc_error> {
    //好吧，我承认这非常暴力，但是很好玩
    let len = (to - from) as usize;
    if !len.is_multiple_of(4) {
        panic!("not a valid length");
    }
    let mut o = vec![0u8; len];
    o.iter_mut().skip(3).step_by(4).for_each(|it| *it = 0x91);
    uc.mem_write(from, &o)?;
    Ok(())
}

fn uc_print_long_reg(uc: &Unicorn<'_, ()>, reg: RegisterARM64) -> u128 {
    let mut u = [0u8; 16];
    u.copy_from_slice(&uc.reg_read_long(reg).unwrap());
    u128::from_le_bytes(u)
}
