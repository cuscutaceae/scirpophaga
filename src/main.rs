use std::{env, fs};

use goblin::elf::Elf;
use unicorn_engine::{Arch, Mode, Prot, RegisterARM64, Unicorn};

const FRAG1: &[u8] = include_bytes!("../frag1.bin");
const FRAG2: &[u8] = include_bytes!("../frag2.bin");
const PRE1_FUN_LEN: usize = 0x1330;
const PRE2_RUN_LEN: usize = 0x2888;

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("no enough arguments: needs 1");
    }
    let file =
        fs::read(args[1].clone()).unwrap_or_else(|_| panic!("no file found: {}", args[1].clone()));
    log::info!(r"           _                        _                       ");
    log::info!(r"          (_)                      | |                      ");
    log::info!(r"  ___  ___ _ _ __ _ __   ___  _ __ | |__   __ _  __ _  __ _ ");
    log::info!(r" / __|/ __| | '__| '_ \ / _ \| '_ \| '_ \ / _` |/ _` |/ _` |");
    log::info!(r" \__ \ (__| | |  | |_) | (_) | |_) | | | | (_| | (_| | (_| |");
    log::info!(r" |___/\___|_|_|  | .__/ \___/| .__/|_| |_|\__,_|\__, |\__,_|");
    log::info!(r"                 | |         | |                 __/ |      ");
    log::info!(r" qxalaris nofyso |_| v0.1.1  |_|                |___/       ");
    log::info!(r"     Source: https://github.com/cuscutaceae/scirpophaga     ");
    log::info!("");
    if let Err(e) = start(&file) {
        log::error!("{e}");
    }
}

fn start(input: &[u8]) -> anyhow::Result<()> {
    #[derive(Debug, thiserror::Error)]
    enum Error {
        #[error("frag not found: {0}")]
        FragNotFound(String),
    }
    log::info!("[*] searching in input, len: 0x{:08x}", input.len());
    let pos1 = input
        .windows(FRAG1.len())
        .position(|it| it == FRAG1)
        .ok_or(Error::FragNotFound("FRAG1".to_string()))?;
    log::info!("[+] found C2_pre1 fn offset: 0x{:08x}", pos1);
    let pos2 = input
        .windows(FRAG2.len())
        .position(|it| it == FRAG2)
        .ok_or(Error::FragNotFound("FRAG2".to_string()))?;
    log::info!("[+] found C2_pre2 fn offset: 0x{:08x}", pos2);
    log::info!("[*] parsing elf, len: 0x{:08x}", input.len());
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
            "      #{}: file_offset:0x{:08x}, file_len: 0x{:08x}, mem_offset: 0x{:08x}, mem_len: 0x{:08x}, data_len:0x{:08x}",
            i,
            file_offset,
            file_sz,
            mem_offset,
            mem_sz,
            v_data.len()
        );
    }
    log::info!("[*] running sample1: C2_pre1");
    let output = sim_1(input, pos1 as u64, PRE1_FUN_LEN as u64, &elf)?;
    log::info!("[+] sim_1 finished");
    log::info!("      Q0: {:x}", output.0);
    log::info!("      Q1: {:x}", output.1);
    log::info!("[*] running sample2: C2_pre2");
    let output2 = sim_2(input, pos2 as u64, PRE2_RUN_LEN as u64, &elf)?;
    log::info!("[+] sim_2 finished");
    log::info!("      Q0: {:x}", output2.0);
    log::info!("      Q1: {:x}", output2.1);
    let c2 = format!(
        "{}{}",
        reversed_string(output.0 ^ output2.0),
        reversed_string(output.1 ^ output2.1)
    );
    log::info!("[+] C2 (predictive) = ");
    log::info!("    {}", c2);
    log::info!("[+] thank you for using scirpophaga ^w^");
    println!("{c2}");
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

fn sim_1(
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
    let prot_addr = 0x0000_0000;
    let prot_size = 0x1000_0000;
    let sp_addr = stack_addr + stack_size / 2;
    log::info!("[*] sim_1_info:");
    log::info!("      sim_base_off:   0x{base_addr:08x}");
    log::info!("      sim_base_size:  0x{base_size:08x}");
    log::info!("      sim_stack_off:  0x{stack_addr:08x}");
    log::info!("      sim_stack_size: 0x{stack_size:08x}");
    log::info!("      sim_prot_off:   0x{prot_addr:08x}");
    log::info!("      sim_prot_size:  0x{prot_size:08x}");
    log::info!("      sim_sp:         0x{sp_addr:08x}");
    uc.mem_map(base_addr, base_size, Prot::ALL)?;
    log::info!("[+] sim_1: mapped sim_base");
    uc.mem_map(stack_addr, stack_size, Prot::ALL)?;
    log::info!("[+] sim_1: mapped sim_stack");
    uc.mem_map(prot_addr, prot_size, Prot::ALL)?;
    log::info!("[+] sim_1: mapped prot");
    uc.mem_write(base_addr, bin)?;
    log::info!("[+] sim_1: loaded bin");
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
        log::info!(
            "[+] sim_1: initialized bss seg: file_sz: 0x{file_sz:08x}, mem_sz: 0x{mem_sz:08x} -> base_addr+0x{mem_offset:08x}"
        );
    }
    uc.reg_write(RegisterARM64::SP, sp_addr)?;
    log::info!("[+] sim_1: wrote registers(SP)");
    log::info!("      SP = {}", uc.reg_read(RegisterARM64::SP)?);
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
    // let box_addr = 0x5000_0000;
    // let box_size = 0x1000_0000;
    let para_addr = 0x6000_0000;
    let para_size = 0x1000_0000;
    let prot_addr = 0x0000_0000;
    let prot_size = 0x1000_0000;
    let para1 = 0x0000_1000;
    let para2 = 0x0000_2000;
    let para3 = 0x0000_3000;
    let para4 = 0x0000_4000;
    let sp_addr = stack_addr + stack_size / 2 + 0x5b0;

    log::info!("[*] sim_2_info:");
    log::info!("      sim_base_off:   0x{base_addr:08x}");
    log::info!("      sim_base_size:  0x{base_size:08x}");
    log::info!("      sim_stack_off:  0x{stack_addr:08x}");
    log::info!("      sim_stack_size: 0x{stack_size:08x}");
    log::info!("      sim_para_off:   0x{para_addr:08x}");
    log::info!("      sim_para_size:  0x{para_size:08x}");
    log::info!("      sim_para1_off:  0x{para1:08x}");
    log::info!("      sim_para2_off:  0x{para2:08x}");
    log::info!("      sim_para3_off:  0x{para3:08x}");
    log::info!("      sim_para4_off:  0x{para4:08x}");
    log::info!("      sim_prot_off:   0x{prot_addr:08x}");
    log::info!("      sim_prot_size:  0x{prot_size:08x}");
    log::info!("      sim_sp:         0x{sp_addr:08x}");

    uc.mem_map(base_addr, base_size, Prot::ALL)?;
    log::info!("[+] sim_2: mapped sim_base");
    uc.mem_map(stack_addr, stack_size, Prot::ALL)?;
    log::info!("[+] sim_2: mapped sim_stack");
    // uc.mem_map(box_addr, box_size, Prot::ALL)?;
    uc.mem_map(para_addr, para_size, Prot::ALL)?;
    log::info!("[+] sim_2: mapped sim_para");
    uc.mem_map(prot_addr, prot_size, Prot::ALL)?;
    log::info!("[+] sim_2: mapped sim_prot");
    uc.mem_write(base_addr, bin)?;
    log::info!("[+] sim_2: loaded bin");
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
        log::info!(
            "[+] sim_2: initialized bss seg: file_sz: 0x{file_sz:08x}, mem_sz: 0x{mem_sz:08x} -> base_addr+0x{mem_offset:08x}"
        );
    }
    uc.reg_write(RegisterARM64::X0, para_addr + para1)?;
    uc.reg_write(RegisterARM64::X1, para_addr + para2)?;
    uc.reg_write(RegisterARM64::X2, para_addr + para3)?;
    uc.reg_write(RegisterARM64::X3, para_addr + para4)?;
    uc.reg_write(RegisterARM64::SP, sp_addr)?;
    log::info!("[+] sim_2: wrote registers(SP, X0, X1, X2, X3)");
    log::info!("      X0 = 0x{:08x}", uc.reg_read(RegisterARM64::X0)?);
    log::info!("      X1 = 0x{:08x}", uc.reg_read(RegisterARM64::X1)?);
    log::info!("      X2 = 0x{:08x}", uc.reg_read(RegisterARM64::X2)?);
    log::info!("      X3 = 0x{:08x}", uc.reg_read(RegisterARM64::X3)?);
    log::info!("      SP = 0x{:08x}", uc.reg_read(RegisterARM64::SP)?);
    let fill_from = 0x13f8;
    let fill_to = 0x14d0;
    uc_fill(
        &mut uc,
        base_addr + offset + fill_from,
        base_addr + offset + fill_to,
    )?;
    log::info!(
        "[+] filled offset: 0x{fill_from:08x}~0x{fill_to:08x} (file_offset: 0x{:08x}~0x{:08x}) size: 0x{:08x}",
        offset + fill_from,
        offset + fill_to,
        fill_to - fill_from
    );
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
