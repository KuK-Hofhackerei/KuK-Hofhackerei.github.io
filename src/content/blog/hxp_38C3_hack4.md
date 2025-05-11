---
title: "Writeup: hxp_silicon_foundaries_hack4"
description: "A multi stage exploitation challenge that requires you to exploit custom x86-64 instructions to gain privilege escalation under Linux and then escape the QEMU VM."
pubDate: "May 11 2025"
heroImage: "/hxp_38C3_hack4.png"
Author: 0x6fe1be2
---
Author: 0x6fe1be2

**Description:**
> You have the great pleasure of sampling our HXP HACK-4 AI1337 processor - an intersection of Security and AI. \  
> Like it? We have many in the pipeline! \
> [Dist](https://2024.ctf.link/assets/files/hxp_silicon_foundaries_hack4-7786be6f6ac42883.tar.xz) \
> - <cite>sisu</cite>

# TL;DR

# Overview

## Files

*hxp_silicon_foundaries_hack4-7786be6f6ac42883.tar.xz*
```
.
└── hxp_silicon_foundaries_hack4
    ├── Dockerfile
    ├── bzImage
    ├── compose.yml
    ├── example_program
    │   ├── ai.s
    │   ├── build.sh
    │   └── main.c
    ├── flag.txt
    ├── hxp_ai1337.pdf
    ├── initramfs.cpio
    ├── launch_vm.sh
    ├── linux_build
    │   └── 0001-Add-PR_SET_SCRATCH_HOLE.patch
    ├── pow-solver
    ├── pow-solver.cpp
    ├── qemu_build
    │   ├── 0001-Add-hack4-ai1337.patch
    │   ├── Dockerfile
    │   └── build_package
    │       ├── bios-256k.bin
    │       ├── efi-e1000.rom
    │       ├── kvmvapic.bin
    │       ├── linuxboot_dma.bin
    │       └── qemu_system_x86_64_ai1337
    └── ynetd

```

### Deployment

The challenge creators where nice enough to give us basically all files necessary for creating

### Challenge


| Opcode | Instruction | Description |
| - | - | - |
| `0F 0A 83` | `MTS` | Load RCX bytes from memory address (RSI) to slice (RBX) at slice offset (RDI) |
| `0F 0A 84` | `STM` | Read RCX bytes from slice (RBX) at slice offset (RDI) and write memory address (RSI) |
| `0F 0A 85` | `FSCR` | Clear all slices |
| `0F 0A 86` | `SCRADD` | Add the slices pointed by RDI and RSI, and store the result into slice pointed by RDX |
` 0F 0A 87` | `SCRSUB` | Subtract the slices pointed by RDI and RSI, and store the result into slice pointed by RDX |
| `0F 0A 88` | `SCRMUL` | Multiply the slices pointed by RDI and RSI, and store the result into slice pointed by RDX |
| `0F 0A 89` | `SCRHLW` (privileged) | Update scratch memory PSCHORR bi-ATS base VA |
| `0F 0A 8A` | `SCRHLR` | Read scratch memory PSCHORR bi-ATS base VA|


# Test Environment

- [vagd](https://github.com/gfelber/vagd) userland exploitation templates using docker
- [how2keap](https://github.com/gfelber/how2keap) kernel exploitation template
- [pwndbg](http://github.com/pwndbg/pwndbg) gdb plugin for kernel- and userland



# Vulnerabilities




# Linux Privilege Escalation



# QEMU Escape



# Exploit

*ai.s*
<details>

```assembly

```

</details>

*pwn.c*
<details>

```c

```


</details>

FLAG: `hxp{tH1s_1s_th3_AI_$$$s3Ri3$$$_n0t_tH3_s3CuR3_s3R1eS}`