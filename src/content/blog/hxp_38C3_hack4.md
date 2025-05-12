---
title: "Writeup: hxp_silicon_foundaries_hack4"
description: "A multi stage exploitation challenge that requires you to exploit custom x86-64 instructions to gain privilege escalation under Linux and then escape the QEMU VM."
pubDate: "Dec 30 2024"
heroImage: "/hxp_38C3_hack4.png"
Author: 0x6fe1be2
---
Author: [0x6fe1be2](https://github.com/gfelber)

**Description:**
> You have the great pleasure of sampling our HXP HACK-4 AI1337 processor - an intersection of Security and AI. \
> Like it? We have many in the pipeline!
>
> [Dist](https://2024.ctf.link/assets/files/hxp_silicon_foundaries_hack4-7786be6f6ac42883.tar.xz)
>
> -- <cite>sisu</cite>

# TL;DR

The challenge consists of a modified QEMU binary which adds new instructions to the existing x86-64 set, notably `MTS` (load bytes from scratch memory), `STM` (store bytes to scratch memory) which are unprivileged and `SCRHLW` (update scratch memory) which is privileged. \
Additionally two MSR (Model Specific Registers) where added `MSR_HACK4_SLICE_SIZE=0x400` and `MSR_HACK4_NUM_SLICES=33`
The privileged `SCRHLW` instruction can be access through a patched in `prctl` option `PR_SET_SCRATCH_HOLE` inside the linux kernel and seems to directly update the TLB (Translation Lookaside Buffer) which we can exploit.

1. We exploit the TLB update in `SCRHLW` to inject CPL0 shellcode
2. We modify the MSR to allow OOB Access, they are mapped to a stack array in QEMU
3. we use the OOB Access to write a ROP Chain inside QEMU, to escape and get the flag

# Overview
Lets give a brief overview of the challenge components.

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

The challenge creators where nice enough to give us basically all files necessary for creating. This is going to be mostly interesting when exploiting the QEMU binary as this pretty similar to userland exploitation and knowing the correct libraries through the *Dockerfile* will be helpful.

We can also see that the flag is not inside the VMs telling us that we will have to escape the QEMU VM if we want to get it.

### Challenge
Now lets look at the more interesting files:

#### Kernel

The kernel related files seems to be rather standard, we have a *initramfs.cpio* which contains our filesystems (Note: kernel challenges normally don't bother booting into a e.g. XFS rootfs and just stay inside the initramfs) and a kernel bzImage (which seems to be `6.12.1`).

We have also been give a kernel patch file, which seems to add a new `prctl` option called `PR_SET_SCRATCH_HOLE` and seems to execute a "new" assembly instructions, which has been added through QEMU.

*0001-Add-PR_SET_SCRATCH_HOLE.patch*

<details>

```diff

```

</details>


Even though the linux kernel doesn't seem to have a deliberate vulnerability it will be important, because we start out as a unprivileged user. Usually QEMU exploit require higher privileged access, which we should keep in mind.


#### QEMU

QEMU seems to be the focus of this challenge. We are given a patched binary *qemu_system_x86_64_ai1337* and a patch file which we will have to analyse, because it's probably where the vulnerability will lie.

*0001-Add-hack4-ai1337.patch*
<details>

```diff

```

</details>

#### Docs

We have also been give some form of Device Specification in form of a pdf (*hxp_silicon_foundaries_hack4/hxp_ai1337.pdf*). Which seems to explain a number of Instructions/MSR which have been added through QEMU and will be the target of our exploit:

Instructions:
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

MSR:
| MSR | Identifier | Description |
| - | - | - |
| `MSR_HACK4_SLICE_SIZE` | `0xC0000105` | Read/Write slice size in the AI1337 engine |
| `MSR_HACK4_NUM_SLICES` | `0xC0000106` | Read/Write count of slices in the AI1337 engine |

We also receive multiple ASCII diagrams notably, which is going to be relevant.
```
      Physical Memory                Virtual Memory
            0                               |
            |                               |
  IO space  |                               |
            |                               |
            -                               |
            |                               |
            |                               |
            |                               |   Direct Addressing
    RAM     |                               |           |
            |    ___________________________|_____      |
            |   /                       |        |      |
            ---/                        | bi-ATS |------|
            |                           |        |
            |    _______________________|________|
  AI1337    |   /
 aperture   |  /  PSCHORR Interconnect
            ---

```

## Test Environment

I'm using the following tools for writing and testing my exploit:

- [vagd](https://github.com/gfelber/vagd) userland exploitation templates using docker which is based on [pwntools](https://github.com/Gallopsled/pwntools)
- [how2keap](https://github.com/gfelber/how2keap) kernel exploitation template
- [pwndbg](http://github.com/pwndbg/pwndbg) gdb plugin for kernel- and userland exploitation

# Exploit

Lets start with writing our exploit:

## Vulnerabilities

As teased before there seem to be vulnerabilities in the implementation of the x86-64 extension called AI1337. Let's have a closer look at the patches

First we define some constants which will be relevant for our extension

*target/i386/ops_ai1337.h*
```c
#define AI1337_SCRATCH_SIZE (33ULL * 1024)
#define AI1337_SCRATCH_MAX_NUM_SLICES (128)
#define AI1337_SCRATCH_SLICE_SIZE_DEFAULT (1024ULL)
#define AI1337_SCRATCH_NUM_SLICES_DEFAULT (33UL)
#define AI1337_SCRATCH_MAX_SLICE_SIZE (4096ULL)
```

Then we need to initialise our new variable directly in the CPU. Note that we use a stack array `cratch[AI1337_SCRATCH_SIZE]` and use it for our scratch operations. It seems like this won't be able to hold `AI1337_SCRATCH_MAX_NUM_SLICES * AI1337_SCRATCH_MAX_SLICE_SIZE` (Foreshadowing).

*target/i386/cpu.c*
```c
...
        env->scratch_config.num_active_slices = AI1337_SCRATCH_NUM_SLICES_DEFAULT;
        env->scratch_config.slice_size = AI1337_SCRATCH_SLICE_SIZE_DEFAULT;
        env->scratch_config.va_base = AI1337_SCRATCH_VA_BASE;
        env->scratch_config.phys_base = AI1337_SCRATCH_PHYS_BASE;
        env->scratch_config.access_enabled = 0;

        uint16_t scratch[AI1337_SCRATCH_SIZE];
        env->scratch_region = malloc(sizeof(MemoryRegion));
        memset(env->scratch_region, 0, sizeof(*env->scratch_region));
        memory_region_init_ram_ptr(env->scratch_region, NULL, "ai1337-scratch", AI1337_SCRATCH_SIZE, scratch);
        env->scratch_region->ram_block->flags |= RAM_RESIZEABLE;
        env->scratch_region->ram_block->max_length = AI1337_SCRATCH_MAX_NUM_SLICES * AI1337_SCRATCH_MAX_SLICE_SIZE;
        memory_region_add_subregion(get_system_memory(), AI1337_SCRATCH_PHYS_BASE, env->scratch_region);
        ...
```

When we edit MSR we directly change the values inside our CPU config without reinitialising our `scratch_region` which should lead to a `OOB`. Sadly we  are only able to edit MSR directly in CPL0 which isn't possible with a unprivileged user.
*target/i386/tcg/sysemu/misc_helper.c*
```c
...
static bool helper_recalculate_scratch(CPUX86State *env, uint32_t new_num_slices, uint32_t new_slice_size)
{
    if (new_num_slices > AI1337_SCRATCH_MAX_NUM_SLICES) {
        return false;
    }
    if (new_slice_size > AI1337_SCRATCH_MAX_SLICE_SIZE) {
        return false;
    }
    uint32_t new_size = new_num_slices * new_slice_size;
    Error *err = NULL;
    bql_lock();
    memory_region_ram_resize(env->scratch_region, new_size, &err);
    bql_unlock();
    if (err) {
        return false;
    }
    env->scratch_config.num_active_slices = new_num_slices;
    env->scratch_config.slice_size = new_slice_size;
    return true;
}

void helper_wrmsr(CPUX86State *env)
...
    case MSR_HACK4_SLICE_SIZE:
        const uint32_t new_slice_size = val;
        if (!helper_recalculate_scratch(env, env->scratch_config.num_active_slices, new_slice_size)) {
            goto error;
        }
        break;
    case MSR_HACK4_NUM_SLICES:
        const uint32_t new_num_active_slices = val;
        if (!helper_recalculate_scratch(env, new_num_active_slices, env->scratch_config.slice_size)) {
            goto error;
        }
        break;
...
void helper_rdmsr(CPUX86State *env)
...
    case MSR_HACK4_SLICE_SIZE:
        val = env->scratch_config.slice_size;
        break;
    case MSR_HACK4_NUM_SLICES:
        val = env->scratch_config.num_active_slices;
        break;
...

```

And yeah it looks like we have a OOB when writing or reading from the `scratch_region` after editing the MSR.

*target/i386/tcg/translate.c*
```c
...
static void gen_mts_8(DisasContext *s, MemOp ot)
{
    const size_t slice_size_offset = offsetof(CPUX86State, scratch_config.slice_size);
    const size_t va_base_offset = offsetof(CPUX86State, scratch_config.va_base);
    const size_t access_offset = offsetof(CPUX86State, scratch_config.access_enabled);

    const TCGv slice_index = cpu_regs[R_EBX];
    const TCGv offset_in_slice = cpu_regs[R_EDI];
    const TCGv memory_address = cpu_regs[R_ESI];
    const TCGv dshift = gen_compute_Dshift(s, ot);

    tcg_gen_st_tl(tcg_constant_i64(1), tcg_env, access_offset);

    // load from memory address
    gen_lea_v_seg(s, memory_address, R_DS, -1);
    gen_op_ld_v(s, MO_8, s->T0, s->A0);

    // Calculate address for scratch
    // A0 = offset_in_slice + slice_base + (slice_index * slice_size)
    tcg_gen_ld_tl(s->A0, tcg_env, va_base_offset);
    gen_lea_v_seg(s, s->A0, R_ES, -1);
    tcg_gen_add_tl(s->A0, s->A0, offset_in_slice);
    tcg_gen_ld32u_tl(s->tmp0, tcg_env, slice_size_offset);
    tcg_gen_mul_tl(s->tmp0, s->tmp0, slice_index);
    tcg_gen_add_tl(s->A0, s->A0, s->tmp0);

    // Store value
    gen_op_st_v(s, MO_8, s->T0, s->A0);

    gen_op_add_reg(s, s->aflag, R_ESI, dshift);
    gen_op_add_reg(s, s->aflag, R_EDI, dshift);

    tcg_gen_st_tl(tcg_constant_i64(0), tcg_env, access_offset);
}

static void gen_stm_8(DisasContext *s, MemOp ot)
{
    ...
    // similar to gen_mts_8
    ...
}

```

Finally let's have a look at  the inner workings of `SCRHLW`.

*target/i386/tcg/emit.c.inc*
```c
static void gen_SCRHLW(DisasContext *s, X86DecodedInsn *decode)
{
    if (CPL(s) != 0)
    {
        gen_illegal_opcode(s);
        return;
    }
    size_t va_base_offset = offsetof(CPUX86State, scratch_config.va_base);
    tcg_gen_st_tl(cpu_regs[R_EDI], tcg_env, va_base_offset);
}

```

And we notice that this seems to unsafely update the TLB, which we can exploit.

*target/i386/tcg/sysemu/excp_helper.c*
```c
...
bool x86_cpu_tlb_fill(CPUState *cs, vaddr addr, int size,
                      MMUAccessType access_type, int mmu_idx,
                      bool probe, uintptr_t retaddr)
...
    if (env->scratch_config.access_enabled &&
        (addr >= env->scratch_config.va_base) &&
        ((addr + size) <= (env->scratch_config.va_base + x86_calculate_scratch_size(env)))) {
        vaddr paddr = env->scratch_config.phys_base + (addr - env->scratch_config.va_base);
        tlb_set_page_with_attrs(cs, addr & TARGET_PAGE_MASK,
                                paddr & TARGET_PAGE_MASK,
                                cpu_get_mem_attrs(env),
                                PAGE_READ | PAGE_WRITE | PAGE_EXEC, mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }
...

```


## Linux Privilege Escalation



## QEMU Escape

## Final

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