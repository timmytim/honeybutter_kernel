cmd_arch/arm/mm/proc-v7.o := arm-eabi-gcc -Wp,-MD,arch/arm/mm/.proc-v7.o.d  -nostdinc -isystem /home/tim/ICS/prebuilt/linux-x86/toolchain/arm-eabi-4.4.0/bin/../lib/gcc/arm-eabi/4.4.0/include -I/home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include -Iinclude  -include include/generated/autoconf.h -D__KERNEL__ -mlittle-endian -Iarch/arm/mach-tegra/include -D__ASSEMBLY__ -mabi=aapcs-linux -mno-thumb-interwork -funwind-tables  -D__LINUX_ARM_ARCH__=7 -march=armv7-a  -include asm/unified.h -msoft-float -gdwarf-2     -Wa,-march=armv7-a   -c -o arch/arm/mm/proc-v7.o arch/arm/mm/proc-v7.S

deps_arch/arm/mm/proc-v7.o := \
  arch/arm/mm/proc-v7.S \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/mmu.h) \
    $(wildcard include/config/arm/errata/430973.h) \
    $(wildcard include/config/arm/errata/458693.h) \
    $(wildcard include/config/arm/errata/460075.h) \
    $(wildcard include/config/trusted/foundations.h) \
    $(wildcard include/config/arm/errata/720791.h) \
    $(wildcard include/config/arm/errata/742230.h) \
    $(wildcard include/config/arm/errata/742231.h) \
    $(wildcard include/config/arm/errata/743622.h) \
    $(wildcard include/config/cpu/endian/be8.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/unified.h \
    $(wildcard include/config/arm/asm/unified.h) \
    $(wildcard include/config/thumb2/kernel.h) \
  include/linux/init.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/hotplug.h) \
  include/linux/compiler.h \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  include/linux/linkage.h \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/linkage.h \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/assembler.h \
    $(wildcard include/config/cpu/feroceon.h) \
    $(wildcard include/config/trace/irqflags.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/ptrace.h \
    $(wildcard include/config/arm/thumb.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/hwcap.h \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/asm-offsets.h \
  include/generated/asm-offsets.h \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/pgtable-hwdef.h \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/pgtable.h \
    $(wildcard include/config/highpte.h) \
    $(wildcard include/config/arm/dma/mem/bufferable.h) \
  include/asm-generic/4level-fixup.h \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/proc-fns.h \
    $(wildcard include/config/cpu/arm610.h) \
    $(wildcard include/config/cpu/arm7tdmi.h) \
    $(wildcard include/config/cpu/arm710.h) \
    $(wildcard include/config/cpu/arm720t.h) \
    $(wildcard include/config/cpu/arm740t.h) \
    $(wildcard include/config/cpu/arm9tdmi.h) \
    $(wildcard include/config/cpu/arm920t.h) \
    $(wildcard include/config/cpu/arm922t.h) \
    $(wildcard include/config/cpu/fa526.h) \
    $(wildcard include/config/cpu/arm925t.h) \
    $(wildcard include/config/cpu/arm926t.h) \
    $(wildcard include/config/cpu/arm940t.h) \
    $(wildcard include/config/cpu/arm946e.h) \
    $(wildcard include/config/cpu/sa110.h) \
    $(wildcard include/config/cpu/sa1100.h) \
    $(wildcard include/config/cpu/arm1020.h) \
    $(wildcard include/config/cpu/arm1020e.h) \
    $(wildcard include/config/cpu/arm1022.h) \
    $(wildcard include/config/cpu/arm1026.h) \
    $(wildcard include/config/cpu/xscale.h) \
    $(wildcard include/config/cpu/xsc3.h) \
    $(wildcard include/config/cpu/mohawk.h) \
    $(wildcard include/config/cpu/v6.h) \
    $(wildcard include/config/cpu/v7.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/memory.h \
    $(wildcard include/config/page/offset.h) \
    $(wildcard include/config/highmem.h) \
    $(wildcard include/config/dram/size.h) \
    $(wildcard include/config/dram/base.h) \
    $(wildcard include/config/have/tcm.h) \
    $(wildcard include/config/zone/dma.h) \
  include/linux/const.h \
  arch/arm/mach-tegra/include/mach/memory.h \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/sizes.h \
  include/asm-generic/memory_model.h \
    $(wildcard include/config/flatmem.h) \
    $(wildcard include/config/discontigmem.h) \
    $(wildcard include/config/sparsemem/vmemmap.h) \
    $(wildcard include/config/sparsemem.h) \
  arch/arm/mach-tegra/include/mach/vmalloc.h \
  arch/arm/mm/proc-macros.S \
    $(wildcard include/config/cpu/dcache/writethrough.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/thread_info.h \
    $(wildcard include/config/arm/thumbee.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/fpstate.h \
    $(wildcard include/config/vfpv3.h) \
    $(wildcard include/config/iwmmxt.h) \

arch/arm/mm/proc-v7.o: $(deps_arch/arm/mm/proc-v7.o)

$(deps_arch/arm/mm/proc-v7.o):
