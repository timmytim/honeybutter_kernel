cmd_arch/arm/mach-tegra/headsmp-t2.o := arm-eabi-gcc -Wp,-MD,arch/arm/mach-tegra/.headsmp-t2.o.d  -nostdinc -isystem /home/tim/ICS/prebuilt/linux-x86/toolchain/arm-eabi-4.4.0/bin/../lib/gcc/arm-eabi/4.4.0/include -I/home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include -Iinclude  -include include/generated/autoconf.h -D__KERNEL__ -mlittle-endian -Iarch/arm/mach-tegra/include -D__ASSEMBLY__ -mabi=aapcs-linux -mno-thumb-interwork -funwind-tables  -D__LINUX_ARM_ARCH__=7 -march=armv7-a  -include asm/unified.h -msoft-float -gdwarf-2        -c -o arch/arm/mach-tegra/headsmp-t2.o arch/arm/mach-tegra/headsmp-t2.S

deps_arch/arm/mach-tegra/headsmp-t2.o := \
  arch/arm/mach-tegra/headsmp-t2.S \
    $(wildcard include/config/hotplug/cpu.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/unified.h \
    $(wildcard include/config/arm/asm/unified.h) \
    $(wildcard include/config/thumb2/kernel.h) \
  include/linux/linkage.h \
  include/linux/compiler.h \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/linkage.h \
  include/linux/init.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/hotplug.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/assembler.h \
    $(wildcard include/config/cpu/feroceon.h) \
    $(wildcard include/config/trace/irqflags.h) \
    $(wildcard include/config/smp.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/ptrace.h \
    $(wildcard include/config/cpu/endian/be8.h) \
    $(wildcard include/config/arm/thumb.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/hwcap.h \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/domain.h \
    $(wildcard include/config/io/36.h) \
    $(wildcard include/config/mmu.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/cache.h \
    $(wildcard include/config/arm/l1/cache/shift.h) \
    $(wildcard include/config/aeabi.h) \
  arch/arm/mach-tegra/include/mach/iomap.h \
    $(wildcard include/config/tegra/debug/uart/none.h) \
    $(wildcard include/config/tegra/debug/uarta.h) \
    $(wildcard include/config/tegra/debug/uartb.h) \
    $(wildcard include/config/tegra/debug/uartc.h) \
    $(wildcard include/config/tegra/debug/uartd.h) \
    $(wildcard include/config/tegra/debug/uarte.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/sizes.h \
  arch/arm/mach-tegra/include/mach/io.h \
    $(wildcard include/config/resetlog.h) \
  arch/arm/mach-tegra/power-macros.S \

arch/arm/mach-tegra/headsmp-t2.o: $(deps_arch/arm/mach-tegra/headsmp-t2.o)

$(deps_arch/arm/mach-tegra/headsmp-t2.o):
