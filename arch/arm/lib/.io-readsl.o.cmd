cmd_arch/arm/lib/io-readsl.o := arm-eabi-gcc -Wp,-MD,arch/arm/lib/.io-readsl.o.d  -nostdinc -isystem /home/tim/ICS/prebuilt/linux-x86/toolchain/arm-eabi-4.4.0/bin/../lib/gcc/arm-eabi/4.4.0/include -I/home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include -Iinclude  -include include/generated/autoconf.h -D__KERNEL__ -mlittle-endian -Iarch/arm/mach-tegra/include -D__ASSEMBLY__ -mabi=aapcs-linux -mno-thumb-interwork -funwind-tables  -D__LINUX_ARM_ARCH__=7 -march=armv7-a  -include asm/unified.h -msoft-float -gdwarf-2        -c -o arch/arm/lib/io-readsl.o arch/arm/lib/io-readsl.S

deps_arch/arm/lib/io-readsl.o := \
  arch/arm/lib/io-readsl.S \
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
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/assembler.h \
    $(wildcard include/config/cpu/feroceon.h) \
    $(wildcard include/config/trace/irqflags.h) \
    $(wildcard include/config/smp.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/ptrace.h \
    $(wildcard include/config/cpu/endian/be8.h) \
    $(wildcard include/config/arm/thumb.h) \
  /home/tim/Downloads/mitchtaydev-Thrive-Shiva-Kernel-ee65d90/linux-2.6/arch/arm/include/asm/hwcap.h \

arch/arm/lib/io-readsl.o: $(deps_arch/arm/lib/io-readsl.o)

$(deps_arch/arm/lib/io-readsl.o):