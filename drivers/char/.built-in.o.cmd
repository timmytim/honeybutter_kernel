cmd_drivers/char/built-in.o :=  arm-eabi-ld -EL    -r -o drivers/char/built-in.o drivers/char/mem.o drivers/char/random.o drivers/char/tty_io.o drivers/char/n_tty.o drivers/char/tty_ioctl.o drivers/char/tty_ldisc.o drivers/char/tty_buffer.o drivers/char/tty_port.o drivers/char/tty_mutex.o drivers/char/pty.o drivers/char/misc.o drivers/char/sysrq.o 
