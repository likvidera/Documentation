#! /usr/bin/env python2

from pwn import *
import binascii
import time
import sys
import re
import os

context(arch = 'amd64', os = 'linux', endian='little')
context.log_level = 'info'
cmd = ""
target = os.path.abspath("./mirc2077")
libcurl_path = os.path.abspath('./libcurl.so')
libc_path = os.path.abspath('./libc-2.27.so')

# make debugging PIE binaries suck less - credits to je / OwariDa
def pie_fix(p, target):
  base_addr = None
  log.info("PIE Binary, fixing symbols for: {}!".format(target))
  for line in open('/proc/%d/maps' % p.pid).readlines():
    arr = line.split()
    if arr[5] == target and arr[1] == 'r-xp':
      log.info("found {}".format(arr[5]))
      base_addr = int(arr[0].split('-')[0], 16)
      break
  text_offs = ELF(target).get_section_by_name('.text').header.sh_addr
  return 'sym\nadd-symbol-file {0} {1}'.format(target, hex(base_addr + text_offs))

env = {'LD_PRELOAD' : "{} {}".format(libc_path, libcurl_path)}
p = process(target, env=env)
if ELF(target).pie:
  cmd = pie_fix(p, target)

gdb.attach(p, '''
{}
set print pretty on
continue
'''.format(cmd))

p.interactive()

