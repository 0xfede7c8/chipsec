#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2015, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#


"""
The me command provides functionalities for the Intel Management Engine

The ME INFO command uses the tool MEAnalyzer by platomav. 
	Tool github project: https://github.com/platomav/MEAnalyzer
	Under the GNU GPLv3

The SIGCHECK, UNPACK and UTIL commands uses code from skochinsky.
	Github project: https://github.com/skochinsky/me-tools
	Repo don't state anything about licencing. Check this.
"""

import os
import subprocess
import platform
import struct
import hashlib
import sys
			
from chipsec.logger     import *
from chipsec.file       import *

import chipsec_util
from chipsec.command    import BaseCommand

class MECommand(BaseCommand):
	"""
    >>> chipsec_util me <options> <me_image.bin>

    For a complete list of commands type:

    >>> chipsec_util me help

    Examples:

    >>> chipsec_util me info

    Note:

    	Supported ME versions: 2.x - 9.x for desktop, 1.x-3.x for SpS, 1.x for TXE/SEC.

    	Unpack Supported formats:

		*Full SPI flash image with descriptor (signature 5A A5 F0 0F)
		*Full ME region image (signature '$FPT')
		*Individual ME code partitions and update images (signature $MN2/$MAN)
    """

	plat = platform.system()

	cmds_help = [
		"\tchipsec_util me info     <me_image.bin> : Displays info of the ME image.",
		"\tchipsec_util me sigcheck <me_image.bin> : Checks the validity of an ME partition\'s manifest using the embedded RSA public key and signature.",
		"\tchipsec_util me unpack   <me_image.bin> : [NOT IMPLEMENTED]Dump and extract Intel ME fimrware images.",
		"\tchipsec_util me util                    : [NOT IMPLEMENTED] Allows you to send HECI (MEI) messages to the ME. The script currently runs only under Windows and requires the ME drivers to be installed. ",
	]

	def requires_driver(self):
		#will have driver conditions when util is implemented
		return False

	def printHelp(self):
		print "Commands: "
		for cmd in self.cmds_help:
			print cmd

	#used in sigcheck
	def bytes2int(self, s, swap=True):
		num = 0
		if swap: s = s[::-1]
		for c in s:
			num = num*256 + ord(c)
		return num

	def run(self):

		if len(self.argv) < 3:
			print MECommand.__doc__
			return

		op = self.argv[2]
		file = None

		if ("help" == op):
			self.printHelp()
			return

		elif("info" == op):
			if(len(self.argv) < 4):
				print "Arguments missing.\n"
				self.printHelp()
				return
			img_path = self.argv[3]
			if(self.plat == 'Linux'):	
				pathtoMEA = os.path.dirname(os.path.abspath(__file__)) + '/../../chipsec_tools/linux/MEAnalizer.bin'
			elif(self.plat == 'Windows'):
				#still not builded
				pathtoMEA = os.path.dirname(os.path.abspath(__file__)) + '/../../chipsec_tools/windows/MEAnalizer.exe'
			self.logger.log( "[CHIPSEC] Getting info of ME image. '%s'" % img_path )
			try:
				#the MEAnalyzer has a few other parameters that can be turned in other me commands. Now we only use 'skip'
				subprocess.call([pathtoMEA, img_path, '-skip'])
			except OSError:
				self.logger.log( "[CHIPSEC] Does file %s exists?" % pathtoMEA)

		elif("sigcheck" == op):
			self.logger.log( "[CHIPSEC] Intel ME partition manifest signature checker v0.1")
			if(len(self.argv) < 4):
				print "Arguments missing.\n"
				self.printHelp()
				return
			img_path = self.argv[3]
			f = open(img_path, "rb")
			hdr1 = f.read(0x80)
			ver = 0
			if hdr1[0x1C:0x20] == '$MN2':
				ver = 2
			elif hdr1[0x1C:0x20] == '$MAN':
				ver = 1
			if not ver:
				self.logger.log( "[CHIPSEC] ME manifest not found! (bad file format?)")
				return
			spubkey = f.read(0x104)
			h = hashlib.sha256() if ver==2 else hashlib.sha1()
			h.update(spubkey)
			pkhash = self.bytes2int(h.digest())
			pubkey = self.bytes2int(spubkey[0:0x100])
			pubexp = self.bytes2int(spubkey[0x100:])
			rsasig = self.bytes2int(f.read(0x100))
			self.logger.log("[CHIPSEC] Public key: " + hex(pubkey) + '\n')
			self.logger.log("[CHIPSEC] Exponent: " + hex(pubexp) + '\n')
			self.logger.log("[CHIPSEC] Pubkey + Exp hash: " + hex(pkhash) + '\n') 
			self.logger.log("[CHIPSEC] Signature " + hex(rsasig) + '\n')
			decsig = pow(rsasig, pubexp, pubkey)
			sigstr = hex(decsig)
			self.logger.log( "[CHIPSEC] Decrypted signature: " + sigstr + '\n')
			# header length
			hlen = struct.unpack("<I", hdr1[4:8])[0] * 4
			# manifest length
			mlen = struct.unpack("<I", hdr1[0x18:0x1C])[0] * 4
			# read trailer of the manifest
			f.seek(hlen)
			hdr2 = f.read(mlen-hlen)
			h = hashlib.sha256() if ver==2 else hashlib.sha1()
			h.update(hdr1)
			h.update(hdr2)
			hashstr = hex(self.bytes2int(h.digest(), False))
			self.logger.log( "[CHIPSEC] Manifest hash: " + hashstr + '\n')
			# TODO: check 0x1ff.... at the start of signature
			if sigstr.endswith(hashstr[2:]):
			   self.logger.log("[CHIPSEC] Signature seems valid")
			else:
			   self.logger.log("[CHIPSEC] Signature is INVALID!")
			   return

		elif("unpack" == op):
			#TODO
			return

		elif("util" == op):
			if(plat != 'Windows'):
				self.logger.log( "[CHIPSEC] This feature only works on Windows.")
				return
			#TODO
			
		else:
			self.printHelp()

commands = { "me": MECommand }