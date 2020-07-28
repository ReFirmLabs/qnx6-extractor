# This Python file uses the following encoding: utf-8
#############################
##  
#	QNX6FS Partition Parser and Automatic file extraction
##  -----------------------------------------------------
#
##  Author: Mathew Evans (mathew.evans@nop.ninja)
#	Revision: 0.2d rev2 (release-candidate) / Dec 2019
##
#	updates posted @ https://www.forensicfocus.com/Forums/viewtopic/t=16846/
##
####################
#!/usr/bin/python
# -*- coding: utf-8 -*-

import binascii, math, zlib, sys, re, os, errno
from struct import *
from collections import OrderedDict

class QNX6FS:

	PARTITION_MAGIC	= {'QNX4':0x002f,'QNX6':0x68191122}
	FILE_TYPE 		= {'DIRECTORY':0x01,'DELETED':0x02,'FILE':0x03}

	QNX6_SUPERBLOCK_SIZE 	= 0x200 	#Superblock is fixed (512 bytes)
	QNX6_SUPERBLOCK_AREA 	= 0x1000	#Area reserved for superblock
	QNX6_BOOTBLOCK_SIZE  	= 0x2000	#Boot Block Size
	QNX6_DIR_ENTRY_SIZE  	= 0x20 		#Dir block size (32 bytes)
	QNX6_INODE_SIZE      	= 0x80 		#INode block size (128 bytes)
	QNX6_INODE_SIZE_BITS 	= 0x07 		#INode entry size shift

	QNX6_NO_DIRECT_POINTERS = 16		#Max Direct iNodes
	QNX6_PTR_MAX_LEVELS 	= 5			#Max Indirect iNodes
	QNX6_SHORT_NAME_MAX 	= 27		#Short Name Max Length
	QNX6_LONG_NAME_MAX 		= 510		#Long Name Max Length

	def __init__(self, source):
		self.TARGET_ = source
		
	def GetPartitions(self):
		with open(self.TARGET_, "rb") as handle:
			DataBlock = handle.read(512);

			##Split DataBlock into parts
			BootCode = DataBlock[0:446]
			MasterPartitionTable = DataBlock[446:510]
			BootRecordSignature = DataBlock[510:512]

			##Detect if MBR is valid.
			BootRecordSignature = unpack('H', BootRecordSignature)[0]
			if BootRecordSignature == 0xAA55:
				if ord(BootCode[0]) == 235:
					return self.parseNoPartitionQNX(handle,0)
				else:
					print "[-] BootRecordSignature Detected."
					return self.parsePartitionMBR(handle,0)
			else:
				raise IOError('[ERROR] BootRecordSignature Missing; Invalid Disk Image')
				exit()
			return null

	def parsePartitionMBR(self, fileIO, offset, blockSize=512):
		fileIO.seek(offset,0); #absolute from start of file
		DataBlock = fileIO.read(blockSize)
		PartitionTable = DataBlock[446:510]
		PartitionList={}
		for i in range(0,4):
			Offset= 0 + (i * 16);
			PartitionList[i]={}
			PartitionList[i]['BootIndicator'] = PartitionTable[Offset+0]
			PartitionList[i]['StartingCHS'] = PartitionTable[Offset+1:Offset+4]
			PartitionList[i]['PartitionType'] = PartitionTable[Offset+4]
			PartitionList[i]['EndingCHS'] = PartitionTable[Offset+5:8]
			PartitionList[i]['StartingSector'] = unpack('<I',PartitionTable[Offset+8:Offset+12])[0]
			PartitionList[i]['PartitionSize'] = unpack('<I',PartitionTable[Offset+12:Offset+16])[0] 
			PartitionList[i]['EndingSector'] = ((PartitionList[i]['PartitionSize']) + (PartitionList[i]['StartingSector']) -1)
			PartitionList[i]['StartingOffset'] = PartitionList[i]['StartingSector'] * 512
			PartitionList[i]['EndOffset'] = PartitionList[i]['EndingSector'] * 512
			PartitionList[i]['SectorSize'] = 512
			PartitionList[i]['qnx6'] = False
			PartitionID = ord(PartitionList[i]['PartitionType'])
			if PartitionID == 0x05 or PartitionID == 0x0F:
					print "[-] (EBR) Extended Boot Record Detected, Processing...."
					Parts = self.parsePartitionMBR(fileIO, offset + PartitionList[i]['StartingSector'], blockSize) 
					for partID in range(0, len(Parts)):
						PartitionList[len(PartitionList) + 1] = Parts[partID]
			elif ( PartitionID == 0xB1 or PartitionID == 0xB2 or PartitionID == 0xB3 or PartitionID == 0xB4 ):
					print "[+] Supported QNX6FS Partition Detected @",format(PartitionList[i]['StartingOffset'],"02x")
					PartitionList[i]['qnx6'] = True
			elif ( PartitionID == 0x4D or PartitionID == 0x4E or PartitionID == 0x4F ):
					print "[X] Unsupported QNX4FS Partition Detected @",format(PartitionList[i]['StartingOffset'],"02x")
			else:
					print format(PartitionID,"02x")
					print PartitionList[i]

		return PartitionList;

	def parseNoPartitionQNX(self, fileIO, offset, blockSize=512):
		fileIO.seek(offset,0); #absolute from start of file
		DataBlock = fileIO.read(blockSize)
		PartitionTable = DataBlock[446:510]
		PartitionList={}
		i=0
		Offset= 0;
		PartitionList[i]={}
		PartitionList[i]['BootIndicator'] = 0
		PartitionList[i]['StartingCHS'] = 0
		PartitionList[i]['PartitionType'] = chr(0xB1)+""
		PartitionList[i]['EndingCHS'] = 0
		PartitionList[i]['StartingSector'] = 0
		PartitionList[i]['PartitionSize'] = 0
		PartitionList[i]['EndingSector'] = 0
		PartitionList[i]['StartingOffset'] = 0
		PartitionList[i]['EndOffset'] = 0
		PartitionList[i]['SectorSize'] = 512
		PartitionList[i]['qnx6'] = True
		PartitionID = ord(PartitionList[i]['PartitionType'])
		print "[+] Supported QNX6FS Partition Detected @",format(PartitionList[i]['StartingOffset'],"02x")
		return PartitionList;

	def ParseQNX(self, Partition, PartitionID):
		self.fileIO = open(self.TARGET_, "rb")

		Offset = self.QNX6_BOOTBLOCK_SIZE + Partition['StartingOffset']
		self.Offset = Offset - self.QNX6_BOOTBLOCK_SIZE # + self.QNX6_SUPERBLOCK_AREA

		### We are not interested in the Boot block, so jump straight past it.
		self.fileIO.seek( ( Partition['StartingOffset'] + self.QNX6_BOOTBLOCK_SIZE ) , 0 )

		## The superblock should only be 512bytes long.
		Data = self.fileIO.read( self.QNX6_SUPERBLOCK_SIZE )
		SuperBlock = self.parseQNX6SuperBlock(Data, Partition['StartingOffset'])
		self.SuperBlock = SuperBlock;

		## If the blocksize != 512, then super block is longer, re-read the area.
		if (SuperBlock['blocksize'] != 512):
			self.fileIO.seek( ( Partition['StartingOffset'] + self.QNX6_BOOTBLOCK_SIZE ) , 0 )
			Data = self.fileIO.read( SuperBlock['blocksize'] )
			SuperBlock = self.parseQNX6SuperBlock(Data, Partition['StartingOffset'])

		if SuperBlock['magic'] == self.PARTITION_MAGIC['QNX6']:
			print " |---+ First SuperBlock Detected","( Serial:", SuperBlock['serial'],") @",format(Offset,"02x")

			BackupSuperBlock_Offset = Partition['StartingOffset'] + self.QNX6_SUPERBLOCK_AREA + self.QNX6_BOOTBLOCK_SIZE + ( SuperBlock['num_blocks'] * SuperBlock['blocksize'])
			self.fileIO.seek(BackupSuperBlock_Offset, 0)
			Data = self.fileIO.read( SuperBlock['blocksize'] )
			blkSuperBlock = self.parseQNX6SuperBlock(Data, Partition['StartingOffset'])

			if blkSuperBlock['magic'] == self.PARTITION_MAGIC['QNX6']:
				print "     |---+ Second SuperBlock Detected ","( Serial:", blkSuperBlock['serial'],") @",format(BackupSuperBlock_Offset,"02x")

				if blkSuperBlock['serial'] < SuperBlock['serial']:
					SB = SuperBlock
					print "         |---+ Using First SuperBlock as Active Block"
				else:
					SB = blkSuperBlock
					print "         |---+ Using Second SuperBlock as Active Block" 

			self.printSuperBlockInfo(SB)
			self.parseBitmap(SB)
			self.LongNames = self.parseLongFileNames(SB)

			#for i in self.LongNames:
			#	print format(int(i),'02x'), self.LongNames[i]

			self.parseINODE(SB,PartitionID)
			
	def printSuperBlockInfo(self, SB):
				print "              |--- volumeID:\t", ("".join("%02x" % q for q in SB['volumeid'] )).upper()
				print "              |--- checksums:\t", ("0x%0.8X" % SB['checksum'])
				print "              |--- num_inodes:\t", SB['num_inodes']
				print "              |--- num_blocks:\t", SB['num_blocks']
				print "              |--- blocksize:\t", SB['blocksize']
				print "              |--- blkoffset: \t", SB['blks_offset']

	def parseQNX6SuperBlock(self, sb, offset): # B = 8 , H = 16 , I = 32 , L = 32 , Q = 64
		SB = {}
		SB['magic'] = unpack('<I', sb[:4])[0]
		SB['checksum'] = (unpack('>I', sb[4:8])[0])
		SB['checksum_calc'] = zlib.crc32(sb[8:512],0) & 0xFFFFFFFF
		SB['serial'] = unpack('<Q', sb[8:16])[0]
		SB['ctime'] = unpack('<I', sb[16:20])[0]
		SB['atime'] = unpack('<I', sb[20:24])[0]
		SB['flags'] = unpack('<I', sb[24:28])[0]
		SB['version1'] = unpack('<H', sb[28:30])[0]
		SB['version2'] = unpack('<H', sb[30:32])[0]
		SB['volumeid'] = unpack('<16B', sb[32:48])
		SB['blocksize'] = unpack('<I', sb[48:52])[0]
		SB['num_inodes'] = unpack('<I', sb[52:56])[0]
		SB['free_inodes'] = unpack('<I', sb[56:60])[0]
		SB['num_blocks'] = unpack('<I', sb[60:64])[0]
		SB['free_blocks'] = unpack('<I', sb[64:68])[0]
		SB['allocgroup'] = unpack('<I', sb[68:72])[0]

		SB['Inode'] = self.parseQNX6RootNode(sb[72:152])  ##80bytes 
		SB['Bitmap'] = self.parseQNX6RootNode(sb[152:232])
		SB['Longfile'] = self.parseQNX6RootNode(sb[232:312])
		SB['Unknown'] = self.parseQNX6RootNode(sb[312:392])

		SB['blks_offset'] = offset + self.QNX6_SUPERBLOCK_AREA + self.QNX6_BOOTBLOCK_SIZE;
		return SB

	def parseQNX6RootNode(self,rn):
		RN = {}
		RN['size'] = unpack('<Q', rn[0:8])[0]
		RN['ptr'] = unpack('<16I', rn[8:72])
		RN['level'] = unpack('<B', rn[72:73])[0]
		RN['mode'] = unpack('<B', rn[73:74])[0]
		RN['reserved'] = unpack('<6B', rn[74:80])[0]
		return RN

	def parseINODE(self,superBlock,PartitionID):
				print "              |--+ Inode: Detected - Processing...."
				#print "                 |---Size:",  superBlock['Inode']['size']
				#print "                 |---Level:",  superBlock['Inode']['level']
				#print "                 |---Mode:",  superBlock['Inode']['mode']
				self.INodeTree = {}
				self.DirTree = {}
				if (superBlock['Inode']['level'] > self.QNX6_PTR_MAX_LEVELS):
					print "[x] invalid Inode structure."
					return 0
				#print "                 |--+PTR: "
				for n in range(0, 16):
					ptr = superBlock['Inode']['ptr'][n]
					if self.checkQNX6blkptr(ptr):
						ptr_ = (ptr*superBlock['blocksize'])+superBlock['blks_offset'];
						#print "                    |--",n," : ",format(ptr_,'02x')
						superBlock['Inodes'] = self.praseQNX6Inode(ptr,superBlock['Inode']['level'],superBlock['blocksize'],superBlock['blks_offset'])
				
				print "[-] Generating directory Listing && Auto Extracting Files to (.\\Extracted\\Partition"+str(PartitionID)+")"
				self.parseINodeDIRStruct(superBlock['blocksize'],superBlock['blks_offset'])

				for i in self.DirTree:
					self.dumpfile(i,'.\\Extraced\\',superBlock['blocksize'],superBlock['blks_offset'],PartitionID)

				#self.parseINodeDIRbyID(1,superBlock['blocksize'],superBlock['blks_offset'])
	
	def parseLongFileNames(self,superBlock):
				print "              |--+ Longfile: Detected - Processing...."
				#print "                 |---Size:",  superBlock['Longfile']['size']
				#print "                 |---Level:",  superBlock['Longfile']['level']
				#print "                 |---Mode:",  superBlock['Longfile']['mode']
				if (superBlock['Longfile']['level'] > self.QNX6_PTR_MAX_LEVELS):
					print "                           *invalid levels, too many*"
				#print "                 |---PTR: "
				longnames = []
				for n in range(0, 16):
					ptr = superBlock['Longfile']['ptr'][n]
					if self.checkQNX6blkptr(ptr):
						ptrB = (ptr*superBlock['blocksize'])+superBlock['blks_offset'];
						#print "                    |--",n,":",format(ptrB,'02x')
						longnames.append(self.parseQNX6LongFilename(ptr,superBlock['Longfile']['level'],superBlock['blocksize'],superBlock['blks_offset']))
				
				##Make Dictionary with all Names and INode/PTRs
				count = 1
				Dict = {}
				for i in longnames:
					if i != None:
						for q in i:
							if q != None:
								Dict[count] = i[q]
								count = count + 1;
				return Dict

	def parseQNX6LongFilename(self,ptr_,level,blksize,blksOffset):
		self.fileIO.seek((ptr_*blksize)+blksOffset)
		handle = self.fileIO.read(512)
		LogFilenameNode={}
		if level == 0:
			size = unpack('<H',handle[0:2])
			fname = unpack('<'+str(size[0])+'B',handle[2:size[0]+2])
			if size[0] > 0:
				LogFilenameNode[str(ptr_)] = str("".join("%c" % i for i in fname )).strip()
				return LogFilenameNode
			else:
				return None
		else:
			Pointers = unpack('<128I', handle)
			for i in range(0, 128):
				if (self.checkQNX6blkptr(Pointers[i]) != False):
					name = (self.parseQNX6LongFilename(Pointers[i],level-1,blksize,blksOffset))
					if name != None:
						if level >= 1:
							LogFilenameNode[str(Pointers[i])]=name[str(Pointers[i])]
						else:
							LogFilenameNode[str(Pointers[i])]=name
		return LogFilenameNode

	def praseQNX6Inode(self,ptr,level,blksize,blksOffset):
		ptr_=(ptr*blksize)+blksOffset
		if self.checkQNX6blkptr(ptr_) and ptr != 0xffffffff:
			self.fileIO.seek(ptr_) 
			RawData = self.fileIO.read(blksize)

			if level >= 1:
				Pointers = unpack('<'+str(blksize/4)+'I', RawData)
				for i in range(0, (blksize/4)):
					if self.checkQNX6blkptr((Pointers[i]*blksize)+blksOffset):
						self.praseQNX6Inode(Pointers[i],level-1,blksize,blksOffset)
			else:
				inode_range = (blksize / 128)
				for i in range(0,inode_range):
					try:
						item = self.parseQNX6InodeEntry(RawData[(i*(blksize/inode_range)):((i+1)*(blksize/inode_range))])
						self.INodeTree[len(self.INodeTree)+1] = item
					except:
						print i, len(self.INodeTree), format(ptr_,'02x'), format(ptr,'02x')
						self.INodeTree[len(self.INodeTree)+1] = None
						break

	def parseQNX6InodeEntry(self, ie): #qnx6_inode_entry 128bytes
		IE = {}
		IE['size'] = unpack('<Q',ie[0:8])[0]
		IE['uid'] = unpack('<I',ie[8:12])[0]
		IE['gid'] = unpack('<I',ie[12:16])[0]
		IE['ftime'] = unpack('<I',ie[16:20])[0]
		IE['mtime'] = unpack('<I',ie[20:24])[0]
		IE['atime'] = unpack('<I',ie[24:28])[0]
		IE['ctime'] = unpack('<I',ie[28:32])[0]
		###S_IFREG 0100000 S_IFDIR 040000 S_IRUSR 0400 S_IWUSR 0200 S_IXUSR 0100
		IE['mode'] = unpack('<H',ie[32:34])[0]
		IE['ext_mode'] = unpack('<H',ie[34:36])[0]
		IE['block_ptr'] = unpack('<16I',ie[36:100])
		IE['filelevels'] = unpack('<B',ie[100:101])[0]
		IE['status'] = unpack('<B',ie[101:102])[0]
		IE['unknown2'] = unpack('<2B',ie[102:104])
		IE['zero2'] = unpack('<6I',ie[104:128])
		return IE

	def parseINodeDIRStruct(self,blksize,blksOffset,INodeID=1):
		InodeEntry = self.INodeTree[INodeID]
		## Check INodeEntry Exists and is a directory type Inode;
		if InodeEntry != None and (self.InodeEntry_ISDIR(InodeEntry['mode'])):

			## Parse all 16 pointers in InodeEntry and make batchlist
			PhysicalPTRs = []
			for pointer_index in InodeEntry['block_ptr']:
				## Make sure pointer != 0xFFFFFFFF
				if pointer_index != 0xffffffff:
					## Calculate Physical Location.
					PhysicalPTRs.append((pointer_index*blksize)+blksOffset)

			## If we have atleast 1 valid pointer process it for Dirs and Files	
			if len(PhysicalPTRs) > 0:
				objects = self.parseInodeDirBatch(PhysicalPTRs,blksize,blksOffset)

				##find perant INode ID (. and .. will be same at root == 1)
				rootID = 0
				for i in objects:
					if objects[i]['Name'] == ".":
						rootID=objects[i]['PTR']
						break;

				for i in objects:
					obj = objects[i]
					if obj['Name'] != ".." and obj['Name'] != ".":
						self.DirTree[ obj['PTR'] ] = {'Name':obj['Name'],'ROOT_INODE':rootID}

						##Recursively Process all Dirs
						if obj['PTR'] > 1:
							self.parseINodeDIRStruct(blksize,blksOffset,obj['PTR'])

	def parseInodeDirBatch(self,ptrs,blksize,blksOffset):
		DIR = {}
		for ptr in ptrs:
			self.fileIO.seek(ptr) 
			RawData = self.fileIO.read(blksize)
			for i in range(0,(blksize/32)):
				raw = RawData[ i*32: ((i+1)*32) ]
				if (unpack('<I', raw[0:4])[0] != 0):
					DIR[str(ptr)+"-"+str(i)]={}
					DIR[str(ptr)+"-"+str(i)]['PTR'] = unpack('<I', raw[0:4])[0]
					DIR[str(ptr)+"-"+str(i)]['Length'] = unpack('<B', raw[4:5])[0]

					if DIR[str(ptr)+"-"+str(i)]['Length'] <= self.QNX6_SHORT_NAME_MAX:
						DIR[str(ptr)+"-"+str(i)]['Name'] = "".join("%c" % i for i in unpack('<27B', raw[5:32] ) ).replace("\x00","")
					else:	
						#print format(ptr,'02x'), "---" , format((ptr * blksize ) + blksOffset,'02x') , unpack('>I', raw[12:16])[0]
						DIR[str(ptr)+"-"+str(i)]['Name'] =  self.LongNames[unpack('>I', raw[5:9])[0]+1] #self.LongNames[unpack('<I', raw[12:16])[0]]
						
		return DIR

	def parseINodeDIRbyID(self,INodeID,blksize,blksOffset,level=0):
		InodeEntry = self.INodeTree[INodeID]
		##print InodeEntry
		if (InodeEntry != None) and (self.InodeEntry_ISDIR(InodeEntry['mode'])):
			for q in range(0,16):
				if InodeEntry['block_ptr'][q] != 0xffffffff:
					_ptr=(InodeEntry['block_ptr'][q]*blksize)+blksOffset
					##print INodeID, "++", format(_ptr,'02x')
					DIRS = self.parseInodeDir(_ptr,blksize,blksOffset)
					root = 0
					for idir in DIRS:
						if (DIRS[idir]['Length'] > 0) and (DIRS[idir]['Length'] < 28):
							if DIRS[idir]['Name'] != "." and DIRS[idir]['Name'] != "..":
								print ("   "*level),"+-",DIRS[idir]['Name'] #, " -- " , DIRS[idir]['PTR']

							elif DIRS[idir]['Name'] == "..":
								root = DIRS[idir]['PTR'];

							if DIRS[idir]['PTR'] != INodeID and DIRS[idir]['Name'] != "." and DIRS[idir]['Name'] != ".." and DIRS[idir]['PTR'] > 2 :
								self.parseINodeDIRbyID(DIRS[idir]['PTR'],blksize,blksOffset,level+1)

	def parseInodeDir(self,ptr,blksize,blksOffset):
		self.fileIO.seek(ptr) 
		RawData = self.fileIO.read(blksize)
		DIR = {}
		for i in range(0,(blksize/32)):
			raw = RawData[ i*32: ((i+1)*32) ]
			DIR[i]={}
			DIR[i]['PTR'] = unpack('<I', raw[0:4])[0]
			DIR[i]['Length'] = unpack('<B', raw[4:5])[0]
			DIR[i]['Name'] = "".join("%c" % i for i in unpack('<27B', raw[5:32] ) ).replace("\x00","")
		return DIR

	def checkQNX6blkptr(self, ptr):
		mask = ( 1 << ptr.bit_length()) -1
		return (ptr ^ mask == 0) == False			

	def InodeEntry_ISDIR(self,mode):
		return ((mode & 040000) == 040000)

	def InodeEntry_ISREG(self,mode):
		return ((mode & 0100000) == 0100000)

	def InodeEntry_ISLNK(self,mode):
		return ((mode & 0120000) == 0120000)

	def parseBitmap(self,superBlock):
		self.Bitmaps = {}
		print "              |--+ Bitmap: Detected - Processing.... (using fast mode, this will still take a while.)"
		#print "       |---Size:",  superBlock['Bitmap']['size']
		#print "       |---Level:",  superBlock['Bitmap']['level']
		#print "       |---Mode:",  superBlock['Bitmap']['mode']

		if (superBlock['Bitmap']['level'] > self.QNX6_PTR_MAX_LEVELS):
			print "                 *invalid levels, too many*"
		#print "       |--+PTR: "
		for n in range(0, 16):
			ptr = superBlock['Bitmap']['ptr'][n]
			if self.checkQNX6blkptr(ptr):
				ptr_ = (ptr*superBlock['blocksize'])+superBlock['blks_offset'];
				#print "                    |--",n," : ",format(ptr_,'02x')
				self.praseQNX6Bitmap(ptr,superBlock['Bitmap']['level'],superBlock['blocksize'],superBlock['blks_offset'])

		#if len(self.Bitmaps) > 0:
		#	for i in range(1,len(self.Bitmaps)):
		#		print format(self.Bitmaps[i]['PTR'],'02x')
		dcount = 0;
		count = 0;
		if len(self.Bitmaps) > 0:
			count = 0;
			for i in range(1,len(self.Bitmaps)):
				Data = self.Bitmaps[i]['DATA']
				for byte in Data:
					if ord(byte) > 0:
						for ii in range(0,7):
							bit = ((ord(byte) >> ii) & 00000001 )
							#print bit,
							#sys.stdout.write(str(bit))
							#sys.stdout.flush()
							if bit == 0:
								if self.isBlockEmpty(count,superBlock['blocksize'],superBlock['blks_offset']) == False:
									dcount = dcount + 1;
									PhysicalPTR=((count)*superBlock['blocksize'])+superBlock['blks_offset']
									snip=self.getSnippet(count,superBlock['blocksize'],superBlock['blks_offset'])
									#print "                 |---Deleted Data @:", format(PhysicalPTR,'02x') , "(",snip,")"
							count = count + 1;
		print "                 |---Deleted Blocks:", dcount , "found"  
				
	def praseQNX6Bitmap(self,ptr,level,blksize,blksOffset):
		ptr_=(ptr*blksize)+blksOffset
		if self.checkQNX6blkptr(ptr_) and ptr != 0xffffffff:
			self.fileIO.seek(ptr_) 
			RawData = self.fileIO.read(blksize)

			if level >= 1:
				Pointers = unpack('<'+str(blksize/4)+'I', RawData)
				for i in range(0, (blksize/4)):
					if self.checkQNX6blkptr((Pointers[i]*blksize)+blksOffset) and Pointers[i] != 0xffffffff and Pointers[i] != 0x0:
						#print (Pointers[i]*blksize)+blksOffset
						self.praseQNX6Bitmap(Pointers[i],level-1,blksize,blksOffset)
			else:
				self.Bitmaps[len(self.Bitmaps)+1] = {'PTR':ptr_, 'DATA':RawData}

	def isBlockEmpty(self,blocknumber,blksize,blksOffset):
		PhysicalPTR=(blocknumber*blksize)+blksOffset
		self.fileIO.seek(PhysicalPTR) 
		Data = self.fileIO.read(blksize) #.replace("\x00","")
		Data = ''.join([x for x in Data if ord(x) > 0])
		return len(Data) < 1

	def getSnippet(self,blocknumber,blksize,blksOffset):
		PhysicalPTR=(blocknumber*blksize)+blksOffset
		self.fileIO.seek(PhysicalPTR) 
		Data = self.fileIO.read(40) #.replace("\x00","")
		Data = re.sub(r'[^\x00-\x7F]+','', Data)
		Data = ''.join([x for x in Data if ord(x) < 128])
		Data = ''.join([x for x in Data if ord(x) > 20])
		return Data.strip().rstrip()

	def parseQNX6LongDirEntry(self,dn):
		DN={}
		DN['inode']= unpack('<I',dn[0:4])
		DN['size']= unpack('<B',dn[4:5])
		DN['unk']= unpack('<BBB',dn[5:8])
		DN['longInode']=unpack('<I',dn[8:12])
		DN['checksum']=unpack('<I',dn[12:16])
		return DN

		##DIRINodeID = PTR for ".." using backwards recursion the full dir path can be found.

	def dumpfile(self,DataINodeID,output_directory='.\\',blksize=1024,blkOffset=0,PartitionID=0):
		InodeDataEntry = self.INodeTree[DataINodeID]
		if (InodeDataEntry != None) and not (self.InodeEntry_ISDIR(InodeDataEntry['mode'])):
			filename = self.DirTree[DataINodeID]['Name']

			## Create DIR List
			dirpath = ""
			dirID = DataINodeID
			while True:
				if dirID <= 0x01:
					break
				if dirID != DataINodeID:
					dirpath = self.DirTree[dirID]['Name'] +"\\"+ dirpath
				dirID = self.DirTree[dirID]['ROOT_INODE']
			print " |--- [",self.bytes2human(InodeDataEntry['size']),"] \t", dirpath + filename

			## Create List of all physical blocks
			PhysicalPTRs = []
			for pointer_index in InodeDataEntry['block_ptr']:
				## Make sure pointer != 0xFFFFFFFF
				if pointer_index != 0xffffffff:
					## Calculate Physical Location.
					PhysicalPTRs += [(pointer_index*blksize)+blkOffset]

			if os.path.exists(output_directory+"Partition"+str(PartitionID)+"\\"+dirpath) == False:
				try: os.makedirs(output_directory+"Partition"+str(PartitionID)+"\\"+dirpath)
				except OSError as e:
					pass

			filepath=output_directory+"Partition"+str(PartitionID)+"\\"+dirpath+filename
			if os.path.exists(filepath) == False:
				self.batchProcessPTRS(PhysicalPTRs,InodeDataEntry,InodeDataEntry['filelevels'],blksize,blkOffset,filepath)

			if os.path.exists(filepath):
				os.utime(filepath, (InodeDataEntry['atime'], InodeDataEntry['mtime']))

	def batchProcessPTRS(self,ptrs,InodeDataEntry,level,blksize,blkOffset,path,io=0):
		if io == 0:
			io = open(path,"wb+");

		DATABUFF = ""
		for i in range(0,len(ptrs)):
			if level == 0:
				if self.checkQNX6blkptr(ptrs[i]):
					if ptrs[i] != 0xffffffff and ptrs[i] != 0x0:
						self.fileIO.seek(ptrs[i])
						if (InodeDataEntry['size'] - io.tell()) >= 1024:
							DATABUFF += self.fileIO.read(blksize)
						else:
							DATABUFF += self.fileIO.read((InodeDataEntry['size'] - io.tell()))
			else:		
				self.fileIO.seek(ptrs[i])
				newPTRS = unpack('<'+str(blksize/4)+'I', self.fileIO.read(blksize))
				level2_PTRS = []
				for i in range(0,len(newPTRS)):
					if self.checkQNX6blkptr(newPTRS[i]):
						if newPTRS[i] != 0xffffffff and newPTRS[i] != 0x0:
							level2_PTRS += [(newPTRS[i]*blksize)+blkOffset]
				self.batchProcessPTRS(level2_PTRS,InodeDataEntry,level-1,blksize,blkOffset,path,io)

		if level == 0:
			io.write(DATABUFF)

	def bytes2human(self,n, format='%(value).1f %(symbol)s'):
	    n = int(n)
	    if n < 0: raise ValueError("n < 0")
	    symbols = ('B','KB','MB','GB','TB','PB','EB','ZB','IB')
	    prefix = {}
	    for i, s in enumerate(symbols[1:]):
	        prefix[s] = 1 << (i+1)*10
	    for symbol in reversed(symbols[1:]):
	        if n >= prefix[symbol]:
	            value = float(n) / prefix[symbol]
	            return format % locals()
	    return format % dict(symbol=symbols[0], value=n)

def main():
	if os.path.exists(sys.argv[1]):
		Q6 = QNX6FS(sys.argv[1]);
		Partitions = Q6.GetPartitions();
		print "[-] Detected", len(Partitions) ,"Partitions."

		for i in range(0, len(Partitions)):
			if ( Partitions[i]['qnx6'] == True ):
				print "[-] Processing Partition",i+1,"of",len(Partitions)
				Q6.ParseQNX(Partitions[i],i+1)
			print ""
			break
	else:
		print "QNX6FS Parser v0.2d rev 2; mathew.evans[@]nop[.]ninja ; Dec 2019"
		print "------------------------------------------------------------"
		print "- src/url: https://NOP.ninja/qnx6-0.2d.py"
		print "- "
		print "- THIS IS A RELESE-CANDIDATE; USE AT YOUR OWN RISK "
		print "- "
		print "- [+] QNX 6.5.0 DONE"
		print "- [-] QNX 6.5.1 TDB"
		print "- "
		print "- Usage: qnx6.py RAWIMAGEFILE.001"
		print "------------------------------------------------------------"

if __name__ == "__main__":
    main();
