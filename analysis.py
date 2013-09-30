import magic
import pydasm
import binascii
import pefile
import hashlib
import re
import sys
def hashes(data):
 return (hashlib.md5(data).hexdigest(),hashlib.sha1(data).hexdigest())

def printable(data):
 chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
 shortest = 4
 regexp = '[%s]{%d,}' % (chars, shortest)
 common=["This program cannot be run in DOS mode.",".text",".rdata",".data"]
 pattern=re.compile(regexp)
 pat=pattern.findall(data)
 for k in common:
  try:
   pat.remove(k)
  except:
   pass
 return pat
def filetype(data):
 try:
  ms=magic.open(magic.MAGIC_NONE)
  ms.load()
  return ms.buffer(data)
 except:
  return magic.from_buffer(data)

def peinfo(dat):
 try:
  pe=pefile.PE(data=dat)
  value=[]
  for section in pe.sections:
   value.append(section.Name.replace("\x00","")+":"+section.get_hash_md5()+":"+str(section.SizeOfRawData))
  return value
 except:
  return ["error"]

def ep(dat):
 try:
  pe=pefile.PE(data=dat)
  return pe.OPTIONAL_HEADER.AddressOfEntryPoint
 except:
  return "error"

def peimport(dat):
 try:
  pe=pefile.PE(data=dat)
  value=[]
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
   importf=[]
   for i in entry.imports:
	   importf.append(i.name)
   value.append(entry.dll)
   value.append(importf)
  return value
 except:
  return ["error"]

def disassembl(dat):
	mal=binascii.hexlify(dat)
	assem=""
	offset=0
	while offset < len(mal):
		i=pydasm.get_instruction(mal[offset:],pydasm.MODE_32)
		assem+=pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0)+"\n"
		if not i:
			break
		offset+=i.length
	return assem

def peexport(dat):
 try:
  pe=pefile.PE(data=dat)
  value=[]
  for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
   value.append(entry.name)
  return value
 except:
  return ["No exported functions"]


def yarac(data):
 leng=0
 rules="rule test\n{\n strings:\n"
 for i in data:
   rules+=" $st"+str(leng)+"=\""+i+"\"\n"
   leng+=1
 rules+=" condition:\n  all of them\n}"
 yara=open("sig.yara","w")
 yara.write(rules)
 yara.close()
 
def clams(data):
 clam=open("clam.hdb","w")
 clam.write(hashlib.md5(data).hexdigest()+":"+str(len(data))+":AutoGen\n")
 clam.close()
