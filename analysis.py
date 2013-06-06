import magic
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
  pat.remove(k)
 return pat
def filetype(data):
 ms=magic.open(magic.MAGIC_NONE)
 ms.load()
 return ms.buffer(data)

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
   value.append(entry.dll)
  return value
 except:
  return ["error"]

def peexport(dat):
 try:
  pe=pefile.PE(data=dat)
  value=[]
  for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
   value.append(entry.name)
  return value
 except:
  return ["error"]


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
