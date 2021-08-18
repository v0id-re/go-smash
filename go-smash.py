import struct
import lief
import argparse

class BadAddrError(Exception):
    pass

class go_executable(object):
    def __init__(self, exe_path, open_log, out_path, keywords):
        self.exe_path = exe_path
        self.binary = lief.parse(exe_path).abstract
        self.sections = self.binary.sections
        self.ptr_size = 8 if self.binary.header.is_64 else 4
        self.content = open(exe_path,'rb').read(-1)
        self.mem = self.load_sections()
        self.magic = 0xFFFFFFFA
        self.name_set = set()
        self.log = open_log
        self.out_path = out_path if out_path!='' else self.exe_path + '_smashed'
        self.keywords = keywords

    def load_sections(self):
        m = b''
        for i in range(len(self.sections)):
            m += bytes([0 for j in range(self.sections[i].virtual_address - len(m))])
            offset = self.sections[i].offset
            size = self.sections[i].size
            m += self.content[offset:offset+size]
        return m

    def sunday_search(self, s, m):
        shift = [0 for i in range(300)]
        l = len(m)
        for i in range(300):
            shift[i] = l + 1
        for i in range(l):
            shift[m[i]] = l - i
        lens = len(s)
        cur = 0
        while(cur < lens-l):
            i = 0
            while(i < l):
                if(s[cur+i]!=m[i]):
                    break
                if(i == l-1):
                    return cur
                i+=1
            cur+=shift[s[cur+l]]
        return -1
    
    def ptr(self,addr,ptr_size = 0):
        if ptr_size==0:
            ptr_size = self.ptr_size
        try:
            if ptr_size==8:
                return struct.unpack('<Q',self.mem[addr:addr+8])[0]
            else:
                return struct.unpack('<I',self.mem[addr:addr+4])[0]
        except:
            raise BadAddrError()

    def check_is_gopclntab16(self, addr):
        try:
            offset = 8 + self.ptr_size * 6 
            first_entry = self.ptr(addr+offset) + addr
            func_loc = self.ptr(first_entry)
            struct_ptr = self.ptr(first_entry+8) + first_entry
            first_entry = self.ptr(struct_ptr)
            if func_loc == first_entry:
                return True
            return False
        except BadAddrError:
            return False

    def check_is_gopclntab(self,addr):
        try:
            first_entry = self.ptr(addr + 8 + self.ptr_size)
            first_entry_off = self.ptr(addr + 8 + self.ptr_size * 2)
            addr_func = addr + first_entry_off
            func_loc = self.ptr(addr_func)
            if func_loc == first_entry:
                return True
            return False
        except BadAddrError:
            return False

    def find_gopclntab16(self):
        pos = []
        m = self.mem
        while(1):
            res = self.sunday_search(m,struct.pack('<I',self.magic))
            if(res==-1):
                break
            offset = pos[len(pos)-1] + 4 if len(pos)!=0 else 0
            pos.append(res + offset)
            m = m[res+4:] #找到一处 magic 就向后跳 4 个字节

        for i in range(len(pos)):
            if(self.check_is_gopclntab16(pos[i])):
                return pos[i]
    
    def find_gopclntab(self):
        pos = []
        m = self.mem
        self.magic = 0xFFFFFFFB
        while(1):
            res = self.sunday_search(m,struct.pack('<I',self.magic))
            if(res==-1):
                break
            offset = pos[len(pos)-1] + 4 if len(pos)!=0 else 0
            pos.append(res + offset)
            m = m[res+4:] #找到一处 magic 就向后跳 4 个字节

        for i in range(len(pos)):
            if(self.check_is_gopclntab(pos[i])):
                return pos[i]

    def get_string(self,addr):
        s = ''
        i = 0
        while(1):
            cur = self.mem[addr+i]
            if(cur == 0):
                break
            s += chr(cur)
            i += 1
        return s

    def rot32(self,value,shift):
        return (value >> shift) | ((value << (32 - shift)) % 0x100000000)
    
    def get_obscured_name(self,name):
        name_hash = 0
        for i in range(len(name)):
            name_hash = self.rot32(name_hash,13)
            name_hash = (name_hash + ord(name[i])) % 0x100000000
        cur = 0
        obscured_name = ''
        for i in range(len(name)):
            cur = name_hash % 3
            name_hash = int(name_hash/3)
            obscured_name += ['o','0','O'][cur]
        if obscured_name not in self.name_set:
            self.name_set.add(obscured_name)
            return obscured_name
        else:
            return self.get_obscured_name(obscured_name)

        
    def get_name_addr16(self,pclntab_addr):
        first_entry = self.ptr(pclntab_addr + self.ptr_size * 6 + 8) + pclntab_addr

        cnt = self.ptr(pclntab_addr + 8)
        funcname_start = pclntab_addr + 8 + self.ptr_size * 7
        for i in range(cnt):
            struct_ptr = self.ptr(first_entry + i * self.ptr_size * 2 + 8) + first_entry
       
            func_addr = self.ptr(first_entry + i * self.ptr_size * 2)
            str_val = self.ptr(struct_ptr+8 , ptr_size=4) + funcname_start
            name = self.get_string(str_val)
            obscured_name = self.get_obscured_name(name)
            if self.log:
                print(f"[FUNC] {func_addr:x} {name} => {obscured_name}")

            for i in self.keywords:
                if i in name:    
                    self.write_to_content(str_val,obscured_name)
                    break

    def get_name_addr(self,pclntab_addr):
        base = pclntab_addr
        pos = pclntab_addr + 8 #skip header
        size = self.ptr(pos)
        pos += self.ptr_size
        end = pos + (size * self.ptr_size * 2)
        while pos < end:
            offset = self.ptr(pos + self.ptr_size)
            pos += self.ptr_size * 2
            func_addr = self.ptr(base + offset)
            name_offset = self.ptr(base + offset + self.ptr_size, ptr_size=4)
            name = self.get_string(base + name_offset)
            obscured_name = self.get_obscured_name(name)
            if self.log:
                print(f"[FUNC] {func_addr:x} {name} => {obscured_name}")

            for i in self.keywords:
                if i in name:   
                    self.write_to_content(base + name_offset,obscured_name)
                    break

    def rva2off(self,addr):
        sec_len = len(self.sections)
        for i in range(sec_len):
            if(self.sections[i].virtual_address <= addr and addr <= self.sections[i].virtual_address + self.sections[i].size):
                return addr - self.sections[i].virtual_address + self.sections[i].offset


    def write_to_content(self,addr,obscured_name):
        offset = self.rva2off(addr)
        self.content = self.content[:offset] + bytes(obscured_name,encoding='utf8') + self.content[offset+len(obscured_name):]


    def write_to_executable(self):
        smashed_exe = open(self.out_path,'wb')
        smashed_exe.write(self.content)
        smashed_exe.close()


parser = argparse.ArgumentParser(description='go-smash.py -- Obfuscate go binaries')
parser.add_argument('-b','--binary_path', type=str,help='path to the binary that you want to obfuscate')
parser.add_argument('-o','--out_path', help='path to obfuscated binary', default='')
parser.add_argument('-n','--no-log', help='no log', action='store_true')
parser.add_argument('-k','--keywords', nargs='+', help='specify the keywords , functions with these keywords in their names will be obfuscated')

#parser.add_argument('-lv','--later-version',help='force to use later version of go(1.6+)',action='store_true')
#parser.add_argument('-t','--pclntab',help='specify the rva of pclntab') TODO

args = parser.parse_args()

print(args.keywords)
go_exe = go_executable(args.binary_path, not args.no_log, args.out_path, args.keywords)
pclntab = go_exe.find_gopclntab16()
if  pclntab == None:
    pclntab = go_exe.find_gopclntab()
    go_exe.get_name_addr(pclntab)
else:
    go_exe.get_name_addr16(pclntab)
go_exe.write_to_executable()
print("[SUCCESS] file "+ args.out_path)




