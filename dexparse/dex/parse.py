# -*- coding:UTF-8 -*-
import sys
import os
import struct
import binascii

'''
unsigned char uint8_tt;
unsigend short uint16_t;
unsigned int  uint32_t;
unsigned long long uint64_t;

signed char int8_t;
short int16_t;
int int32_t;
long long int64_t;


uint8_t u1;
uint16_t u2;
uint32_t  u4;
uint64_t  u8;

int8_t  s1;
int16_t s2;
int32_t  s4;
int64_t   s8;


struct DexHeader{

unsigned char[8]     magic;
uint         checksum; //
unsigned char[20]     signature;//
uint          file_size ;
uint          header_size;
uint          endia-tag;
uint           link_size;
uint            linke_off;
uint           map_item_off;
uint             string_idx_size;
uint             string_idx_offset;
uint             type_idx_size;
uint             type_idx_offset;
uint            prototype_idx_size;
uuint           prototype_idx_offset;
uint           field_idx_size   ;
uint             field_idx_offset;
uint            method_idx_size;
uint            method_idx_offset;
uint           class_defs_size;
uint           class_defs_offset;
uint           data_size;
uint          data_offset;

}

'''

print ("解析dex文件内容")
class DexHeader():
    
    def __init__(self):
        self.dexfile = sys.path[0]+os.sep+"classes.dex"
        if not os.path.isfile(self.dexfile):
            raise Exception("{} is not file or not exists".format(self.dexfile))
        self.fd = open(self.dexfile,'rb')
        #控制输出变量
        self.log_type_debug =1
        self.log_type_error =-1
        #
        self.string_item_datas_offset_list=set()#使用集合的方式，保证不为重复值
         
    def mprint(self,tag,msg,log_type=1):
        if log_type == self.log_type_debug:
            print ("[DEBUG]: {} = {}  ".format(tag,msg))
        elif log_type == self.log_type_error:
            print ('[ERROR]: {} = {}'.format(tag,msg))
   
    def parse_dexheader(self):
        print ('====================parse_dexheader=========================')
        if self.fd  is None:
            raise Exception("[ERROR]: filediscriptor object is None")
        #magic addr 0
        fmt = "<4s"
        self.fd.seek(0)
        data = self.fd.read(struct.calcsize(fmt))
        self.magic =  struct.unpack(fmt,data)[0]
        self.mprint("magic", binascii.b2a_hex(self.magic))
        # version addr  4
        self.fd.seek(4)
        self.version =  struct.unpack(fmt,self.fd.read(struct.calcsize(fmt)))[0]
        self.mprint('version', binascii.b2a_hex(self.version)) #二进制字符串转为ascci码的16进制
        #checksum  addr 8 
        fmt = "<I"
        self.fd.seek(8)
        offset = struct.calcsize(fmt)
        self.checksum = struct.unpack(fmt,self.fd.read(offset))[0]
        self.mprint('checksum', hex(self.checksum))
        #signature addr c
        self.fd.seek(0xc)
        fmt = "<20s"  #s python中 s表示char[] 表示bytes
        offset = struct.calcsize(fmt)
        self.signature = struct.unpack(fmt,self.fd.read(offset))[0]
        #为了打印出对应的16进制，这里的是字符类型，所有，需要转换为ascii -->hex
        self.mprint('signatures[20]', str(binascii.b2a_hex(self.signature)))
        #file_size addr 0x20
        self.fd.seek(0x20)
        self.file_size = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('file_size', hex(self.file_size))
        #header_size  addr 0x24
        self.fd.seek(0x24)
        self.header_size = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('header_size', hex(self.header_size))
        #endia-tag addr 0x28
        self.fd.seek(0x28)
        self.endia_tag = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('endia_tag', hex(self.endia_tag))
        #linke_size addr 0x2c
        self.fd.seek(0x2c)
        self.link_size = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('link_size', hex(self.link_size))
        #link_offset  addr 0x30
        self.fd.seek(0x30)
        self.link_offset = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('link_offset', hex(self.link_offset))
        #map_off addr 0x34
        self.fd.seek(0x34)
        self.map_offset = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('map_offset', hex(self.map_offset))
        #string_idx_sieze addr 0x38
        self.fd.seek(0x38)
        self.string_idx_size = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('string_idx_size', hex(self.string_idx_size))
        #string_idx_offset addr 0x3c
        self.fd.seek(0x3c)
        self.string_idx_offset = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('string_idx_size', hex(self.string_idx_offset))
        #type_idx_size addr 0x40
        self.fd.seek(0x40)
        self.type_idx_size =  struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('type_idx_size', hex(self.type_idx_size))
        #type_idx_size  addr 0x44
        self.fd.seek(0x44)
        self.type_idx_offset = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('type_idx_offset', hex(self.type_idx_offset))
        #proto_idx_size  addr 0x48
        self.fd.seek(0x48)
        self.proto_idx_size =  struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('proto_idx_size', hex(self.proto_idx_size))
        #proto_idx_offset addr 0x4c
        self.fd.seek(0x4c)
        self.proto_idx_offset = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('proto_idx_offset', hex(self.proto_idx_offset))
        #field_idx_size  addr 0x50 
        self.fd.seek(0x50)
        self.field_idx_size = struct.unpack("<I",self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('field_idx_size', hex(self.field_idx_size))
        #field_idx_offset addr 0x54
        self.fd.seek(0x54)
        self.field_idx_offset = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('field_idx_offset', hex(self.field_idx_offset))
        #method_idx_size addr 0x58
        self.fd.seek(0x58)
        self.method_idx_size = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('method_idx_size', hex(self.method_idx_size))
        #method_idx_offset addr  0x5c
        self.fd.seek(0x5c)
        self.method_idx_offset = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('metod_idx_offset', hex(self.method_idx_offset))
        #class_defs_idx_size addr 0x60
        self.fd.seek(0x60)
        self.class_defs_idx_size = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('class_defs_idx_size', hex(self.class_defs_idx_size))
        #class_defs_idx_offset addr 0x64
        self.fd.seek(0x64)
        self.class_defs_idx_offset = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('class_defs_idx_offset', hex(self.class_defs_idx_offset))
        #data_size  addr 0x68
        self.fd.seek(0x68)
        self.data_size = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('data_size', hex(self.data_size))
        #data_offset addr 0x6c
        self.fd.seek(0x6c)
        self.data_offset = struct.unpack('<I',self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('data_offset', hex(self.data_offset))
        
    def read_string_idx_datas(self):
        '''
        读取dex文件的string_idx的数据内容，读取string字符串的常量池
        '''
        print ('====================read string_idx_datas=========================')
        self.mprint('string_idx_size', self.string_idx_size)
        self.mprint('string_idx_offset', self.string_idx_offset)
        if self.string_idx_size <=0 or self.string_idx_offset <= 0:
            self.mprint('read string idx ', 'data is invalid', log_type=self.log_type_error)
            return
        #先输出所有的string_item_data_offset 的地址
        #首先，fd先跳转到string_idx_offset的地址，然后开始遍历出所有的string_item_data_offset的地址，根据string_idx_size来控制循环
        self.fd.seek(self.string_idx_offset)
        index_id =0
        fmt = '<I' #采用无符号数
        while index_id < self.string_idx_size:
            #每个string_item_data_offset占4个自己 ，选择为I
            string_item_data_offset = struct.unpack(fmt,self.fd.read(struct.calcsize(fmt)))[0]
            self.string_item_datas_offset_list.add(string_item_data_offset)
#             self.mprint('string_item_data_offset', hex(string_item_data_offset)) #输出16进制格式
            index_id +=1
#             break
        print ('****************************read string_idx_datas finished*******************************')
        self.mprint('all string_item_offset ', index_id)
        if self.string_item_datas_offset_list.__len__() == self.string_idx_size:
            self.mprint('read string_item_data_offset ', 'successful')
            #在这里解析出每一个item的数据
        else: #读取数据出现缺失
            self.mprint('read string_item_data_offset', 'failed', log_type=self.log_type_error)
    def read_string_item_datas(self):
        '''
        读取每一个string_item_data,如下结构
        
        struct string_item_data{}
        uleb128 size;
        u1 data[size]
        };
        解析出size ,然后读取后面的字符，转换为ascii 
        在dex文件结构中说明了，每一个字符串的长度是使用uleb128（可变长度的大小）来计算。
        这里首先计算出size，同时，每个字符串
        的结尾使用00来作为标记。
        '''
        pass
        
        pass
    def read_type_idx_datas(self):
        '''
        读取dex文件的type_idx的数据内容 数据类型
        根据string_idx_offset 定位到string_idx的常量地址，根据
        string_item_data {
         
        }
        '''
        print ('====================read_type_idx_datas=========================')
        pass
    def read_proto_idx_datas(self):
        '''
        读取dex文件的proto_idx的数据内容 方法原型
        '''
        print ('====================read_proto_idx_datas=========================')
        pass
    def read_field_idx_datas(self):
        '''
        读取dex文件的field_idx的数据内容
        '''
        print ('====================read_field_idx_datas=========================')
        pass
    def read_method_idx_datas(self):
        '''
        读取dex文件的method_idx的数据内容
        '''
        print ('====================read_method_idx_datas=========================')
        pass
    def close_dexreader(self):
        self.fd.close()
        
        
#####      
dexheader = DexHeader()
dexheader.parse_dexheader()
dexheader.read_string_idx_datas()
dexheader.close_dexreader()    #关闭资源