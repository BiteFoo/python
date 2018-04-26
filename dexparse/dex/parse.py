# -*- coding:UTF-8 -*-
import sys
import os
import struct
import binascii
import time
import re

from class_defs import ClassDefs, DexClassDataHeader, DexField, DexMethod
from field import FieldIdx
from methods import DexMethodIdx
from paramters import DexMethodProto
from settings import *

'''
unsigned char uint8_t;
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

主要参考：
http://mybeibei.net/1103.html 

'''

print("解析dex文件内容")

# 'classes.dex.hidden'#'classes.dex' #'MyHide.dex' hidex.dex
TEST_DEXFILE = sys.path[0] + os.sep + 'dexfile' + os.sep + 'MyHide.dex'


class DexHeader():

    def __init__(self):
        self.dexfile = TEST_DEXFILE
        if not os.path.isfile(self.dexfile):
            raise Exception(
                "{} is not file or not exists".format(self.dexfile))
        self.fd = open(self.dexfile, 'rb')
        self.strings_datas_list = []  # 保存所有的字符数据集合
        self.string_datas_dict = {}
        # 控制输出变量
        self.log_type_debug = 1
        self.log_type_error = -1
        #
        self.string_item_datas_offset_list = []  # 使用集合的方式，保证不为重复值
        self.method_code_off = []  # 记录code的偏移地址
        # 2018-04-23添加标记方法输出
        self.is_method_print = False

        self.open_debug = False  # 用于打印出输出日志信息 True表示开启 False表示关闭

    def get_method_code_off_list(self):
        return self.method_code_off

    def mprint(self, tag, msg, log_type=1):

        if self.open_debug:
            if log_type == self.log_type_debug:
                print("[DEBUG]: {} = {}  ".format(tag, msg))
            elif log_type == self.log_type_error:
                print('[ERROR]: {} = {}'.format(tag, msg))

    def parse_dexheader(self):
        self.mprint(
            '', '====================parse_dexheader=========================')
        if self.fd is None:
            raise Exception("[ERROR]: filediscriptor object is None")
        # magic addr 0
        fmt = "<4s"
        self.fd.seek(0)
        data = self.fd.read(struct.calcsize(fmt))
        self.magic = struct.unpack(fmt, data)[0]
        self.mprint("magic", binascii.b2a_hex(self.magic))
        # version addr  4
        self.fd.seek(4)
        self.version = struct.unpack(
            fmt, self.fd.read(struct.calcsize(fmt)))[0]
        self.mprint('version', binascii.b2a_hex(
            self.version))  # 二进制字符串转为ascci码的16进制
        # checksum  addr 8
        fmt = "<I"
        self.fd.seek(8)
        offset = struct.calcsize(fmt)
        self.checksum = struct.unpack(fmt, self.fd.read(offset))[0]
        self.mprint('checksum', hex(self.checksum))
        # signature addr c
        self.fd.seek(0xc)
        fmt = "<20s"  # s python中 s表示char[] 表示bytes
        offset = struct.calcsize(fmt)
        self.signature = struct.unpack(fmt, self.fd.read(offset))[0]
        # 为了打印出对应的16进制，这里的是字符类型，所有，需要转换为ascii -->hex
        self.mprint('signatures[20]', str(binascii.b2a_hex(self.signature)))
        # file_size addr 0x20
        self.fd.seek(0x20)
        self.file_size = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('file_size', hex(self.file_size))
        # header_size  addr 0x24
        self.fd.seek(0x24)
        self.header_size = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('header_size', hex(self.header_size))
        # endia-tag addr 0x28
        self.fd.seek(0x28)
        self.endia_tag = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('endia_tag', hex(self.endia_tag))
        # linke_size addr 0x2c
        self.fd.seek(0x2c)
        self.link_size = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('link_size', hex(self.link_size))
        # link_offset  addr 0x30
        self.fd.seek(0x30)
        self.link_offset = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('link_offset', hex(self.link_offset))
        # map_off addr 0x34
        self.fd.seek(0x34)
        self.map_offset = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('map_offset', hex(self.map_offset))
        # string_idx_sieze addr 0x38
        self.fd.seek(0x38)
        self.string_idx_size = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('string_idx_size', hex(self.string_idx_size))
        # string_idx_offset addr 0x3c
        self.fd.seek(0x3c)
        self.string_idx_offset = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('string_idx_offset', hex(self.string_idx_offset))
        # type_idx_size addr 0x40
        self.fd.seek(0x40)
        self.type_idx_size = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('type_idx_size', hex(self.type_idx_size))
        # type_idx_size  addr 0x44
        self.fd.seek(0x44)
        self.type_idx_offset = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('type_idx_offset', hex(self.type_idx_offset))
        # proto_idx_size  addr 0x48
        self.fd.seek(0x48)
        self.proto_idx_size = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('proto_idx_size', hex(self.proto_idx_size))
        # proto_idx_offset addr 0x4c
        self.fd.seek(0x4c)
        self.proto_idx_offset = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('proto_idx_offset', hex(self.proto_idx_offset))
        # field_idx_size  addr 0x50
        self.fd.seek(0x50)
        self.field_idx_size = struct.unpack(
            "<I", self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('field_idx_size', hex(self.field_idx_size))
        # field_idx_offset addr 0x54
        self.fd.seek(0x54)
        self.field_idx_offset = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('field_idx_offset', hex(self.field_idx_offset))
        # method_idx_size addr 0x58
        self.fd.seek(0x58)
        self.method_idx_size = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('method_idx_size', hex(self.method_idx_size))
        # method_idx_offset addr  0x5c
        self.fd.seek(0x5c)
        self.method_idx_offset = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('metod_idx_offset', hex(self.method_idx_offset))
        # class_defs_idx_size addr 0x60
        self.fd.seek(0x60)
        self.class_defs_idx_size = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('class_defs_idx_size', hex(self.class_defs_idx_size))
        # class_defs_idx_offset addr 0x64
        self.fd.seek(0x64)
        self.class_defs_idx_offset = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('class_defs_idx_offset', hex(self.class_defs_idx_offset))
        # data_size  addr 0x68
        self.fd.seek(0x68)
        self.data_size = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('data_size', hex(self.data_size))
        # data_offset addr 0x6c
        self.fd.seek(0x6c)
        self.data_offset = struct.unpack(
            '<I', self.fd.read(struct.calcsize('<I')))[0]
        self.mprint('data_offset', hex(self.data_offset))

    def read_string_idx_datas(self):
        '''
        读取dex文件的string_idx的数据内容，读取string字符串的常量池
        '''
        self.mprint(
            '', '====================read string_idx_datas=========================')
        self.mprint('string_idx_size', self.string_idx_size)
        self.mprint('string_idx_offset', self.string_idx_offset)
        if self.string_idx_size <= 0 or self.string_idx_offset <= 0:
            self.mprint('read string idx ', 'data is invalid',
                        log_type=self.log_type_error)
            return
        # 先输出所有的string_item_data_offset 的地址
        # 首先，fd先跳转到string_idx_offset的地址，然后开始遍历出所有的string_item_data_offset的地址，根据string_idx_size来控制循环
        self.fd.seek(self.string_idx_offset)
        index_id = 0
        fmt = '<I'  # 采用无符号数
        while index_id < self.string_idx_size:
            # 每个string_item_data_offset占4个自己 ，选择为I
            string_item_data_offset = struct.unpack(
                fmt, self.fd.read(struct.calcsize(fmt)))[0]
            self.string_item_datas_offset_list.append(string_item_data_offset)
# self.mprint('string_item_data_offset', hex(string_item_data_offset))
# #输出16进制格式
            index_id += 1
#             break
        self.mprint(
            '', '****************************read string_idx_datas finished*******************************')
        self.mprint('all string_item_offset ', index_id)
        if self.string_item_datas_offset_list.__len__() == self.string_idx_size:
            self.mprint('read string_item_data_offset ', 'successful')
            for offset in self.string_item_datas_offset_list:
                if '0x20e' == hex(offset):
                    print('----------found item mmmm {}'.format(offset))
                self.read_string_item_datas(offset)
#       #输出结果
#             if self.string_datas_dict != None :#字典的形式保存，使用offset作为key ,value就是读取的结果值
#                 for offset in self.string_datas_dict.keys():
#                     self.mprint('offset', hex(offset))
#                     self.mprint('string_data', binascii.b2a_hex(self.string_datas_dict[offset]))
#             if self.strings_datas_list.__len__() >0 and self.strings_datas_list != None: #列表保存所有的字符
#                 for strings in self.strings_datas_list:
#                     self.mprint('strings_item', strings)
    #                 break
            # 在这里解析出每一个item的数据
        else:  # 读取数据出现缺失
            self.mprint('read string_item_data_offset',
                        'failed', log_type=self.log_type_error)

    def read_uleb128(self, offset=0):
        '''
        计算uleb128的长度
        这里使用的MyHide.dex文件
        读取方是：
                0 1  2  3  4  5  6  7  8  9  a b 
        0x180: e4 01 01 09 fc 01 01 02 90 02 00 00 
        第一次读取四个字节，在第一次读取的时候，fd的位置为0x180 ，
        struct.unpack('i',fd.read(struct.calcsize('i')))
        e4 01  01 09 -->输出 0x090101e4 ，通过ljust(4,'\0')方法对齐，不满足4个字节的是\0补充
        执行后。fd的位置调整为0x184
        执行
        result=result&0x000000ff -->0xe ,得到最后一个字节
        通过fd.seek(-3,1)，调整fd的位置，去读取下一个字节，每次依然读取的是4个字节，例如
        fd=0x181，只是fd的位置调整到了0x181,往后读取4个字节 --此时，fd的位置调整为了0x185,每次都通过
        fd.seek(-3,1)的方式调整文件指针，直到读取到最后一个字节

        '''
#         print ('====================read_uleb128=========================')
        if self.is_method_print:

            self.mprint('fd current position >>>>', hex(self.fd.tell()))
        result = struct.unpack('i', self.fd.read(
            struct.calcsize('i')).ljust(4, b'\0'))[0]
        if self.is_method_print:
            self.mprint(
                '<<<<<origin method code off before uleb128 calcu ', hex(result))
            self.mprint('fd current position <<< ', hex(self.fd.tell()))
        # 这里取出代表uleb128的字符数据长度，只取最后一个字节，最后一个字节为string_item_data的长度
        result = result & 0x000000ff
        if self.is_method_print:
            self.mprint('first byte,', hex(result))
        # 保证每次都能完后添加一个字节 例如在一开始读取的为 aa bb cc dd ee ff 一次读取四个字节 ，aa bb cc dd -->
        # 下一次
        # 读取  bb cc dd ee 每次都往后移动一个字节
        # seek(off,wherece=0) wherece的取值，0文件其实，1当前位置，2文件末尾
        self.fd.seek(-3, 1)
        if result > 0x7f:  # 如果大于0x7f，那么需要第二个字节
            if self.is_method_print:
                self.mprint('fd position is:', hex(self.fd.tell()))
            cur = struct.unpack('i', self.fd.read(struct.calcsize('i')))[0]
            cur = cur & 0x000000ff  # 取出最低位的字节序
            result = (result & 0x7f) | ((cur & 0x7f) << 7)
            if self.is_method_print:
                self.mprint('next byte1111', hex(cur))
                self.mprint('cur 111', hex(cur))
                self.mprint('111111 current position <<< ',
                            hex(self.fd.tell()))
                self.mprint('second byte,', hex(result))
            self.fd.seek(-3, 1)
            if cur > 0x7f:  # 第三个字节
                cur = struct.unpack('i', self.fd.read(struct.calcsize('i')))[0]
                cur = cur & 0x000000ff
                result = (result & 0x7f) | ((cur & 0x7f) << 14)
                if self.is_method_print:
                    self.mprint('next byte2222', hex(cur))
                    self.mprint('22222 current position <<< ',
                                hex(self.fd.tell()))
                    self.mprint('third byte,', hex(result))
                self.fd.seek(-3, 1)
                if cur > 0x7f:  # 第四个字节
                    cur = struct.unpack(
                        'i', self.fd.read(struct.calcsize('i')))[0]
                    cur = cur & 0x000000ff  # 取出最低位的字节
                    result = (result & 0x7f) | ((cur & 0x7f) << 21)
                    if self.is_method_print:
                        self.mprint('next byte333', hex(cur))
                        self.mprint('33333 current position <<< ',
                                    hex(self.fd.tell()))
                        self.mprint('fourth byte,', hex(result))
                    self.fd.seek(-3, 1)
                    if cur > 0x7f:  # 第5个字节
                        cur = struct.unpack(
                            'i', self.fd.read(struct.calcsize('i')))[0]
                        cur = cur & 0x0000ff
                        result = result | cur << 28
                        if self.is_method_print:
                            self.mprint('next byte4444', hex(cur))
                            self.mprint('4444 current position <<< ',
                                        hex(self.fd.tell()))
                            self.mprint('fifth byte,', hex(result))
        if self.is_method_print:
            self.mprint(
                '<<<<<origin method code off  final uleb128 calcu', hex(result))

        return result

    def read_string_item_datas(self, offset):
        '''
        读取string_items_data
        根据offset查询出字符串的内容
        '''
#         print ('====================read_string_item_datas=========================')
#         offset = 746047 #测试使用超过了0x7f的值
#         self.mprint('offset', hex(offset))
        self.fd.seek(offset, 0)
        uleb12_size = self.read_uleb128()
        if uleb12_size == '\x00':
            print(
                '**************found \x00************>>offset = {},uleb128_size={}'.format(offset, uleb12_size))
            sys.exit(1)
            return
#         self.mprint('uleb128 size', hex(uleb12_size))
        # 读取指定长度的字符数据
        # 为什么在读取的时候没有包含到长度位置的值，因为在使用read_uleb128的时候，使用了file.seek(-3,1)
        string_data = self.fd.read(uleb12_size)
        # 每次都能完后移动一个单位
        #
        fmt = str(uleb12_size) + 's'
        result = struct.unpack(fmt, string_data)[0]
#         self.mprint('string_data', result) #字符数据，需要转为ascii值，才能读取
        self.strings_datas_list.append(result)
        self.string_datas_dict[offset] = result

    def get_strings_data(self):
        """
        返回字符串数据,返回的数据是byte对象
        """
        return self.strings_datas_list

    def read_type_idx_datas(self):
        '''
        读取dex文件的type_idx的数据内容 数据类型,每个

        typy_item{
        u4 description ;这里指向的是string的表，表示每个类型值
        }
        '''
        self.mprint(
            '', '====================read_type_idx_datas=========================')
        self.type_item_list = []
        self.fd.seek(self.type_idx_offset, 0)  # 首先，保证游标读取到指定位置的首页
        index_item = 0
        while index_item < self.type_idx_size:
            type_item = struct.unpack(
                'I', self.fd.read(struct.calcsize('I')))[0]
            self.type_item_list.append(type_item)
            index_item += 1
        idx = 0
        for item in self.type_item_list:
            self.mprint('type_item', hex(item))
            if '0x20e' == hex(item):
                self.mprint('found item', item)
                while idx < self.string_item_datas_offset_list.__len__():
                    idx += 1
                    # 根据type_idx的索引值，找到string_idx_list的序列号(从0~string_idx_list_len)的长度，然后找到对应的offset，最后根据offset取出值
                    if idx == 0x20e:
                        offset = self.string_item_datas_offset_list[idx]
                        value = self.string_datas_dict[offset]
                        self.mprint('found type value', value)
                        break
                break

    def show_proto_paramters_list(self):
        '''
        读取每一个方法参数的列表类型值
        '''
        if self.proto_idx_obj_list == None or self.proto_idx_obj_list.__len__() <= 0:
            self.mprint('show_proto_paramters_list',
                        'show_proto_paramters_list is None ', log_type=self.log_type_error)
            return
        if self.proto_idx_obj_dict == None:
            self.mprint('proto_idx_obj_dict',
                        'proto_idx_obj_dict is None ', log_type=self.log_type_error)
            return
#         for obj in self.proto_idx_obj_list: #使用list的方式输出，不能较好的记录到每个proto_item的索引号
#             self.mprint('shorty_idx', hex(obj.shorty_idx))
#             self.mprint('returnty_idx', hex(obj.return_type_idx ))
#             self.mprint('paramters_offset', hex( obj.parameter_type_offset))#这里的每个offset都指向了一个type_list
#             if obj.parameter_type_offset != 0x0:
#                 self.fd.seek(obj.parameter_type_offset,0)
#                 type_size = struct.unpack('I',self.fd.read(struct.calcsize('I')))[0]
#                 type_item =  struct.unpack('H',self.fd.read(struct.calcsize('H')))[0] #H表示unsigned char 两个字节 h 表示有符号
#                 self.mprint('type_size', hex(type_size))
#                 self.mprint('type_item', hex(type_item))
#             print ('---'*20)
# 根据每个idx作为所以，刚好能够输出每一个数据项和对应的item项，存在idx位置，可以方便对别数据
        for index_id in self.proto_idx_obj_dict.keys():  # 使用list的方式输出，能记录到每个proto_item的索引号
            self.mprint('proto_item_idx', index_id)
            proto_item = self.proto_idx_obj_dict[index_id]
            self.mprint('shorty_idx', hex(proto_item.shorty_idx))
            self.mprint('returnty_idx', hex(proto_item.return_type_idx))
            # 这里的每个offset都指向了一个type_list
            self.mprint('paramters_offset', hex(
                proto_item.parameter_type_offset))
            if proto_item.parameter_type_offset != 0x0:
                tmp_idx = 0
                self.fd.seek(proto_item.parameter_type_offset, 0)
                type_size = struct.unpack(
                    'I', self.fd.read(struct.calcsize('I')))[0]
                self.mprint('type_size', hex(type_size))
                while tmp_idx < type_size:
                    type_item = struct.unpack('H', self.fd.read(struct.calcsize('H')))[
                        0]  # H表示unsigned char 两个字节 h 表示有符号
                    self.mprint('type_item_{}'.format(tmp_idx), hex(type_item))
                    tmp_idx += 1
            print('---' * 20)

        pass

    def read_proto_idx_datas(self):
        '''
        读取dex文件的proto_idx的数据内容 方法原型
        '''
        self.mprint(
            '', '====================read_proto_idx_datas=========================')
        self.proto_idx_obj_list = []
        self.proto_idx_obj_dict = {}
        self.fd.seek(self.proto_idx_offset, 0)
        count = 0
        fmt = 'I'
        while count < self.proto_idx_size:
            proto_paramters = DexMethodProto()
            proto_paramters.shorty_idx = struct.unpack(fmt, self.fd.read(struct.calcsize(fmt)))[
                0]  # -->string_idx_list 指向string_idx_list的索引地址
            proto_paramters.return_type_idx = struct.unpack(fmt, self.fd.read(
                struct.calcsize(fmt)))[0]  # 指向type_idx_list的索引号，类似于type_idx索引string_idx_list一样
            proto_paramters.parameter_type_offset = struct.unpack(
                fmt, self.fd.read(struct.calcsize(fmt)))[0]  # 根据paramters_offset读取方法参数列表
            self.proto_idx_obj_list.append(proto_paramters)
            # 这里采用每个idx作为一个索引号，保存在一个字典中，方便后续使用
            self.proto_idx_obj_dict[count] = proto_paramters
            count += 1
        self.mprint('proto_paramters', self.proto_idx_obj_list.__len__())
#         self.show_proto_paramters_list() #在这里读取每个对象的数据参数类型值
        pass

    def read_field_idx_data(self):
        '''
        读取每一个数据项
        '''
        if self.field_idx_dict is None or self.field_idx_list is None or self.field_idx_list.__len__() <= 0:
            self.mprint('read_field_idx_data',
                        'field_idx_dict or field_idx_list is None ', log_type=self.log_type_error)
            return
        for idx in self.field_idx_dict.keys():
            self.mprint('fied_idx', idx)
            field_idx_obj = self.field_idx_dict[idx]
            self.mprint('fied_ix_class_idx', hex(field_idx_obj.class_idx))
            self.mprint('fied_ix_class_idx', hex(field_idx_obj.type_idx))
            self.mprint('fied_ix_class_idx', hex(field_idx_obj.name_idx))
            print('***' * 20)
        pass

    def read_field_idx_datas(self):
        '''
        读取dex文件的field_idx的数据内容
        '''
        self.mprint(
            '', '====================read_field_idx_datas=========================')
        self.fd.seek(self.field_idx_offset, 0)
        count = 0
        fmt_2 = 'H'
        fmt_4 = 'I'
        self.field_idx_list = []  # 使用list的方式存放
        self.field_idx_dict = {}  # 字典方式存放
        while count < self.field_idx_size:
            field_idx_obj = FieldIdx()
            field_idx_obj.class_idx = struct.unpack(
                fmt_2, self.fd.read(struct.calcsize(fmt_2)))[0]
            field_idx_obj.type_idx = struct.unpack(
                fmt_2, self.fd.read(struct.calcsize(fmt_2)))[0]
            field_idx_obj.name_idx = struct.unpack(
                fmt_4, self.fd.read(struct.calcsize(fmt_4)))[0]
            self.field_idx_list.append(field_idx_obj)
            self.field_idx_dict[count] = field_idx_obj
            count += 1
#         self.read_field_idx_data()
        pass

    def show_method_idx_item_data(self):
        if self.method_idx_dict is None:
            self.mprint('read_method_idx_datas',
                        'read_method_idx_datas was failed ', log_type=self.log_type_error)
            return
        for idx in self.method_idx_dict.keys():
            self.mprint('method_idx', idx)
            method_idx_obj = self.method_idx_dict[idx]
            self.mprint('method_idx_obj.class_idx',
                        hex(method_idx_obj.class_idx))
            self.mprint(' method_idx_obj.proto_idx ',
                        hex(method_idx_obj.proto_idx))
            self.mprint('method_idx_obj.name_idx',
                        hex(method_idx_obj.name_idx))
            self.mprint('', '===' * 20)

    def read_method_idx_datas(self):
        '''
        读取dex文件的method_idx的数据内容
        '''
        self.mprint(
            '', '====================read_method_idx_datas=========================')
        self.fd.seek(self.method_idx_offset, 0)
        fmt_2 = 'H'
        fmt_4 = 'I'
        self.method_idx_list = []  # 保存method的列表
        # 根据index保存method的对象数据
        # ，查找方法：从method_idx_list取出idx-->根据idx从method_idx_dict取出method，最后在查询数据
        self.method_idx_dict = {}
        count = 0
        while count < self.method_idx_size:
            method_obj = DexMethodIdx()
            method_obj.class_idx = struct.unpack(
                fmt_2, self.fd.read(struct.calcsize(fmt_2)))[0]
            method_obj.proto_idx = struct.unpack(
                fmt_2, self.fd.read(struct.calcsize(fmt_2)))[0]
            method_obj.name_idx = struct.unpack(
                fmt_4, self.fd.read(struct.calcsize(fmt_4)))[0]
            self.method_idx_list.append(method_obj)
            self.method_idx_dict[count] = method_obj
            count += 1
        # self.show_method_idx_item_data()

    def read_class_data_item_by_class_data_off(self, class_data_off):
        if class_data_off == 0x0:
                    # 表明这里是接口类，没有方法体
            self.mprint('interface', 'found interface class object')
            return
        self.fd.seek(class_data_off)  # 跳转到指定的类位置
        # 读取uleb128的数据值
        static_field_size = self.read_uleb128()
        instance_field_size = self.read_uleb128()
        direct_method_size = self.read_uleb128()
        virtual_method_size = self.read_uleb128()

        self.mprint('static field size', static_field_size)
        static_field_idx = 0
        while static_field_size > 0:
            static_field_diff = self.read_uleb128()
            self.mprint('static field ', self.field_idx_list[
                        static_field_idx + static_field_diff])
            static_field_idx += static_field_diff
            access_flags = self.read_uleb128()
            static_field_size -= 1
            self.mprint('', '++++' * 20)
        self.mprint('instance field size ', instance_field_size)
        instance_field_idx = 0
        while instance_field_size > 0:
            instance_field_diff = self.read_uleb128()
            self.mprint('instance field', self.field_idx_list[
                        instance_field_idx + instance_field_diff])
            instance_field_idx += instance_field_diff
            access_flags = self.read_uleb128()
            instance_field_size -= 1
            self.mprint('', '----' * 20)
        self.mprint('direct method size', direct_method_size)
        direct_method_idx = 0
        self.mark_method = 'directMethod:'  # 记录是那个方法
        while direct_method_size > 0:

            # 读取methodIdx的索引值
            direct_method_diff = self.read_uleb128()
            self.mprint('direct  method diff', hex(direct_method_diff))
            # 需要更改这个索引你列表的值，
            tmp = direct_method_idx + direct_method_diff
            self.find_method_name_by_idx(tmp)
            # method_idx_obj = self.method_idx_list[
            #     direct_method_idx + direct_method_diff]
            # if isinstance(method_idx_obj, DexMethodIdx):
            #     self.mprint('direct method class_idx ',
            #                 method_idx_obj.class_idx)
            #     self.mprint('direct method proto_idx ',
            #                 self.proto_idx_obj_list[method_idx_obj.proto_idx])
            #     self.mprint('direct method name_idx ',
            #                 self.strings_datas_list[method_idx_obj.name_idx])
            direct_method_idx += direct_method_diff

            # 访问标志
            access_flags = self.read_uleb128()
            self.mprint('direct  method access_flags ', hex(access_flags))
            # self.is_method_print = True
            self.mprint('calling method ------<<<<', self.is_method_print)
            # 读取指令偏移地址
            code_off = self.read_uleb128()
            self.is_method_print = False
            self.mprint('direct method code_off ', hex(code_off))
            # 这里要把文件读取的游标对象保存记录地址，方便读取一个code的时候，直接返回到当前位置，下一次读取就不会出现异常
            self.method_code_off.append(code_off)
            # 打印出指令码
            self.read_code_item_code(code_off)
#                 self.fd.seek(code_off,0)
            direct_method_size -= 1
            self.mprint('', '====' * 20)
        self.mprint('virtual method size', virtual_method_size)
        virtal_method_idx = 0
        self.mark_method = 'virtualMethod:'  # 记录是那个方法
        while virtual_method_size > 0:
            virtual_method_diff = self.read_uleb128()
            tmp = virtal_method_idx + virtual_method_diff
            self.find_method_name_by_idx(tmp)

            self.mprint('virutal method diff', hex(virtual_method_diff))
            self.mprint('virtual  method ', self.method_idx_list[
                        tmp])
            virtal_method_idx += virtual_method_diff
            access_flags = self.read_uleb128()
            self.mprint('virtual  method access_flags ', hex(access_flags))
            code_off = self.read_uleb128()
            self.read_code_item_code(code_off)
            self.mprint('virtual method code_off ', hex(code_off))
            virtual_method_size -= 1
            self.mprint('', '--**--' * 20)

    def read_code_item_code(self, code_off):
        '''
        在这里读取出每个方法的指令值
        '''
        if code_off == 0x0:
            '''
            没有code off
            '''
            return
        print('codeoff:', hex(code_off))
        # fp=open(TEST_DEXFILE,'rb')
        with open(TEST_DEXFILE, 'rb') as fp:

            # 如果我这里使用的是self.fd,在读取指令这里是错误的。如果重新打开的话，就不会出错
            # self.fd.seek(code_off,1)
            fp.seek(code_off, 1)
            fmt_2 = 'H'
            fmt_4 = 'I'
            method_register_size = struct.unpack(fmt_2, fp.read(2))[0]
            metdhod_ins_size = struct.unpack(fmt_2, fp.read(2))[0]
            method_outs_size = struct.unpack(fmt_2, fp.read(2))[0]
            method_tries_size = struct.unpack(fmt_2, fp.read(2))[0]
            method_debug_info_off = struct.unpack(
                fmt_4, fp.read(4))[0]  # debug信息
            method_insns_size = struct.unpack(fmt_4, fp.read(4))[0]  # 方法指令长度
            self.mprint('insns_code_size', hex(method_insns_size))
            print('insns_code_size:', hex(method_insns_size))

            count = 0
            while method_insns_size > 0:
                insns_code = struct.unpack(fmt_2, fp.read(2))[0]  # 方法指令
                self.mprint('insns_code', hex(insns_code))
                print('insns_code[%d]:' % count, hex(insns_code))
                method_insns_size -= 1
                count += 1
#         pass

    def read_class_defs(self):
        '''
        读取类型信息：根据class_defs读取出每个类
        要求输出对应的类型：
        className:完整的类名  com/xxx/xxx/AAA
        class_def_item_off:对应类名地址
        methodName:方法名称 例如：showMe
        methodCodeOff: 方法地址偏移
        methodInsArr:指令集数组
        '''
        count = 0

        while count < self.class_defs_idx_size:

            class_def_item_off = self.class_defs_idx_offset + count * 32

            self.fd.seek(class_def_item_off)
            class_idx,\
                access_flags,\
                superclass_idx,\
                interfaces_off,\
                source_file_idx,\
                annotations_off,\
                class_data_off,\
                static_values_off = struct.unpack("IIIIIIII", self.fd.read(32))

            #
            # -->stringsIds[typeIds[idx]]-->strings_ids_dict[stringsIds[typeIds[idx]]]
            self.mprint('class', self.type_item_list[class_idx])
            # print('class idx ', self.type_item_list[class_idx])
            # print('class  type idx ', self.type_item_list[class_idx])
            class_name = self.find_class_name_by_idx(class_idx)
            # print('className:', class_name)
            count += 1
            re_packg = packg_name + '.*'
            # 在这里判断出需要解析的类和方法
            if not self.check_class_isvalid(re_packg, class_name.decode('UTF-8').replace('L', '').replace('/', '.').replace(';', '')):
                continue
            print('className:', class_name)
            self.read_class_data_item_by_class_data_off(
                class_data_off)  # 读取class_data_item
        print('all class:', count)

    def check_class_isvalid(self, re_tag, class_name):
        """
        筛选符合条件的类作为输出
        re_tag:需要过滤的条件
        class_nmame:需要判断的内容
        """
        if re_tag is None or re_tag == '' or class_name is None or class_name == '':
            return False
        # print('=====>>:',packg_name+'.R.?*')
        # 过滤掉属性文件类
        reojb = re.compile(packg_name + '((.R.?)|(.BuildConfig))')
        for need_filter in need_filter_classes:
            valid = reojb.match(class_name)
            if valid:
                # print('found.....',class_name)
                return False
        # 过滤掉不符合包名的类
        reojb = re.compile(re_tag)
        # print('check_class_isvalid class_name>>>>:', class_name)
        match = reojb.match(class_name)

        return True if match is not None else False

    def find_string_value(self, idx):
        """
        根据idx读取string的值
        """
        off = self.string_item_datas_offset_list[idx]
        return self.string_datas_dict[off]

        pass

    def find_class_name_by_idx(self, idx):
        """
        查找type类型:查找idx查询字符串内容
        根据idx的值，查找字符串内容
        这里主要查询的是className和methodName

        如下
        #strind_idx=typeIds[class_idx]
        #string_offset=string_ids[strind_idx]
        #根据string_offset得到string
        #class_name=string_ids_dict[string_offset]
        """

        off = self.string_item_datas_offset_list[self.type_item_list[idx]]
        return self.string_datas_dict[off]

    def find_method_proto_by_idx(self, idx):
        """
        根据idx查询方法的原型，例如()V或者(III)Z等
        """
        # print('==' * 10)
        print('DexMethodProto,idx:', idx)
        # for proto in self.proto_idx_obj_list:

        #     shorty_idx = proto.shorty_idx
        #     returnTypeIdx = proto.return_type_idx
        #     parameters_off = proto.parameter_type_offset
        #     print('shorty_idx:', shorty_idx)
        #     print('returnTypeIdx:', returnTypeIdx)
        #     print('parameters_off:', parameters_off)
        # print('--' * 5)

        dexmethod_proto = self.proto_idx_obj_dict[idx]

        # self.find_class_name_by_idx(dexmethod_proto.shorty_idx)
        method_proto_name = self.find_string_value(dexmethod_proto.shorty_idx)

        # print('returnty_idx in typeIds:',self.type_item_list[dexmethod_proto.return_type_idx])
        # print('returnty_value in stringIds:',self.find_string_value(self.type_item_list[dexmethod_proto.return_type_idx]))

        # rtype_off=string_item_datas_offset_list[self.type_item_list[dexmethod_proto.return_type_idx]]
        # rtype=string_datas_dict[rtype_off]

        print('method_proto_name:', method_proto_name)
        print('returnty_value:', self.find_string_value(
            self.type_item_list[dexmethod_proto.return_type_idx]))
        # print('method_proto_rtype:',rtype)

        pass

    def find_method_name_by_idx(self, idx):
        """
        根据idx查询method的名称和所属于的类
        这里的idx是从
        class_data_off-->dexmethod-->method_idx-->DexMethodIdx--{class_idx,proto_idx,name}

        method=method_is[idx]
        proto=proto_idx[method.proto_idx]
        className=find_class_name_by_idx(method.idx)
        methodname=strinds_datas_dict[strings_idx[method.name]]
        """
        # print(type(idx))
        # self.find_method_proto_by_idx(idx)
        dex_method_idx = self.method_idx_list[idx]
        short_class_idx = dex_method_idx.class_idx
        name_idx = dex_method_idx.name_idx
        proto_idx = dex_method_idx.proto_idx  # 根据这个值，读取方法原型表

        print('===' * 10)
        print('%s' % self.mark_method)
        print('method idx:', idx)
        print('short_class_name：', self.find_class_name_by_idx(short_class_idx))
        print('method_name', self.find_string_value(name_idx))
        # print('name_idx idx:',name_idx)
        # print('short_class_idx：', self.find_class_name_by_idx(short_class_idx))
        self.find_method_proto_by_idx(proto_idx)
        pass

    def read_class_defs_idx_data(self):
        '''
        读取class_defx_idx数据内容,读取有问题，暂时不适用
        '''
        self.mprint(
            '', '====================read_class_defs_idx_data=========================')
        self.mprint('offset', hex(self.class_defs_idx_offset))
        self.fd.seek(self.class_defs_idx_offset, 0)

        count = 0
        fmt = 'I'
        self.class_def_item_list = []
        self.class_def_item_dict = {}
        while count < self.class_defs_idx_size:
            class_def_item = ClassDefs()
            class_def_item.class_idx = struct.unpack(
                fmt, self.fd.read(struct.calcsize(fmt)))[0]
            class_def_item.access_flag = struct.unpack(
                fmt, self.fd.read(struct.calcsize(fmt)))[0]
            class_def_item.superclass_idx = struct.unpack(
                fmt, self.fd.read(struct.calcsize(fmt)))[0]
            class_def_item.interface_offset = struct.unpack(
                fmt, self.fd.read(struct.calcsize(fmt)))[0]
            class_def_item.source_file_idx = struct.unpack(
                fmt, self.fd.read(struct.calcsize(fmt)))[0]
            class_def_item.annotation_idx_off = struct.unpack(
                fmt, self.fd.read(struct.calcsize(fmt)))[0]
            class_def_item.class_data_off = struct.unpack(
                fmt, self.fd.read(struct.calcsize(fmt)))[0]
            class_def_item.static_value_offset = struct.unpack(
                fmt, self.fd.read(struct.calcsize(fmt)))[0]
            self.class_def_item_list.append(class_def_item)
            self.class_def_item_dict[count] = class_def_item
            count += 1
        # for item in self.class_def_item_list:#使用list的方式输出
        #     if isinstance(item,ClassDefs):
        #         self.mprint('class_idx ',hex(item.class_idx))
        #         self.mprint('accessflag ', hex(item.access_flag))
        #         self.mprint('superclass ', hex(item.superclass_idx))
        #         self.mprint('interface_idx ', hex(item.interface_offset))
        #         self.mprint('source_file_idx ', hex(item.source_file_idx))
        #         self.mprint('class_data_item ', hex(item.class_data_off))
        #         self.mprint('static_value_off ', hex(item.static_value_offset))
        #         print('--*--'*20)
        #     pass
        for count_idx in self.class_def_item_dict.keys():  # 使用字典的方式输出
            self.mprint('class_idx_count', count_idx)
            item = self.class_def_item_dict[count_idx]
            if isinstance(item, ClassDefs):

                self.mprint('class_idx ', hex(item.class_idx))
                self.mprint('accessflag ', hex(item.access_flag))

                self.mprint('superclass ', hex(item.superclass_idx))
                self.mprint('interface_idx ', hex(item.interface_offset))

                self.mprint('source_file_idx ', hex(item.source_file_idx))
                self.mprint('annotation_idx_off', hex(item.annotation_idx_off))

                self.mprint('class_data_item ', hex(item.class_data_off))
                self.read_class_data_item(item.class_data_off)

                self.mprint('static_value_off ', hex(item.static_value_offset))

                print('=***=' * 20)
        pass

    def read_dex_class_data_header(self, offset):
        fmt_4 = 'I'
        # dexclassdataheader
        self.fd.seek(offset, 0)
        dex_class_data_header = DexClassDataHeader()
        dex_class_data_header.static_fileds_size = struct.unpack(
            fmt_4, self.fd.read(struct.calcsize(fmt_4)))[0]
        dex_class_data_header.instance_fileds_size = struct.unpack(
            fmt_4, self.fd.read(struct.calcsize(fmt_4)))[0]
        dex_class_data_header.direct_methods_size = struct.unpack(
            fmt_4, self.fd.read(struct.calcsize(fmt_4)))[0]
        dex_class_data_header.virtual_methods_size = struct.unpack(
            fmt_4, self.fd.read(struct.calcsize(fmt_4)))[0]
        pass

    def read_dex_field(self, offset, is_static=False):
        # dexfiled
        self.fd.seek(offset, 0)
        fmt_4 = 'I'
        if is_static:  # 静态属性
            static_dexfield = DexField()
            static_dexfield.field_idx = struct.unpack(
                fmt_4, self.fd.read(struct.calcsize(fmt_4)))[0]
            static_dexfield.access_flags = struct.unpack(
                fmt_4, self.fd.read(struct.calcsize(fmt_4)))[0]
        else:  # 实例属性
            instance_dexfield = DexField()
            instance_dexfield.field_idx = struct.unpack(
                fmt_4, self.fd.read(struct.calcsize(fmt_4)))[0]
            instance_dexfield.access_flags = struct.unpack(
                fmt_4, self.fd.read(struct.calcsize(fmt_4)))[0]
        pass

    def read_dex_method(self, offset, is_direct=False):
          # dexmethod
        self.fd.seek(offset, 0)
        fmt_4 = 'I'
        if is_direct:
            direct_dexmethod = DexMethod()
            direct_dexmethod.method_idx = struct.unpack(
                fmt_4, self.fd.read(fmt_4))[0]
            direct_dexmethod.access_flags = struct.unpack(
                fmt_4, self.fd.read(fmt_4))[0]
            direct_dexmethod.code_off = struct.unpack(
                fmt_4, self.fd.read(fmt_4))[0]
        else:
            instance_dexmethod = DexMethod()
            instance_dexmethod.method_idx = struct.unpack(
                fmt_4, self.fd.read(fmt_4))[0]
            instance_dexmethod.access_flags = struct.unpack(
                fmt_4, self.fd.read(fmt_4))[0]
            instance_dexmethod.code_off = struct.unpack(
                fmt_4, self.fd.read(fmt_4))[0]
            self.mprint('instance_dexmethod.method_idx',
                        instance_dexmethod.method_idx)
            self.mprint('instance_dexmethod.access_flags',
                        instance_dexmethod.access_flags)
            self.mprint('instance_dexmethod.code_off',
                        instance_dexmethod.method_idx)
            print('--**--' * 20)

        pass

    def read_class_data_item(self, class_data_off):
        '''
        解析出class_data_off的数据值
        方法错误：暂时不用
        '''
        self.fd.seek(class_data_off, 0)
        fmt_2 = 'H'
        fmt_4 = 'I'
        #

        # class_data_header
        dex_class_data_header = DexClassDataHeader()  # 所有的数据都是uleb128类型，因此需要读取每一个数据单元
        # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
        dex_class_data_header.static_fileds_size = self.read_uleb128()
        # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
        dex_class_data_header.instance_fileds_size = self.read_uleb128()
        # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
        dex_class_data_header.direct_methods_size = self.read_uleb128()
        # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
        dex_class_data_header.virtual_methods_size = self.read_uleb128()

        self.mprint('dex_class_data_header.static_fileds_size',
                    hex(dex_class_data_header.static_fileds_size))
        self.mprint('dex_class_data_header.instance_fileds_size',
                    hex(dex_class_data_header.instance_fileds_size))
        self.mprint('dex_class_data_header.direct_methods_size',
                    hex(dex_class_data_header.direct_methods_size))
        self.mprint('dex_class_data_header.virtual_methods_size',
                    hex(dex_class_data_header.virtual_methods_size))

        print('=-=' * 25)
        if dex_class_data_header.static_fileds_size != 0x0:
            for count in dex_class_data_header.static_fileds_size:
                static_dexfield = DexField()
                # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
                static_dexfield.field_idx = self.read_uleb128()
                # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
                static_dexfield.access_flags = self.read_uleb128()
        else:  # ==0

            static_dexfield = DexField()
            # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
            static_dexfield.field_idx = self.read_uleb128()
            # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
            static_dexfield.access_flags = self.read_uleb128()
        count = 0
        if dex_class_data_header.instance_fileds_size != 0x0:  # == 0 的情况
            while count < dex_class_data_header.instance_fileds_size:
                instance_dexfield = DexField()
                # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
                instance_dexfield.field_idx = self.read_uleb128()
                # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
                instance_dexfield.access_flags = self.read_uleb128()
                count += 1
        else:
            instance_dexfield = DexField()
            # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
            instance_dexfield.field_idx = self.read_uleb128()
            # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
            instance_dexfield.access_flags = self.read_uleb128()
        print('**--**' * 20)
        count = 0
        if dex_class_data_header.direct_methods_size != 0x0:
            print('--------direct method size >0')
            while count < dex_class_data_header.direct_methods_size:
                direct_dexmethod = DexMethod()
                # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
                direct_dexmethod.method_idx = self.read_uleb128()
                # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
                direct_dexmethod.access_flags = self.read_uleb128()
                # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
                direct_dexmethod.code_off = self.read_uleb128()
                self.mprint('direct_dexmethod.method_idx',
                            hex(direct_dexmethod.method_idx))
                self.mprint('direct_dexmethod.access_flags',
                            hex(direct_dexmethod.access_flags))
                self.mprint('direct_dexmethod.code_off',
                            hex(direct_dexmethod.method_idx))
                count += 1
                print('++**++' * 20)
        else:  # ==0
            print('--------direct method size ==0')
            direct_dexmethod = DexMethod()
            # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
            direct_dexmethod.method_idx = self.read_uleb128()
            # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
            direct_dexmethod.access_flags = self.read_uleb128()
            # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
            direct_dexmethod.code_off = self.read_uleb128()
            self.mprint('direct_dexmethod.method_idx',
                        hex(direct_dexmethod.method_idx))
            self.mprint('direct_dexmethod.access_flags',
                        hex(direct_dexmethod.access_flags))
            self.mprint('direct_dexmethod.code_off',
                        hex(direct_dexmethod.method_idx))
            print('++**++' * 20)
        count = 0
        if dex_class_data_header.virtual_methods_size != 0x0:
            print('--------virtual method size >0')
            while count < dex_class_data_header.virtual_methods_size:
                virtual_dexmethod = DexMethod()
                # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
                virtual_dexmethod.method_idx = self.read_uleb128()
                # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
                virtual_dexmethod.access_flags = self.read_uleb128()
                # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
                virtual_dexmethod.code_off = self.read_uleb128()
                self.mprint('virtual_dexmethod.method_idx',
                            hex(virtual_dexmethod.method_idx))
                self.mprint('virtual_dexmethod.access_flags',
                            hex(virtual_dexmethod.access_flags))
                self.mprint('virtual_dexmethod.code_off',
                            hex(virtual_dexmethod.method_idx))
                count += 1
                print('--**--' * 20)
        else:
            print('--------virtual method size ==0')
            virtual_dexmethod = DexMethod()
            # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
            virtual_dexmethod.method_idx = self.read_uleb128()
            # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
            virtual_dexmethod.access_flags = self.read_uleb128()
            # struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
            virtual_dexmethod.code_off = self.read_uleb128()
            self.mprint('virtual_dexmethod.method_idx',
                        hex(virtual_dexmethod.method_idx))
            self.mprint('virtual_dexmethod.access_flags',
                        hex(virtual_dexmethod.access_flags))
            self.mprint('virtual_dexmethod.code_off',
                        hex(virtual_dexmethod.method_idx))
            # print('--**--' * 20)

#         class_data_header_off = struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
#         self.mprint('class_data_header_off', hex(class_data_header_off))
#         self.read_dex_class_data_header(class_data_header_off)
#
#         static_field_idx =struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
#         self.read_dex_field(static_field_idx, is_static=True)
#
#         instance_field_idx =struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
#         self.read_dex_field(instance_field_idx, is_static=False)
#
#         direct_method_idx =struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
#         self.read_dex_method(direct_method_idx, is_direct=True)
#
#         virtual_method_idx =struct.unpack(fmt_4,self.fd.read(struct.calcsize(fmt_4)))[0]
#         self.read_dex_method(direct_method_idx, is_direct=False)

        pass

    def close_dexreader(self):
        '''
        关闭流
        '''
        if self.fd != None:
            self.fd.close()

#####

def print_code_off(code_off_list):
    '''
    打印指令放法指令
    首先读取方法指令的长度:insns_size 方法指令集是两个字节一组ushort类型
    其次读取指令集：insns[0],
    外部测试用
    '''
    # dex = sys.path[0] + os.sep + "MyHide.dex"
    with open(TEST_DEXFILE, 'rb') as fd:
        for code_off in code_off_list:

            fd.seek(code_off, 0)
            fmt_4 = 'I'
            fmt_2 = 'H'
            method_register_size = struct.unpack(fmt_2, fd.read(2))[0]
            metdhod_ins_size = struct.unpack(fmt_2, fd.read(2))[0]
            method_outs_size = struct.unpack(fmt_2, fd.read(2))[0]
            method_tries_size = struct.unpack(fmt_2, fd.read(2))[0]
            method_debug_info_off = struct.unpack(
                fmt_4, fd.read(4))[0]  # debug信息
            method_insns_size = struct.unpack(fmt_4, fd.read(4))[0]  # 方法指令长度
            print('***' * 20)
            print('code off', hex(code_off))
            print('insns_code_size', hex(method_insns_size))
            tmp_ins=[]
            while method_insns_size > 0:
                insns_code = struct.unpack(fmt_2, fd.read(2))[0]  # 方法指令
                print('insns_code', hex(insns_code))
                tmp_ins.append(insns_code)
                method_insns_size -= 1
            print('code min:',min(method_insns_size*2,4))


def modified_dec_code_ins(codeoff, fd=None):
    """
    修该指令：codeoff指令地址位置，通过修改对应的指令地址的指令
    fd:打开的dex文件的流对象
    不能使用wb的模式，只能通过rb的模式
    """
    test_dexfile = TEST_DEXFILE
    with open(test_dexfile, 'rb') as fp:
        fp.seek(codeoff)
        fmt_4 = 'I'
        fmt_2 = 'H'
        method_register_size = struct.unpack(fmt_2, fd.read(2))[0]
        metdhod_ins_size = struct.unpack(fmt_2, fd.read(2))[0]
        method_outs_size = struct.unpack(fmt_2, fd.read(2))[0]
        method_tries_size = struct.unpack(fmt_2, fd.read(2))[0]
        method_debug_info_off = struct.unpack(
            fmt_4, fd.read(4))[0]  # debug信息
        method_insns_size = struct.unpack(fmt_4, fd.read(4))[0]  # 方法指令长度
        # 根据size


def fix_dex_header(dexfile):
    """
    重新计算修改过的dex文件：
    checksum:
    sha-1:
    """

    pass


def main():

    start_time = time.time()
    dexheader = DexHeader()
    dexheader.parse_dexheader()
    dexheader.read_string_idx_datas()
    dexheader.read_type_idx_datas()
    dexheader.read_proto_idx_datas()
    dexheader.read_field_idx_datas()
    dexheader.read_method_idx_datas()
    dexheader.read_class_defs()
    # 这里方法读取
    # dexheader.read_class_defs_idx_data()
    strings_data = dexheader.get_strings_data()

    dexheader.close_dexreader()
    print('cost time:', time.time() - start_time)

    # print('**' * 20)
    # for string_item in strings_data:
    #     print(string_item)

    # print('===' * 20)
    # method_code_off = dexheader.get_method_code_off_list()
    method_code_off = [228]#dexheader.get_method_code_off_list()
    print('insns_code :')
    print(method_code_off)
    print_code_off(method_code_off)

    # 关闭资源

if __name__ == '__main__':
    main()
