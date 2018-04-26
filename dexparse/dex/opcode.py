# -*-coding:utf-8 -*-

"""
指令操作部分
1、抽取指令
2、填充指令

常见指令表示：
human:          ins
1a:             1a00
10a:            0a01
10a0:           a010
1a00:           001a

"""

import struct



class Opcodes(object):

    def __init__(self, buff, codeitems):
        """
        buff:打开的dex文件流,使用arra.array('B',open(dexfile,'rb').read())生成数据流，通过这里修改内容
        codeitems:要提取的指令地址集合
        """
        self.buff=buff
        self.codeitems=codeitems

    def extract_opcode(self, save):
        """
        提取指令
        save:要保存的文件

        """
        pass

    def fill_empty_code(self, zero_code=0x0000):
        """
        填充00指令
        zero_code:填充的零字节，两个字节长度
        """
        pass
