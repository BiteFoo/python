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
        codeitems:要提取的指令地址集合 codeoff code size
        根据codeoff 读取到指令地址，根据size，读取到指令长度

        """
        self.buff = buff
        self.codeitems = codeitems
        self.code_fmt = [
            ('registers_size', 'H'),
            ('ins_size', 'H'),
            ('outs_size', 'H'),
            ('tries_size', 'H'),
            ('debug_info_off', 'I'),
            ('insns_size', 'I')
        ]

        # 准备一   个字典
        # self.opcodes={}
        # print(self.buff)

    def extract_opcode(self, save):
        """
        提取指令
        save:要保存指令的文件
        registers_size:H
        ins_size:H
        outs_size:H
        tries_size:H
        debug_info_off:I
        insns_size:H
        insns_arr[]:H

        存储文件内容：codeoff1 codesize1 insns1[0],...,codeoff2,codesize2,insns2[0],...,

        """

        with open(save, 'ab+') as fp:
            for codeitem in self.codeitems:
                print('codeitem:', codeitem)
                # 计算真实指令的地址，否则读取到的地址位置不正确
                ins_offset = codeitem[0] + \
                    struct.calcsize(
                        ''.join(map(lambda x: x[1], self.code_fmt)))
                print('ins_codeitem:', ins_offset)

                insns_size = codeitem[1]
                if insns_size <=1:

                    """
                    指令长度小于或等于1的，不做处理
                    """
                    continue
                insns = struct.unpack_from(
                    'B' * 2 * insns_size, self.buff, ins_offset)
                print('insns', insns)
                # 首先记录下指令地址,这里不是codeoff的地址，是直接指向的指令地址，
                """
                例如codeoff:0x110是指向了codeItem,要获取指令，需要通过当前
                insns_code_off=codeoff+registers_size+ins_size+outs_size+tries_size+debug_info_off+insns_size
                假设
                registers_size:=2
                ins_size=2
                outs_size=2
                tries_size=2
                debug_info_off=4
                insns_size=4
                也就是insns_code_off=0x110+2+2+2+2+4+4得到指令的地址，
                后续根据长度获取指令并保存
                注意，这里计算要通过struct模块的calcsize计算总和
                """
                save_code_insns_off = struct.pack('I', ins_offset)
                fp.write(save_code_insns_off)
                # 记录下指令长度
                save_code_insns_size = struct.pack('I', insns_size)
                fp.write(save_code_insns_size)
                # 记录下真实指令
                for i in insns:
                    # 保存指令
                    code = struct.pack('B', i)
                    fp.write(code)
        print('extract opcodes done !!')
        pass

    def fill_empty_code(self, zero_code=0):
        """
        填充00指令
        zero_code:填充的零字节，两个字节长度

        """

        for codeitem in self.codeitems:
            print('fill_empty_code off:',codeitem)
            ins_offset = codeitem[0] + \
                    struct.calcsize(
                        ''.join(map(lambda x: x[1], self.code_fmt)))
            insns_size = codeitem[1]

            if insns_size<=1:
                """
                指令长度为1，不需要处理
                """
                continue
            # ins=[code for code in ]
            ins=[]
            # ins[0]=14
            # ins.append(struct.pack('B'*2,14,0))
            ins.append(14)

            for i in range(1,insns_size*2):
                # ins[i]=0
                # _tmp=struct.pack('B'*2,0,0)
                # ins.append(_tmp)
                _tmp=0
                ins.append(_tmp)
            print(ins)
            print('=='*10)
            struct.pack_into('B'*2*insns_size,self.buff,ins_offset,*ins)
            print('modified code done')

        # self.save_mofidied_dexfile()
        pass
