# -*- coding:utf-8 -*-


"""
测试二进制文件修改：
读取指定位置修改

"""

import struct

import re

import array 

def write_bin():

    """
    生成二进制文件
    """

    data = [i for i in range(5)]
    fmt='5I'
    bin_data=struct.pack(fmt,*data)
    print(bin_data)
    with open('test.bin','wb') as fp:
        fp.write(bin_data)
    print('write bin ok ')


def modified_bin():

    """
    修改二进制数据：
    读取offset,根据数据格式，填写数据

    """
    # off=0x0008#需要修改的地址位置
    off=228
    # fp = open('test_bal.bin','ab') 

    buff=array.array('B',open('MyHide.dex','rb').read())
    print(type(buff))
    print(buff)
    # fmt='B'*2 #需要修改的数据B unsigned char  'B'*4 =='BBBB'
    # args=[6,7,8,9] #需要修改的数据值，注意，这里只需把原始数据填入，不能是更改的过的数据，不用使用struct.pack(fmt,data)
    # ins=['0xe0','0x00','0x00','0x00']
    ins=[0xe0,0x00,0x00,0x00]
    args=map(ord,ins)
    try:
       ##更改内容，
        struct.pack_into('B'*2*0x4,buff,off,*args)
    except Exception as e:
        raise e
    # fp.close()
    print('modified_bin ok ')
    ##回写数据
    # open('test_bal.bin','wb').write(buff)
    open('modifiedMyHide.dex','wb').write(buff)
    # data=array.array('B',open('test_bal.bin','rb').read())
    # print(type(data))
    # print(data)


def main():

    # write_bin()
    modified_bin()

if __name__ == '__main__':
    main()
