
##流程：

#####1、extract dexcode ins[0] == empty dexfile (done)
注：也要过滤掉不需要的方法，有些方法不能做修改，例如<init>

1.根据dexfile获取到指定的类方法读取指令内容，根据codeoff的地址做指令抽取：
抽取指令也要按照2byte字节，如果不满足两个字节，需要填充保存
codeoff  codesize ins[0] 000000(使用00000000作为结束)
常见指令表示：
human:			ins
1a:				1a00
10a:			0a01
10a0:			a010
1a00:			001a

e.g:
------------------------
directMethod:
method idx: 19
short_class_name： b'Lcom/fortiguard/hideandseek/MrHyde;'
method_name b'<init>'
DexMethodProto,idx: 26
method_proto_name: b'VL'
returnty_value: b'V'
codeoff: 0xd74
insns_code_size: 0xd
insns_code[0]: 0x1070
insns_code[1]: 0x36
insns_code[2]: 0x2
insns_code[3]: 0x1a
insns_code[4]: 0xd
insns_code[5]: 0x11a
insns_code[6]: 0x13
insns_code[7]: 0x2071
insns_code[8]: 0x8
insns_code[9]: 0x10
insns_code[10]: 0x235b
insns_code[11]: 0xa
insns_code[12]: 0xe
----------------------------------------
保存的时候，需要高低位排序正确，小端模式
0 1 2 3   4 5 6 7   8 7 a b 		c d e f 
codeoff  codesize	ins[0]ins[1]   ins[3]ins[4]
0xd74	0000000d 	70103600	   1a000d00

2.抽取指定类的方法指令,需要填充，根据codeoff，如下
通过fd.seek(codeof)，获取到code_size,后续根据code_size，遍历填充0：
指令的长度是两个字节：2byte
ins[0]=0x0e00 对应的smali opcode : return-void 
ins[1]=0x0000
ins[2]=0x0000
ins[3]=0x0000
ins[4]=0x0000
ins[5]=0x0000
ins[6]=0x0000
ins[...]=0x0000


######2、fix empty dexfile (done) fix_dexfile

抽取后的dexfile，其checksum和sha1的值不正确，需要从新计算，
首先计算出sha1的值，写入到dexfile内
然后计算checksum

1、fix signature（也就是通过sha1来计算）
跳过dexheader的magic checksum signature余下的整个sha
2、fix checksum
跳过dexheader的magic和checksum字段，跳过前alder32(dexheader[magic+checksum:])


注：如果不修正更改多的dex文件，那么在使用010Editor打开会出方法和一些错乱值。具体可以查看tmp_modified.dex和tmp/tmp_modified.dex文件
这里使用修正的工具是52上下载的DexFixer.

##2018-05-02功能完成：
dex指令抽取和修改后的dex文件修复
hidex_dex_ins和fix_dex_header 以及save_modified_dex 三个函数完成

######3、memory load fix_dexfile(wating)


######4、testing (waiting)


###记录测试
拼接方法：例如
Lcom/java/lang/String

基本信息：
headerinfos
stringinfos
typeinfos
protoinfos
fieldinfos
methodinfos
classdefinfos

-->classdefinfos-->class_def_item-->class_data-->dexmethod-->codeoff-->dexcode-->ins[0]

输出每个方法的类，方法原型，proto
class
method 
ins[]
class+method+ins[]==>ins[]{000}

--->class+method+ins[]==>ins[]{0000}
{

1x2x3x4
[0]=0xe return-void
[1]=0x0
[2]=0x0

									No
}									|
==>empty_dex--->so_clasLoader-->fix(empty_dex)-->yes
	
	后续操作{mem()-->

	}

#===
opcode-->string 


根据条件读取方法偏移：
com.xxxx.yyy
com.xxxx.yyy.aa.AAA
com.xxxx.yyy.bv.cCCC
主要根据读取的包名，符合条件的，就读取(2018-04-26支持，通过包名过滤出需要的类)



根据方法偏移，指令提取：

注意python写文件的模式，使用wb的方式打开文件，会重新创建文件，应该使用rb的模式


要保存的数据内容：
header_class_def_offset   class_def_item  class_datae_item   codeOff

0x12345678					0xaabbccdd	0xmmhhiijj		uleb128(0x09101015)	--> 读取指令填充
00000000					xxxx0000   	zzzzzzzz			yyyyyyyy		
uuuuuuuu					00000000



根据的得到的codeOff，读取出指令集，保存在另一个文件或者是通过0000 xx xxx xxx xxxx 0000 

00000000	data sections		00000000 