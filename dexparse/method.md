
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
主要根据读取的包名，符合条件的，就读取

根据方法偏移，指令提取：

注意python写文件的模式，使用wb的方式打开文件，会重新创建文件，应该使用rb的模式


要保存的数据内容：
header_class_def_offset   class_def_item  class_datae_item   codeOff

0x12345678					0xaabbccdd	0xmmhhiijj		uleb128(0x09101015)	--> 读取指令填充
00000000					xxxx0000   	zzzzzzzz			yyyyyyyy		
uuuuuuuu					00000000



根据的得到的codeOff，读取出指令集，保存在另一个文件或者是通过0000 xx xxx xxx xxxx 0000 

00000000	data sections		00000000 