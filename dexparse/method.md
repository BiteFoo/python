注意python写文件的模式，使用wb的方式打开文件，会重新创建文件，应该使用rb的模式


要保存的数据内容：
header_class_def_offset   class_def_item  class_datae_item   codeOff

0x12345678					0xaabbccdd	0xmmhhiijj		uleb128(0x09101015)	--> 读取指令填充
00000000					xxxx0000   	zzzzzzzz			yyyyyyyy		
uuuuuuuu					00000000



根据的得到的codeOff，读取出指令集，保存在另一个文件或者是通过0000 xx xxx xxx xxxx 0000 

00000000	data sections		00000000 