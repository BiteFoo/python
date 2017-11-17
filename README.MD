#version 1.0

#2017-11-17
解析dex文件脚本。
当前进度：
完成了dexheader部分的解析，需要对所有的数据段进行解析分解
未完成：
关于uleb128的读取，因为string_item_data的size是采用的uleb128格式编码，需要解析出来。
脚本采用的文件在dexparse中，对于每个字段的读取，可以使用010模板来分析，然后完成代码的编写
添加：
添加下载ARM7-TDMI-manual脚本



