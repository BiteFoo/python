#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "sha.h"



void readDexFile(const char* src,const char* dst);
void rewriteDexFile(FILE* out,void *off,size_t size,void* data);
void fixDexFileHeader(const char* dexfile);
int fixCheckSum();
int fixSignature();


int main(int argc,const char* argv[])

{

	if (argc ==3){
	const char* srcfile=argv[1];
	const char* dstfile=argv[2];
	printf("src:%s , dst:%s\n",srcfile,dstfile);
	readDexFile(srcfile,dstfile);
	
	}
	
	printf("finish\n");
	return 0;
}

/**
 *
 *修复dex头部的signature信息
 *
 * **/
int fixSignature(const char* dexfile){
	

	
	return 0;
}


/**
 *
 *读取指令数据

 * **/
void readDexFile(const char* src,const char* dst){
	
	
	FILE *in;
	FILE *out;
	in=fopen(src,"rb");
	out=fopen(dst,"rb+");
	if(in == NULL || out==NULL){
		printf("file \"%s\" or \"%s\" was not exists\n",src,dst);
		return ;
	}
	printf("rewriteDexFile ....\n");
	
	unsigned int* codeOff=(unsigned int*) malloc(sizeof(unsigned int));
	unsigned int* codeSize=(unsigned  int*)malloc(sizeof(unsigned int));
	unsigned short* insns=(unsigned short*)malloc(sizeof(unsigned short));
        long offset=0;
	int buffSize=sizeof(unsigned char)*4;//缓冲区
	int flag=1;//用来读取指令地址和指令长度的第一次标记，
	//调整文件指针到底部，
	fseek(in,0L,SEEK_END);
	int fsize=ftell(in);
	printf("fsize:%d\n",fsize);
	printf("*********************\n");
	//调整文件指针回到头部，
	rewind(in);
	if(codeOff == NULL || codeSize == NULL || insns == NULL){
	
		printf("malloc memorise failed \n");
	
}
	//读取第一个数据4个字节，
	//feof 正常读取，返回0，读取结束返回1
	//
	fread(codeOff,buffSize,1,in);
	while(!feof(in)){
		
		if(flag!=1){
		//这里是第二次读取了指令地址
		fread(codeOff,buffSize,1,in);
		}
		//添加判断，是都读取到了尾部，只有在fread方法调用后，feof才会更新状态值
		if(feof(in))
		{
			printf("read bin datas finished\n");
	        	break;
		}
		printf("codeOff:0x%08x\n",*codeOff);
		fread(codeSize,buffSize,1,in);
		printf("codeSize:0x%08x\n",*codeSize);
		printf("insns:\n");
		for(int i= 0;i<*codeSize;i++){
			//读取指令数据
			//
			offset=(long)(*codeOff+sizeof(unsigned short)*i);
			fread(insns,sizeof(unsigned short),1,in);
			printf("insns[%d]:0x%04x,offset:0x%08x ,offset:0x%08x\n",i,*insns,offset);
			//重写dexfile，填写指令
			//
			fseek(out,offset,SEEK_SET);
			fwrite(insns,sizeof(unsigned char),sizeof(unsigned short),out);
                      // rewriteDexFile(out,&offset,sizeof(unsigned short),insns);		       		
		}
		printf("--------------\n");
	      flag++;
	}

	printf("total modified insns:%d\n",flag-1);	
	
	fclose(in);
	fclose(out);
	//
	free(codeOff);
	free(codeSize);
	free(insns);

}
/**
 *重写指令到dexfile内
 *
 * **/
/**
void rewriteDexFile(FILE* out,void* offset,size_t size,void* data)
{

	if(out == NULL){
		printf("rewriteDexFile  failed \n");
		return ;
	}
	printf("rewriteDexFile offset:0x%08x\n",*(long*)offset);
	fseek(out,*(long*)offset,SEEK_SET);
	fwrite(data,sizeof(unsigned char),size,out);
	
}
*/


