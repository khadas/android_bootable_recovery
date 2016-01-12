#ifndef _SECURITY_H_
#define _SECURITY_H_

#define DTB_IMG               "dtb.img"

typedef struct Dtb_Partition_s
{
    char partition_name[16];
    unsigned int  partition_size;
}Dtb_Partition_S;


#endif