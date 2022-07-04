/*
 * Copyright (c) 2014 Amlogic, Inc. All rights reserved.
 *
 * This source code is subject to the terms and conditions defined in the
 * file 'LICENSE' which is part of this source code package.
 *
 * Description: C++ file
 */

#define LOG_TAG "SystemControl"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <zlib.h>

#ifdef MTD_OLD
# include <linux/mtd/mtd.h>
#else
# define  __user	/* nothing */
# include <mtd/mtd-user.h>
#endif

#include "Ubootenv.h"
//#include "common.h"

unsigned int crc32(unsigned int crc, const unsigned char *ptr, int buf_len) {
    static const unsigned int s_crc32[16] = {
        0, 0x1db71064, 0x3b6e20c8, 0x26d930ac, 0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
        0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c, 0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c };

    unsigned int crcu32 = crc;
    unsigned char b;

    if (buf_len <= 0) {
        return 0;
    }

    if (!ptr) {
        return 0;
    }

    crcu32 = ~crcu32;
    while (buf_len--) {
        b = *ptr++;
        crcu32 = (crcu32 >> 4) ^ s_crc32[(crcu32 & 0xF) ^ (b & 0xF)];
        crcu32 = (crcu32 >> 4) ^ s_crc32[(crcu32 & 0xF) ^ (b >> 4)];
    }

    return ~crcu32;
}


const char *PROFIX_UBOOTENV_VAR = "ubootenv.var.";

Ubootenv::Ubootenv() :
    mEnvLock(PTHREAD_MUTEX_INITIALIZER) {

    init();

    //printValues();
}

Ubootenv::~Ubootenv() {
    if (mEnvData.image) {
        free(mEnvData.image);
        mEnvData.image = NULL;
        mEnvData.crc = NULL;
        mEnvData.data = NULL;
    }
    env_attribute * pAttr = mEnvAttrHeader.next;
    memset(&mEnvAttrHeader, 0, sizeof(env_attribute));
    env_attribute * pTmp = NULL;
    while (pAttr) {
        pTmp = pAttr;
        pAttr = pAttr->next;
        free(pTmp);
    }
}

int Ubootenv::updateValue(const char* name, const char* value) {
    if (!mEnvInitDone) {
        printf("[ubootenv] bootenv do not init\n");
        return -1;
    }

    printf("[ubootenv] update value name [%s]: value [%s] \n", name, value);
    const char* envName = NULL;
    if (strcmp(name, "ubootenv.var.bootcmd") == 0) {
        envName = "bootcmd";
    }
    else {
        if (!isEnv(name)) {
            //should assert here.
            printf("[ubootenv] %s is not a ubootenv variable.\n", name);
            return -2;
        }
        envName = name + strlen(PROFIX_UBOOTENV_VAR);
    }

    const char *envValue = get(envName);
    if (!envValue)
        envValue = "";

    if (!strcmp(value, envValue))
        return 0;

    pthread_mutex_lock(&mEnvLock);
    set(envName, value, true);

    int i = 0;
    int ret = -1;
    while (i < MAX_UBOOT_RWRETRY && ret < 0) {
        i ++;
        ret = save();
        if (ret < 0)
            printf("[ubootenv] Cannot write %s: %d.\n", mEnvPartitionName, ret);
    }

    if (i < MAX_UBOOT_RWRETRY) {
        printf("[ubootenv] Save ubootenv to %s succeed!\n", mEnvPartitionName);
    }

    pthread_mutex_unlock(&mEnvLock);

    return ret;
}

const char * Ubootenv::getValue(const char * key) {
    if (!isEnv(key)) {
        //should assert here.
        printf("[ubootenv] %s is not a ubootenv varible.\n", key);
        return NULL;
    }

    pthread_mutex_lock(&mEnvLock);
    const char* envName = key + strlen(PROFIX_UBOOTENV_VAR);
    const char* envValue = get(envName);
    pthread_mutex_unlock(&mEnvLock);
    return envValue;
}

void Ubootenv::printValues() {
    env_attribute *attr = &mEnvAttrHeader;
    while (attr != NULL) {
        printf("[ubootenv] key: [%s], value: [%s]\n", attr->key, attr->value);
        attr = attr->next;
    }
}

void Ubootenv::dump(int fd) {
    env_attribute *attr = &mEnvAttrHeader;
    while (attr != NULL) {
        dprintf(fd, "[ubootenv] key: [%s], value: [%s]\n", attr->key, attr->value);
        attr = attr->next;
    }
}

int Ubootenv::reInit() {
   pthread_mutex_lock(&mEnvLock);

   if (mEnvData.image) {
       free(mEnvData.image);
       mEnvData.image = NULL;
       mEnvData.crc = NULL;
       mEnvData.data = NULL;
   }
   env_attribute * pAttr = mEnvAttrHeader.next;
   memset(&mEnvAttrHeader, 0, sizeof(env_attribute));
   env_attribute * pTmp = NULL;
   while (pAttr) {
       pTmp = pAttr;
       pAttr = pAttr->next;
       free(pTmp);
   }
   init();

   pthread_mutex_unlock(&mEnvLock);
   return 0;
}

int Ubootenv::init() {
    const char *NAND_ENV = "/dev/nand_env";
    const char *BLOCK_ENV = "/dev/block/env";//normally use that
    const char *BLOCK_UBOOT_ENV = "/dev/block/ubootenv";
    struct stat st;

    //the nand env or block env is the same
    mEnvPartitionSize = CONFIG_ENV_SIZE;
//#if defined(MESON8_ENVSIZE) || defined(GXBABY_ENVSIZE) || defined(GXTVBB_ENVSIZE) || defined(GXL_ENVSIZE)
//    mEnvPartitionSize = 0x10000;
//#endif
    mEnvSize = mEnvPartitionSize - sizeof(uint32_t);

    if (!stat(NAND_ENV, &st)) {
        strcpy (mEnvPartitionName, NAND_ENV);
    }
    else if (!stat(BLOCK_ENV, &st)) {
        strcpy (mEnvPartitionName, BLOCK_ENV);
    }
    else if (!stat(BLOCK_UBOOT_ENV, &st)) {
        int fd;
        struct mtd_info_user info;

        strcpy (mEnvPartitionName, BLOCK_UBOOT_ENV);
        if ((fd = open(mEnvPartitionName, O_RDWR)) < 0) {
            printf("[ubootenv] open device(%s) error\n", mEnvPartitionName );
            return -2;
        }

        memset(&info, 0, sizeof(info));
        int err = ioctl(fd, MEMGETINFO, &info);
        if (err < 0) {
            printf("[ubootenv] get MTD info error\n" );
            close(fd);
            return -3;
        }
        close(fd);

        //mEnvEraseSize = info.erasesize;//0x20000;//128K
        mEnvPartitionSize = info.size;//0x8000;
        mEnvSize = mEnvPartitionSize - sizeof(long);
    }

    //the first four bytes are crc value, others are data
    printf("[ubootenv] using %s with size(%d) (%d)", mEnvPartitionName, mEnvPartitionSize, mEnvSize);

    int i = 0;
    int ret = -1;
    while (i < MAX_UBOOT_RWRETRY && ret < 0) {
        i ++;
        ret = readPartitionData();
        if (ret < 0)
            printf("[ubootenv] Cannot read %s: %d.\n", mEnvPartitionName, ret);
        if (ret < -2)
            free(mEnvData.image);
    }

    if (i >= MAX_UBOOT_RWRETRY) {
        printf("[ubootenv] read %s failed \n", mEnvPartitionName);
        return -2;
    }

#if 0
    char prefix[PROP_VALUE_MAX] = {0};
    property_get("ro.ubootenv.varible.prefix", prefix, "");
    if (prefix[0] == 0) {
        strcpy(prefix , "ubootenv.var");
        printf("[ubootenv] set property ro.ubootenv.varible.prefix: %s\n", prefix);
        property_set("ro.ubootenv.varible.prefix", prefix);
    }

    if (strlen(prefix) > 16) {
        printf("[ubootenv] Cannot r/w ubootenv varibles - prefix length > 16.\n");
        return -4;
    }

    sprintf(PROFIX_UBOOTENV_VAR, "%s.", prefix);
    printf("[ubootenv] ubootenv varible prefix is: %s\n", prefix);
#endif

    propertyLoad();
    return 0;
}

int Ubootenv::readPartitionData() {
    int fd;
    int flag = 0;
    if ((fd = open(mEnvPartitionName, O_RDONLY)) < 0) {
        printf("[ubootenv] open devices error: %s\n", strerror(errno));
        return -1;
    }

    char *addr = (char *)malloc(mEnvPartitionSize);
    if (addr == NULL) {
        printf("[ubootenv] Not enough memory for environment (%u bytes)\n", mEnvPartitionSize);
        close(fd);
        return -2;
    }

    memset(addr, 0, mEnvPartitionSize);
    mEnvData.image = addr;
    struct env_image *image = (struct env_image *)addr;
    mEnvData.crc = &(image->crc);
    mEnvData.data = image->data;

    int ret = read(fd ,mEnvData.image, mEnvPartitionSize);
    if (ret == (int)mEnvPartitionSize) {
        uint32_t crcCalc = crc32(0, (uint8_t *)mEnvData.data, mEnvSize);
        if (crcCalc != *(mEnvData.crc)) {
            printf("[ubootenv] CRC Check printf save_crc=%08x, crcCalc = %08x \n",
                *mEnvData.crc, crcCalc);
            flag = -3;
        }
        //parseAttribute();
        //printValues();
    } else {
        printf("[ubootenv] read error 0x%x \n",ret);
        flag = -5;
    }

    if (flag != 0) {
        printf("first env error, try second....\n");
        ret = lseek(fd, CONFIG_ENV_OFFSET_REDUND, SEEK_SET);
        if (ret < 0) {
            printf("%s() %d: ret is %d\n", __func__, __LINE__, ret);
            close(fd);
            return -4;
        }
        int ret2 = read(fd ,mEnvData.image, CONFIG_ENV_OFFSET_REDUND);
        if (ret2 == (int)mEnvPartitionSize) {
            uint32_t crcCalc = crc32(0, (uint8_t *)mEnvData.data, mEnvSize);
            if (crcCalc != *(mEnvData.crc)) {
                printf("[ubootenv] CRC2 Check printf save_crc=%08x, crcCalc = %08x \n",
                    *mEnvData.crc, crcCalc);
                close(fd);
                return -3;
            }
        }
    }

    parseAttribute();

    close(fd);
    return 0;
}

/* Parse a session attribute */
env_attribute* Ubootenv::parseAttribute() {
    char *proc = mEnvData.data;
    char *nextProc;
    env_attribute *attr = &mEnvAttrHeader;

    memset(attr, 0, sizeof(env_attribute));

    do {
        nextProc = proc + strlen(proc) + sizeof(char);
        //SYS_LOGV("process %s\n",proc);
        char *key = strchr(proc, (int)'=');
        if (key != NULL) {
            *key=0;
            strcpy(attr->key, proc);
            strncpy(attr->value, key + sizeof(char), sizeof(attr->value));
            attr->value[sizeof(attr->value) - 1] = '\0';
        } else {
            printf("[ubootenv] error need '=' skip this value\n");
        }

        if (!(*nextProc)) {
            //SYS_LOGV("process end \n");
            break;
        }
        proc = nextProc;

        attr->next = (env_attribute *)malloc(sizeof(env_attribute));
        if (attr->next == NULL) {
            printf("[ubootenv] parse attribute malloc error \n");
            break;
        }
        memset(attr->next, 0, sizeof(env_attribute));
        attr = attr->next;
    }while(1);

    return &mEnvAttrHeader;
}

char * Ubootenv::get(const char * key) {
    if (!mEnvInitDone) {
        printf("[ubootenv] don't init done\n");
        return NULL;
    }

    env_attribute *attr = &mEnvAttrHeader;
    while (attr) {
        if (!strcmp(key, attr->key)) {
            return attr->value;
        }
        attr = attr->next;
    }
    return NULL;
}

/*
creat_args_flag : if true , if envvalue don't exists Creat it .
              if false , if envvalue don't exists just exit .
*/
int Ubootenv::set(const char * key,  const char * value, bool createNew) {
    env_attribute *attr = &mEnvAttrHeader;
    env_attribute *last = attr;
    while (attr) {
        if (!strcmp(key, attr->key)) {
            strncpy(attr->value, value, sizeof(attr->value));
            attr->value[sizeof(attr->value) - 1] = '\0';
            return 2;
        }
        last = attr;
        attr = attr->next;
    }

    if (createNew) {
        printf("[ubootenv] ubootenv.var.%s not found, create it.\n", key);

        attr = (env_attribute *)malloc(sizeof(env_attribute));
        last->next = attr;
        memset(attr, 0, sizeof(env_attribute));
        strncpy(attr->key, key, sizeof(attr->key));
        attr->key[sizeof(attr->key) - 1] = '\0';
        strncpy(attr->value, value, sizeof(attr->value));
        attr->value[sizeof(attr->value) - 1] = '\0';
        return 1;
    }
    return 0;
}

//save value to storage flash
int Ubootenv::save() {
    int fd;
    int err;

    formatAttribute();
    *(mEnvData.crc) = crc32(0, (uint8_t *)mEnvData.data, mEnvSize);

    if ((fd = open (mEnvPartitionName, O_RDWR)) < 0) {
        printf("[ubootenv] open devices error\n");
        return -1;
    }

    if (strstr (mEnvPartitionName, "mtd")) {
        struct erase_info_user erase;
        struct mtd_info_user info;
        unsigned char *data = NULL;

        memset(&info, 0, sizeof(info));
        err = ioctl(fd, MEMGETINFO, &info);
        if (err < 0) {
            printf("[ubootenv] Get MTD info error\n");
            close(fd);
            return -4;
        }

        erase.start = 0;
        if (info.erasesize > ((unsigned int)mEnvPartitionSize * 2)) {
            data = (unsigned char*)malloc(info.erasesize);
            if (data == NULL) {
                printf("[ubootenv] Out of memory!!!\n");
                close(fd);
                return -5;
            }
            memset(data, 0, info.erasesize);
            err = read(fd, (void*)data, info.erasesize);
            if (err != (int)info.erasesize) {
                printf("[ubootenv] Read access failed !!!\n");
                free(data);
                close(fd);
                return -6;
            }
            memcpy(data, mEnvData.image, mEnvPartitionSize);
            memcpy(data + CONFIG_ENV_OFFSET_REDUND, mEnvData.image, mEnvPartitionSize);
            erase.length = info.erasesize;
        }
        else {
            erase.length = mEnvPartitionSize * 2;
        }

        err = ioctl (fd, MEMERASE,&erase);
        if (err < 0) {
            printf ("[ubootenv] MEMERASE printf %d\n",err);
            free(data);
            close(fd);
            return  -2;
        }

        if (info.erasesize > (unsigned int)mEnvPartitionSize) {
            err = lseek(fd, 0L, SEEK_SET);
            if (err < 0) {
                printf("%s() %d: err is %d\n", __func__, __LINE__, err);
                free(data);
                close(fd);
                return -7;
            }
            if (data != NULL)
                err = write(fd , data, info.erasesize);
            else
                printf("data is NULL\n");
            free(data);
        }
        else {
            err = write(fd ,mEnvData.image, mEnvPartitionSize);
            err = lseek(fd, CONFIG_ENV_OFFSET_REDUND, SEEK_SET);
            if (err < 0) {
                printf("%s() %d: err is %d\n", __func__, __LINE__, err);
                free(data);
                close(fd);
                return -8;
            }
            err = write(fd ,mEnvData.image, mEnvPartitionSize);
            free(data);
        }

    } else {
        //emmc and nand needn't erase
        lseek(fd, 0L, SEEK_SET);
        err = write(fd, mEnvData.image, mEnvPartitionSize);
        err = lseek(fd, CONFIG_ENV_OFFSET_REDUND, SEEK_SET);
        if (err < 0) {
            printf("%s() %d: err is %d\n", __func__, __LINE__, err);
            close(fd);
            return -9;
        }
        err = write(fd ,mEnvData.image, mEnvPartitionSize);
    }

    close(fd);
    if (err < 0) {
        printf ("[ubootenv] printf write, size %d \n", mEnvPartitionSize);
        return -3;
    }
    return 0;
}

/*  attribute revert to sava data*/
int Ubootenv::formatAttribute() {
    env_attribute *attr = &mEnvAttrHeader;
    char *data = mEnvData.data;
    memset(mEnvData.data, 0, mEnvSize);
    do {
        int len = sprintf(data, "%s=%s", attr->key, attr->value);
        if (len < (int)(sizeof(char)*3)) {
            printf("[ubootenv] Invalid env data key:%s, value:%s\n", attr->key, attr->value);
        }
        else
            data += len + sizeof(char);

        attr = attr->next;
    } while (attr);
    return 0;
}

int Ubootenv::isEnv(const char* prop_name) {
    if (!prop_name || !(*prop_name))
        return 0;

    if (!(*PROFIX_UBOOTENV_VAR))
        return 0;

    if (strncmp(prop_name, PROFIX_UBOOTENV_VAR, strlen(PROFIX_UBOOTENV_VAR)) == 0
        && strlen(prop_name) > strlen(PROFIX_UBOOTENV_VAR) )
        return 1;

    return 0;
}

#if 0
void Ubootenv::propertyTrampoline(void* raw_data, const char* name, const char* value, unsigned serial) {
    struct callback_data* data = (struct callback_data*)(raw_data);
    data->callback(name, value, data->cookie);
}

void Ubootenv::propertyListCallback(const prop_info* pi, void* data) {
    __system_property_read_callback(pi, propertyTrampoline, data);
}

void Ubootenv::propertyInit(const char *key, const char *value, void *cookie) {
    if (isEnv(key)) {
        const char* varible_name = key + strlen(PROFIX_UBOOTENV_VAR);
        const char *varible_value = get(varible_name);
        if (!varible_value)
            varible_value = "";
        if (strcmp(varible_value, value)) {
            property_set(key, varible_value);
            printf("[ubootenv] bootenv_prop_init set property key:%s value:%s\n", key, varible_value);
            (*((int*)cookie))++;
        }
    }
}

int Ubootenv::propertyList(void (*propfn)(const char *key, const char *value, void *cookie), void *cookie) {
    if (true/*bionic_get_application_target_sdk_version() >= __ANDROID_API_O__*/) {
        struct callback_data data = { propfn, cookie };
        return __system_property_foreach(propertyListCallback, &data);
    }

    char name[PROP_NAME_MAX];
    char value[PROP_VALUE_MAX];
    const prop_info *pi;
    unsigned n;

    for (n = 0; (pi = __system_property_find_nth(n)); n++) {
        __system_property_read(pi, name, value);
        propfn(name, value, cookie);
    }
    return 0;
}
#endif

void Ubootenv::propertyLoad() {
    int count = 0;

    //propertyList(propertyInit, (void*)&count);

    printf("[ubootenv] set property count: %d\n", count);
    mEnvInitDone = true;
}
