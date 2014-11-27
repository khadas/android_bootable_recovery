#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <malloc.h>
#include <linux/types.h>

#include "common.h"
#include "ui.h"
#include "key.h"

#define DWORD unsigned int
#define BYTE unsigned char
#define SHA1_MAC_LEN 20

typedef struct {
    DWORD state[5];
    DWORD count[2];
    BYTE buffer[64];
} SHA1_CTX;

void SHA1Reset(SHA1_CTX *context);
void SHA1Input(SHA1_CTX *context, BYTE *data, DWORD len);
void SHA1Result(SHA1_CTX *context, BYTE *digest); //20
void SHA1Transform_H(DWORD *state, BYTE *buffer); //5  64

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#define blk0(i) (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) | \
        (rol(block->l[i], 8) & 0x00FF00FF))
#define blk(i) (block->l[i & 15] = rol(block->l[(i + 13) & 15] ^ \
        block->l[(i + 8) & 15] ^ block->l[(i + 2) & 15] ^ block->l[i & 15], 1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) \
        z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); \
        w = rol(w, 30);
#define R1(v,w,x,y,z,i) \
        z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); \
        w = rol(w, 30);
#define R2(v,w,x,y,z,i) \
        z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); w = rol(w, 30);
#define R3(v,w,x,y,z,i) \
        z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); \
        w = rol(w, 30);
#define R4(v,w,x,y,z,i) \
        z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); \
        w=rol(w, 30);

/* Hash a single 512-bit block. This is the core of the algorithm. */
void SHA1Transform_H(DWORD *state, BYTE *buffer)
{
    DWORD a, b, c, d, e;
    typedef union {
        BYTE c[64];
        DWORD l[16];
    } CHAR64LONG16;
    CHAR64LONG16 *block;

    DWORD workspace[16];
    block = (CHAR64LONG16 *)workspace;
    memcpy(block, buffer, 64);

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    /* Wipe variables */
    a = b = c = d = e = 0;
    memset(block, 0, 64);
}

/* SHA1Reset - Initialize new context */
void SHA1Reset(SHA1_CTX *context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

/* Run your data through this. */
void SHA1Input(SHA1_CTX* context, BYTE *_data, DWORD len)
{
    DWORD i, j;
    BYTE *data = _data;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3))
        context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1Transform_H(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) {
            SHA1Transform_H(context->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&context->buffer[j], &data[i], len - i);
}

/* Add padding and return the message digest. */
void SHA1Result(SHA1_CTX *context, BYTE *digest)
{
    DWORD i;
    BYTE finalcount[8];

    for (i = 0; i < 8; i++) {
        /* Endian independent */
        finalcount[i] = (BYTE)
            ((context->count[(i >= 4 ? 0 : 1)] >> ((3-(i & 3)) * 8) ) & 255);
    }
    SHA1Input(context, (BYTE *) "\200", 1);
    while ((context->count[0] & 504) != 448) {
        SHA1Input(context, (BYTE *) "\0", 1);
    }
    /* Should cause a SHA1Transform_H() */
    SHA1Input(context, finalcount, 8);
    for (i = 0; i < 20; i++) {
        digest[i] = (BYTE)
            ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
    /* Wipe variables */
    i = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(finalcount, 0, 8);
}

typedef struct {
    unsigned char ksv[5];
    unsigned char rsv[3];
    unsigned char dpk[280];
    unsigned char sha[20];
} hdcp_llc_file;

/**********************************************************************
* NOTES: Test Vectors (from FIPS PUB 180-1) to verify implementation
* 1- Input : "abc"
*   Output : A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
* 2- Input : "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
*   Output : 84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
* 3- Input : A million repetitions of 'a' - not applied (memory shortage)
*   Output : 34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*   More test vectors can be obtained from FIPS web site
**********************************************************************/
void SHA1_Perform(BYTE *indata, DWORD inlen, BYTE *outdata)
{
    SHA1_CTX sha;
    SHA1Reset(&sha);
    SHA1Input(&sha, indata, inlen);
    SHA1Result(&sha, outdata);
}

static char Hex2Asc(char para)
{
    if (para >= 0 && para <= 9) {
        para = para + '0';
    } else if (para >= 0xa && para <= 0xf) {
        para = para + 'a' - 0xa;
    }

    return para;
}

static char Asc2Hex(char para)
{
    if (para >= '0' && para <= '9') {
        para = para - '0';
    } else if (para >= 'a' && para <= 'f') {
        para = para - 'a' + 0xa;
    } else if (para >= 'A' && para <= 'F') {
        para = para - 'A' + 0xa;
    }

    return para;
}

static int SecukeyInit(const char *path)
{
    int fd = -1;
    size_t size = 0;
    const char *value = "auto3";

    fd = open(path, O_WRONLY);
    if (fd <= 0) {
        ui->Print("open %s failed (%s)\n", path, strerror(errno));
        return -1;
    }
    size = write(fd, value, strlen(value));
    if (size != strlen(value)) {
        ui->Print("write %s failed.len(%d) != %d\n",
            value, size, strlen(value));
    }

    if (fd > 0) {
        close(fd);
        fd = -1;
    }

    return (size == strlen(value)) ? 0 : -1;
}

/**
  *  --- read key from flash
  *  @keyName: mac/mac_bt/mac_wifi/usid/hdcp ...
  *  @keyBuf: save key datas
  *  return: 0->have writen and read ok, 1->haven't write before, -1->read failed
  */
static int FlashReadKey(const char *keyName, char *keyBuf)
{
    int fdName = -1, fdRead = -1, fdList = -1;
    int i = 0, j = 0, rc= -1;
    size_t count = 0, keyMaxLength = 0;
    char keyList[SECUKEY_BYTES] = {'\0', 0};
    char keyData[SECUKEY_BYTES * 2] = {0};
    char keyRead[SECUKEY_BYTES] = {0};
    const char *secukeyNamePath = SECUKEY_NAME;
    const char *secukeyReadPath = SECUKEY_READ;
    const char *secukeyListPath = SECUKEY_LIST;

    if (!strcmp(keyName, keyTitle[MAC_WIFI].name) ||
        !strcmp(keyName, keyTitle[MAC_BT].name) ||
        !strcmp(keyName, keyTitle[MAC].name)) {
        keyMaxLength = MAC_KEY_LEN;
    } else if (!strcmp(keyName, keyTitle[USID].name)) {
        keyMaxLength = USID_KEY_LEN;
    } else if (!strcmp(keyName, keyTitle[HDCP].name)) {
        keyMaxLength = HDCP_KEY_LEN;
    } else {
        ui->Print("error: can't support read %s at present\n", keyName);
        return -1;
    }

    if (keyBuf == NULL) {
        printf("havn't malloc space to save %s\n", keyName);
        return -1;
    }

    printf("read %s,read max length:%d\n", keyName, keyMaxLength);
    fdName = open(secukeyNamePath, O_WRONLY);
    if (fdName <= 0) {
        ui->Print("open %s failed (%s)\n", secukeyNamePath, strerror(errno));
        return -1;
    }

    fdRead = open(secukeyReadPath, O_RDONLY);
    if (fdRead <= 0) {
        ui->Print("open %s failed (%s)\n", secukeyReadPath, strerror(errno));
        goto ERR1;
    }

    fdList = open(secukeyListPath, O_RDONLY);
    if (fdList <= 0) {
        ui->Print("open %s failed (%s)\n", secukeyListPath, strerror(errno));
        goto ERR2;
    }

    count = write(fdName, keyName, strlen(keyName));
    if (count != strlen(keyName)) {
        ui->Print("write name failed,len(%d) != %d\n", count, strlen(keyName));
        goto ERR3;
    }

    count = read(fdRead, keyData, keyMaxLength * 2);
    if (!strstr(keyName, keyTitle[MAC].name) &&
        !strstr(keyName, keyTitle[HDCP].name)) {// such usid,not fixed length
        if (count <= 0) {
            read(fdList, keyList, sizeof(keyList));
            if (!strstr(keyList, keyName)) {
                rc = 1;     // can't find key in list, haven't write before
                goto OUT;
            }
            ui->Print("%s exist in keylist,but read datas failed,len(%d)\n",
                keyName, count);
            goto ERR3;
        }
    } else {                // such as mac,hdcp, fixed length
         if (count != keyMaxLength * 2) {
            read(fdList, keyList, sizeof(keyList));
            if (!strstr(keyList, keyName)) {
                rc = 1;
                goto OUT;
            }
            ui->Print("%s exist in keylist,but read datas failed,len(%d) != %d\n",
                keyName, count, keyMaxLength * 2);
            goto ERR3;
        }
    }

    for (i = 0, j = 0; i < (int)keyMaxLength * 2; i ++, j ++) {
        keyRead[j] = (((Asc2Hex(keyData[i])) << 4) | (Asc2Hex(keyData[i+1])));
        i++;
    }

    memset(keyData, 0, sizeof(keyData));
    if (memcmp(keyRead, keyData, keyMaxLength)) {
        memset(keyBuf, 0, keyMaxLength);
        memcpy(keyBuf, keyRead, keyMaxLength);
        if (!strstr(keyName, keyTitle[HDCP].name)) {
            printf("have writen %s before and read ok(%s)\n", keyName, keyBuf);
        } else {
            printf("have writen %s before and read ok\n", keyName);
        }
        rc = 0;     //have writen before and read ok
    } else {
        rc = 1;     //haven't write before
        printf("havn't write %s before\n", keyName);
    }

OUT:
ERR3:
    if (fdList > 0) {
        close(fdList);
        fdList = -1;
    }

ERR2:
    if (fdRead > 0) {
        close(fdRead);
        fdRead = -1;
    }

ERR1:
    if (fdName > 0) {
        close(fdName);
        fdName = -1;
    }

    return rc;
}

/**
  *  --- write key to flash
  *  @keyName: mac/mac_bt/mac_wifi/usid/hdcp ...
  *  @keyBuf: key datas
  *  return: 0->write success, -1->write failed
  */
static int FlashWriteKey(const char *keyName, char *keyBuf)
{
    int fdName = -1, fdRead = -1, fdWrite = -1;
    int i = 0, j = 0, rc= -1, ret = -1;
    size_t count = 0, keyActualLength = 0;
    char keyRead[SECUKEY_BYTES] = {0};
    char keyWrite[SECUKEY_BYTES * 2] = {0};
    char keyData[SECUKEY_BYTES * 2] = {0};
    const char *secukeyNamePath = SECUKEY_NAME;
    const char *secukeyReadPath = SECUKEY_READ;
    const char *secukeyWritePath = SECUKEY_WRITE;

    if (!strcmp(keyName, keyTitle[MAC_WIFI].name) ||
        !strcmp(keyName, keyTitle[MAC_BT].name) ||
        !strcmp(keyName, keyTitle[MAC].name)) {
        keyActualLength = strlen(keyBuf);
        if (keyActualLength != MAC_KEY_LEN) {
            ui->Print("error: %s length(%d) != %d\n",
                keyName, keyActualLength, MAC_KEY_LEN);
            return -1;
        }
    } else if (!strcmp(keyName, keyTitle[USID].name)) {
        keyActualLength = strlen(keyBuf);
        if (keyActualLength > USID_KEY_LEN) {
            ui->Print("error: %s length(%d) > %d\n",
                keyName, keyActualLength, USID_KEY_LEN);
            return -1;
        }
    } else if (!strcmp(keyName, keyTitle[HDCP].name)) {
        keyActualLength = HDCP_KEY_LEN;
    } else {
        ui->Print("error: can't support read %s at present\n",
            keyName);
        return -1;
    }

    if (keyBuf == NULL) {
        printf("havn't malloc space to save %s\n", keyName);
        return -1;
    }

    printf("write %s,write actual length:%d\n", keyName, keyActualLength);
    fdName = open(secukeyNamePath, O_WRONLY);
    if (fdName <= 0) {
        ui->Print("open %s failed (%s)\n", secukeyNamePath, strerror(errno));
        return -1;
    }

    fdWrite = open(secukeyWritePath, O_WRONLY);
    if (fdWrite <= 0) {
        ui->Print("open %s failed (%s)\n", secukeyWritePath, strerror(errno));
        goto ERR1;
    }

    fdRead = open(secukeyReadPath, O_RDONLY);
    if (fdRead <= 0) {
        ui->Print("open %s failed (%s)\n", secukeyReadPath, strerror(errno));
        goto ERR2;
    }

    count = write(fdName, keyName, strlen(keyName));
    if (count != strlen(keyName)) {
        ui->Print("write name failed,len(%d) != %d\n", count, strlen(keyName));
        goto ERR3;
    }

    for (i = 0, j = 0; i < (int)keyActualLength; i ++, j ++) {
        keyWrite[j] = Hex2Asc((keyBuf[i] >> 4) & 0x0f);
        keyWrite[++j] = Hex2Asc((keyBuf[i]) & 0x0f);
    }

    count = write(fdWrite, keyWrite, keyActualLength * 2);
    if (count != keyActualLength * 2) {
        ui->Print("write datas failed,len(%d) != %d\n", count, keyActualLength * 2);
        goto ERR3;
    }
    sync();

    /* test read key */
    printf("write %s successful,test read...\n", keyName);
    count = read(fdRead, keyData, keyActualLength * 2);
    if (count != keyActualLength * 2) {
        ui->Print("write successful,but test read failed,len(%d) != %d\n",
            count, keyActualLength * 2);
        goto ERR3;
    }

    for (i = 0, j = 0; i < (int)keyActualLength * 2; i ++, j ++) {
        keyRead[j] = (((Asc2Hex(keyData[i])) << 4) | (Asc2Hex(keyData[i+1])));
        i++;
    }

    if (!memcmp(keyRead, keyBuf, keyActualLength)) {
        printf("write successful and test read successful\n");
        rc = 0;
    } else {
        if (!strstr(keyName, keyTitle[HDCP].name)) {
            ui->Print("write successful,but test read(%s) not match write(%s)\n",
                keyRead, keyBuf);
        } else {
            ui->Print("write successful,but test read not match write\n");
        }
        rc = -1;
    }

ERR3:
    if (fdRead > 0) {
        close(fdRead);
        fdRead = -1;
    }

ERR2:
    if (fdWrite > 0) {
        close(fdWrite);
        fdWrite = -1;
    }

ERR1:
    if (fdName > 0) {
        close(fdName);
        fdName = -1;
    }

    return rc;
}

static int s_SecukeyInited = -1;
static int EnsureSecukeyInit(void)
{
    if (!s_SecukeyInited) {
        return 0;
    }

    s_SecukeyInited = SecukeyInit(SECUKEY_VERSION);
    if (s_SecukeyInited < 0) {
        ui->Print("secukey init %s\n", !s_SecukeyInited ? "successful" : "failed");
    } else {
        printf("secukey init %s\n", !s_SecukeyInited ? "successful" : "failed");
    }
    return s_SecukeyInited;
}

static int ExecCmd(const char* path, char* const argv[])
{
    int status;
    pid_t child;
    if ((child = vfork()) == 0) {
        execv(path, argv);
        _exit(-1);
    }
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("%s failed with status %d\n", path, WEXITSTATUS(status));
    }
    return WEXITSTATUS(status);
}

static int BackupFile(const char *srcFilePath)
{
    int result = -1;
    char buf[50] = {0};
    char destDirPath[128] = {0};
    char destFilePath[128] = {0};
    const char *busybox = "/sbin/busybox";

    sscanf(srcFilePath, "/%[^/]", buf);  // eg: get XXX from /XXX/...

    sprintf(destDirPath, "/%s/%s", buf, "bak");
    if (access(destDirPath, F_OK)) {
        const char* const argvMkdir[] = {"mkdir", destDirPath, "-p", NULL};
        result = ExecCmd(busybox, (char* const*)argvMkdir);
    }

    if (!access(destDirPath, F_OK)) {
        char fileName[50] = {0};
        char *tmp = strstr(srcFilePath, buf) + strlen(buf) + 1;
        strcpy(fileName, tmp);
        sprintf(destFilePath, "%s/%s%s", destDirPath, fileName, ".bak");
        const char* const argvCp[] = {"cp", srcFilePath, destFilePath, NULL};
        result = ExecCmd(busybox, (char* const*)argvCp);
    } else {
        sprintf(destFilePath, "%s%s", srcFilePath, ".bak");
        const char* const argvCp[] = {"cp", srcFilePath, destFilePath, NULL};
        result = ExecCmd(busybox, (char* const*)argvCp);
    }

    printf("backup %s to %s %s\n",
        srcFilePath, destFilePath, (result != 0) ? "failed" : "successful");
    sync();
    return result;
}

static int FlashWriteMacFun(const char *filePath, const char *keyName, char *keyStr)
{
    FILE *fp = NULL;
    char *rBuff = NULL, *wBuff = NULL;
    char keyBuff[MAC_KEY_LEN + 1] = {0};
    char *line = NULL;
    int count = 0, size = 0, rc = 0, error = 0, offset = 0;
    unsigned char mac[6] = {0};

    fp = fopen(filePath, "r");
    if (fp == NULL) {
        ui->Print("open %s failed (%s)\n", filePath, strerror(errno));
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);

    rBuff = (char *)malloc(size + 1);
    wBuff = (char *)malloc(size + 2);
    if (rBuff == NULL || wBuff == NULL) {
        printf("can't malloc for rBuff or wBuff\n");
        if (rBuff) free(rBuff);
        if (wBuff) free(wBuff);
        fclose(fp);
        return -1;
    }

    fseek(fp, 0, SEEK_SET);
    count = fread(rBuff, 1, size, fp);
    if (count != size) {
        ui->Print("read %s failed. count(%d) != size(%d)\n",
            filePath, count, size);
        if (rBuff) free(rBuff);
        if (wBuff) free(wBuff);
        fclose(fp);
        return -1;
    }

    rc = 0;
    rBuff[size] = '\0';
    fclose(fp);
    fp = NULL;

    line = strtok(rBuff, "\n");
    do {
        if (*line == '$' || (strlen(line) != MAC_KEY_LEN && strlen(line) != MAC_KEY_LEN + 1)) {
            offset += strlen(line) + 1;
            // printf("skip line=%s. offset=%d\n", line, offset);
            continue;
        }
        for (rc = 0; rc < MAC_KEY_LEN; rc += 3) {
            if (isxdigit(line[rc]) &&
                isxdigit(line[rc + 1]) &&
                (line[rc + 2] == ':' || line[rc + 2] == '\0' || line[rc + 2] == '\r')) {
                mac[rc/3] = ((isdigit(line[rc]) ? line[rc] - '0' : toupper(line[rc]) - 'A' + 10) << 4) |
                            (isdigit(line[rc + 1]) ? line[rc + 1] - '0' : toupper(line[rc + 1]) - 'A' + 10);
            } else {
                break;
            }
        }

        if (rc == MAC_KEY_LEN + 1) {
            sprintf(keyBuff, "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            printf("match line:%s\n", line);
            printf("writing %s:%s\n", keyName, keyBuff);
            if (!FlashWriteKey(keyName, keyBuff)) {
                fp = fopen(filePath, "r");
                if (fp) {
                    fread(rBuff, 1, size, fp);
                    rBuff[size] = '\0';
                    fclose(fp);
                    fp = NULL;

                    BackupFile(filePath); // the best to save file first
                    fp = fopen(filePath, "w+");
                    if (fp) {
                        line = wBuff;
                        memset(wBuff, 0, size + 2);
                        memcpy(line, rBuff, offset);
                        *(line + offset) = '$';
                        memcpy(line + offset + 1, rBuff + offset, size - offset);
                        offset = fwrite(wBuff, 1, size + 1, fp);
                        printf("rewrite offset=%d size=%d to %s\n", offset, size + 2, filePath);
                        if (offset != size + 1) {
                            error++;
                            printf("error %s(%d).\n", keyName, error);
                        }
                        fclose(fp);
                        memcpy(keyStr, keyBuff, strlen(keyBuff));
                        sync();
                    } else {
                        ui->Print("open %s failed (%s)\n", filePath, strerror(errno));
                        return -1;
                    }
                } else {
                    ui->Print("open %s failed (%s)\n", filePath, strerror(errno));
                    return -1;
                }
            } else {
                error++;
                printf("flash write failed.error(%d)\n", error);
            }
            break;
        } else {
            offset += strlen(line) + 1;
            printf("invalid line=%s. offset=%d\n", line, offset);
        }
    } while((line = strtok(NULL,"\n")));

    if (rc != MAC_KEY_LEN + 1) {
        ui->Print("error: havn't found any %s can be written in %s\n",
            keyName, filePath);
        error ++;
    }

    if (rBuff) {
        free(rBuff);
        rBuff = NULL;
    }
    if (wBuff) {
        free(wBuff);
        wBuff = NULL;
    }
    return -error;
}

static int FlashWriteUsidFun(const char *keyFilePath, const char *keyInfoPath, char *keyStr)
{
    FILE *fpKey = NULL, *fpInfo = NULL;
    size_t count = 0, size = 0;
    int line = 0, rc = -1;
    int startValue = 0, usidStartLen = 0, usidEndLen = 0;
    int basePosition[USID_GROUP_NUM] = {0};     // 0: base is in the previous, 1: base is in the back
    int groupIndex = 0, usedGroupIndex = 0;     // 0: use Group1, 1: use Group2
    long int usidTotal[USID_GROUP_NUM] = {0}, calculateUsidTotal = -1, writeUsidIndex = -1;

    char *tmpStr = NULL, *rBuf = NULL, *wBuf = NULL, *groupStr = NULL, *infoBackup = NULL;
    char groupUsidStart[USID_GROUP_NUM][BUF_SIZE], groupUsidEnd[USID_GROUP_NUM][BUF_SIZE];
    char tmpBuf[128] = {0}, format[128] = {0}, usidValue[128] = {0}, usidStr[BUF_SIZE] = {0};

    const char *GROUP1 = "[Group1]", *GROUP2 = "[Group2]", *USID_USAG = "[USID usage information]";
    const char *BASE = "base=", *START = "start=", *END = "end=";   // group message
    const char *USE = "use:", *USID_TOTAL = "usid total:", *USID_INDEX = "prepare to write usid index:";

    /* parse usid */
    fpKey = fopen(keyFilePath, "r");
    if (fpKey == NULL) {
        ui->Print("open %s failed (%s)\n", keyFilePath, strerror(errno));
        return -1;
    }

    fseek(fpKey, 0, SEEK_END);
    size = ftell(fpKey);

    rBuf = (char *)calloc(size + 1, sizeof(char));
    if (rBuf == NULL) {
        printf("can't malloc for rBuf\n");
        goto ERR1;
    }

    fseek(fpKey, 0, SEEK_SET);
    count = fread(rBuf, 1, size, fpKey);
    if (count != size) {
        ui->Print("fread %s count(%d) != size(%d)\n",
            keyFilePath, count, size);
        free(rBuf);
        goto ERR1;
    }
    printf("%s contents:\n%s\n", keyFilePath, rBuf);

    memset(groupUsidStart, 0, USID_GROUP_NUM * BUF_SIZE);
    memset(groupUsidEnd, 0, USID_GROUP_NUM * BUF_SIZE);

    tmpStr = strtok(rBuf, "\n");
    while (tmpStr != NULL) {
        if (tmpStr[strlen(tmpStr) -1] == 0x0D) {
            tmpStr[strlen(tmpStr) -1] = '\0';
        }
        tmpStr = trim(tmpStr);
        if (strstr(tmpStr, GROUP1)) {
            groupIndex = 0;                             // Group1
        } else if (strstr(tmpStr, GROUP2)) {
            groupIndex = 1;                             // Group2
        }

        if (strstr(tmpStr, BASE)) {
            strcpy(USID_BASE(groupIndex), tmpStr + strlen(BASE));
            if (line == 0) {
                basePosition[groupIndex] = 0;   // base in the previous
            } else {
                basePosition[groupIndex] = 1;   // base in the previous
            }
            line ++;
        } else if (strstr(tmpStr, START)) {
            strcpy(USID_START(groupIndex), tmpStr + strlen(START));
            line ++;
        } else if (strstr(tmpStr, END)) {
            strcpy(USID_END(groupIndex), tmpStr + strlen(END));
            line ++;
        }

        if (line == 3) {
            line = 0;
            int diffValue = strtol(USID_END(groupIndex), 0, 10) -
                strtol(USID_START(groupIndex), 0, 10);
            if (diffValue < 0) {
                ui->Print("error: %s the value of end < the value of start\n",
                    groupIndex ? GROUP2 : GROUP1);
                free(rBuf);
                goto ERR1;
            }
            usidTotal[groupIndex] = diffValue + 1;
            if (usidTotal[groupIndex] > USID_NUM_MAX || usidTotal[groupIndex] <= 0) {
                ui->Print("error: %s usid num(%ld) out of range([1~%ld])\n",
                    (groupIndex ? GROUP2 : GROUP1), usidTotal[groupIndex], (long int)USID_NUM_MAX);
                free(rBuf);
                goto ERR1;
            }

            if (!basePosition[groupIndex]) {    // base in the previous
                strcat(groupUsidStart[groupIndex], USID_BASE(groupIndex));
                strcat(groupUsidStart[groupIndex], USID_START(groupIndex));
                strcat(groupUsidEnd[groupIndex], USID_BASE(groupIndex));
                strcat(groupUsidEnd[groupIndex], USID_END(groupIndex));
            } else {                                        // base in the back
                strcat(groupUsidStart[groupIndex], USID_START(groupIndex));
                strcat(groupUsidStart[groupIndex], USID_BASE(groupIndex));
                strcat(groupUsidEnd[groupIndex], USID_END(groupIndex));
                strcat(groupUsidEnd[groupIndex], USID_BASE(groupIndex));
            }
            printf("%s usid range:\n%s ~ %s. usid total:%ld\n", groupIndex ? GROUP2 : GROUP1,
                groupUsidStart[groupIndex], groupUsidEnd[groupIndex], usidTotal[groupIndex]);
        }
        tmpStr = strtok(NULL, "\n");
    }

    if (rBuf != NULL) {
        free(rBuf);
        rBuf = NULL;
    }

    /* parse usid.ini */
    fpInfo = fopen(keyInfoPath, "r");
    if (!fpInfo) {
        ui->Print("open %s failed (%s)\n", keyInfoPath, strerror(errno));
        goto ERR1;
    }

    fseek(fpInfo, 0, SEEK_END);
    size = ftell(fpInfo);
    fseek(fpInfo, 0, SEEK_SET);

    rBuf = (char *)calloc(size + 128, sizeof(char));
    wBuf = (char *)calloc(size + 128, sizeof(char));
    if (!rBuf || !wBuf) {
        if (rBuf) free(rBuf);
        if (wBuf) free(wBuf);
        printf("can't malloc for rBuf or wBuf\n");
        goto ERR2;
    }

    count = fread(rBuf, 1, size, fpInfo);
    if (count != size) {
        ui->Print("read %s failed. count(%d) != size(%d)\n",
            keyInfoPath, count, size);
        goto ERR3;
    }

    infoBackup = strdup(rBuf);
    if (infoBackup == NULL) {
        printf("can't strdup for infoBackup\n");
        goto ERR3;
    }

    printf("%s contents:\n%s\n", keyInfoPath, infoBackup);
    if (!strstr(infoBackup, USE)) {
        ui->Print("error: havn't found match message(%s) in %s\n",
            USE, keyInfoPath);
        goto ERR4;
    }

    if (!strstr(infoBackup, USID_TOTAL)) {
        ui->Print("error: havn't found match message(%s) in %s\n",
            USID_TOTAL, keyInfoPath);
        goto ERR4;
    }

    if (!strstr(infoBackup, USID_INDEX)) {
        ui->Print("error: havn't found match message(%s) in %s\n",
            USID_INDEX, keyInfoPath);
        goto ERR4;
    }

    tmpStr = strtok(rBuf, "\n");
    while (tmpStr != NULL) {
        if (strstr(tmpStr, USE)) {
            if (strstr(tmpStr, GROUP1)) {
                usedGroupIndex = 0;  // use Group1
            } else if (strstr(tmpStr, GROUP2)) {
                usedGroupIndex = 1;  // use Group2
            } else {
                ui->Print("error: can't find specify Group in %s\n", keyInfoPath);
                goto ERR4;
            }
        } else if (strstr(tmpStr, USID_TOTAL)) {
            calculateUsidTotal = strtol(tmpStr + strlen(USID_TOTAL), 0 , 10);
            if (calculateUsidTotal <= 0) {
                ui->Print("error: calculate usid total(%ld) <= 0\n", calculateUsidTotal);
                goto ERR4;
            } else if (calculateUsidTotal != usidTotal[usedGroupIndex]) {
                ui->Print("error: calculate usid total(%ld) != actual usid total(%ld)\n",
                    calculateUsidTotal, usidTotal[usedGroupIndex]);
                goto ERR4;
            }
        } else if (strstr(tmpStr, USID_INDEX)) {
            writeUsidIndex = strtol(tmpStr + strlen(USID_INDEX), 0, 10);
            if (writeUsidIndex <= 0) {
                ui->Print("error: write usid index(%ld) <= 0\n", writeUsidIndex);
                goto ERR4;
            } else if (writeUsidIndex > usidTotal[usedGroupIndex]) {
                ui->Print("error: write usid index(%ld) > actual usid total(%ld)\n",
                    writeUsidIndex, usidTotal[usedGroupIndex]);
                goto ERR4;
            }
        }
        tmpStr = strtok(NULL, "\n");
    }

    printf("%s %s, %s %ld, %s %ld\n",
        USE, usedGroupIndex ? GROUP2 : GROUP1, USID_TOTAL,
        calculateUsidTotal, USID_INDEX, writeUsidIndex);

    /* get prepare write usid by index */
    usidStartLen = strlen(USID_START(usedGroupIndex));
    usidEndLen = strlen(USID_END(usedGroupIndex));
    if (usidStartLen != usidEndLen) {
        ui->Print("error: %s start length(%d) != end length(%d)\n",
            usedGroupIndex ? GROUP2 : GROUP1, usidStartLen, usidEndLen);
        goto ERR4;
    }

    /* format: %0?d */
    strcat(format, "%0");
    sprintf(tmpBuf, "%dd", usidStartLen);
    strcat(format, tmpBuf);

    startValue = strtol(USID_START(usedGroupIndex), 0, 10);
    sprintf(usidValue, format, (writeUsidIndex - 1) + startValue);//100 ->000100
    if (!basePosition[usedGroupIndex]) {// base is in the previous
        strcat(usidStr, USID_BASE(usedGroupIndex));
        strcat(usidStr, usidValue);
    } else {                                            // base is in the back
        strcat(usidStr, usidValue);
        strcat(usidStr, USID_BASE(usedGroupIndex));
    }

    printf("writing usid:%s\n", usidStr);
    if (FlashWriteKey(keyTitle[USID].name, usidStr) < 0) {
        goto ERR4;
    } else {                                        // write usid ok
        if (fpInfo) {
            fclose(fpInfo);
            fpInfo = NULL;
        }

        BackupFile(keyInfoPath);    // the best to save file first
        fpInfo = fopen(keyInfoPath, "w+");
        if (!fpInfo) {
            ui->Print("open %s failed (%s)\n", keyInfoPath, strerror(errno));
            goto ERR4;
        }

        tmpStr = strstr(infoBackup, USID_INDEX);
        if (tmpStr) {
            int writeIndexPositionOffsetLen = (int)(tmpStr - infoBackup) + strlen(USID_INDEX);
            printf("writeIndexPositionOffsetLen: %d\n", writeIndexPositionOffsetLen);
            memcpy(wBuf, infoBackup, writeIndexPositionOffsetLen);
            memset(tmpBuf, 0, sizeof(tmpBuf));
            sprintf(tmpBuf, "%ld\n", ++writeUsidIndex);
            strcat(wBuf, tmpBuf);
            count = fwrite(wBuf, 1, strlen(wBuf), fpInfo);
            if (count != strlen(wBuf)) {
                ui->Print("rewrite to information %s failed(size:%d,count:%d).\n%s",
                    keyInfoPath, strlen(wBuf), count, wBuf);
                goto ERR4;
            }
            memcpy(keyStr, usidStr, strlen(usidStr));
            sync();
            rc = 0;                                     // successful
            printf("rewrite information to %s successful(size:%d,count:%d).\n%s",
                keyInfoPath, strlen(wBuf), count, wBuf);
        } else {
             ui->Print("error: havn't found match message(%s) in %s\n",
                USID_INDEX, keyInfoPath);
             goto ERR4;
        }
    }


ERR4:
    if (infoBackup != NULL) {
        free(infoBackup);
        infoBackup = NULL;
    }

ERR3:
    if (rBuf != NULL) {
        free(rBuf);
        rBuf = NULL;
    }
    if (wBuf != NULL) {
        free(wBuf);
        wBuf = NULL;
    }

ERR2:
    if (fpInfo != NULL) {
        fclose(fpInfo);
        fpInfo = NULL;
    }

ERR1:
    if (fpKey != NULL) {
        fclose(fpKey);
        fpKey = NULL;
    }

    return rc;
}

static unsigned char Char2Dial(char c_left, char c_right)
{
    char ox_left = 0, ox_right = 0;

    if (c_left >= '0' && c_left <= '9') {
        ox_left = c_left - 0x30;
    } else if (c_left >= 'A' && c_left <= 'F') {
        ox_left = (c_left - 0x40) + 0x9;
    } else if (c_left >= 'a' && c_left <= 'f') {
        ox_left = (c_left - 0x60) + 0x9;
    }

    if (c_right >= '0' && c_right <= '9') {
        ox_right = c_right - 0x30;
    } else if (c_right >= 'A' && c_right <= 'F') {
        ox_right = (c_right - 0x40) + 0x9;
    } else if (c_right >= 'a' && c_right <= 'f') {
        ox_right = (c_right - 0x60) + 0x9;
    }

    return (unsigned char)((ox_left << 4) | ox_right);
}

static int FlashWriteHdcpFun(const char *keyFilePath, const char *keyInfoPath)
{
    FILE *fpKey = NULL, *fpInfo = NULL;
    size_t count = 0, keyFileSize = 0, infoFileSize = 0;
    int i = 0, rc = -1, iVal[4] = {0};
    int positionOffset = 0, hdcpIndexPositionOffset = 0;
    int hdcpKeyTotal = 0, hdcpCalculateTotal = 0, hdcpIndex = 0;

    char *tmpStr = NULL, sBuf[128] = {0};
    char *keyBuf = NULL, *infoBuf = NULL, *infoBackupBuf = NULL;
    char hdcpVerifyDataCalculate[20] = {0};
    unsigned char buf[4] = {0}, hdcpKey[HDCP_KEY_SIZE] = {0};
    const char *HDCP_TOTAL = "hdcp total:", *HDCP_INDEX = "prepare to write hdcp index:";

    fpKey = fopen(keyFilePath, "rb");
    if (fpKey == NULL) {
       ui->Print("open %s failed (%s)\n", keyFilePath, strerror(errno));
       return -1;
    }

    fpInfo = fopen(keyInfoPath, "r");
    if (fpInfo == NULL) {
        ui->Print("open %s failed (%s)\n", keyInfoPath, strerror(errno));
        goto ERR1;
    }

    fseek(fpKey, 0, SEEK_END);
    fseek(fpInfo, 0, SEEK_END);
    keyFileSize = ftell(fpKey);
    infoFileSize = ftell(fpInfo);

    keyBuf = (char *)calloc(keyFileSize, sizeof(char));
    infoBuf = (char *)calloc(infoFileSize + 128, sizeof(char));
    infoBackupBuf = (char *)calloc(infoFileSize + 128, sizeof(char));
    if (keyBuf == NULL || infoBuf == NULL || infoBackupBuf == NULL) {
        if (keyBuf) free(keyBuf);
        if (infoBuf) free(infoBuf);
        if (infoBackupBuf) free(infoBackupBuf);
        printf("can't malloc for keyBuf or infoBuf or infoBackupBuf\n");
        goto ERR2;
    }

    fseek(fpKey, 0, SEEK_SET);
    fseek(fpInfo, 0, SEEK_SET);
    count = fread(infoBuf, 1, infoFileSize, fpInfo);
    if (count != infoFileSize) {
        ui->Print("read %s count(%d) != size(%d)\n",
            keyInfoPath, count, infoFileSize);
        goto ERR3;
    }
    memcpy(infoBackupBuf, infoBuf, infoFileSize);
    printf("%s contents:\n%s\n", keyInfoPath, infoBuf);

    if (!strstr(infoBuf, HDCP_TOTAL)) {
        ui->Print("error: havn't found match message(%s) in %s\n",
            HDCP_TOTAL, keyInfoPath);
        goto ERR3;
    }

    if (!strstr(infoBuf, HDCP_INDEX)) {
        ui->Print("error: havn't found match message(%s) in %s\n",
            HDCP_INDEX, keyInfoPath);
        goto ERR3;
    }

    /* parse hdcp.ini */
    /* get hdcp index number offset in hdcp.ini */
    tmpStr = strstr(infoBuf, HDCP_INDEX);
    if (tmpStr) {
        hdcpIndexPositionOffset = (tmpStr - infoBuf) + strlen(HDCP_INDEX);
    } else {
        ui->Print("error: havn't found match message(%s) in %s\n",
            HDCP_INDEX, keyInfoPath);
        goto ERR3;
    }

    tmpStr = strtok(infoBuf, "\n");
    while (tmpStr != NULL) {
        if (tmpStr[strlen(tmpStr) -1] == 0x0D) {
            tmpStr[strlen(tmpStr) -1] = '\0';
        }
        tmpStr = trim(tmpStr);
        if (strstr(tmpStr, HDCP_TOTAL)) {
            hdcpCalculateTotal = strtoul(tmpStr + strlen(HDCP_TOTAL), 0, 10);
        } else if (strstr(tmpStr, HDCP_INDEX)) {
            hdcpIndex = strtoul(tmpStr + strlen(HDCP_INDEX), 0, 10);
        }
        tmpStr = strtok(NULL, "\n");
    }

    if (hdcpCalculateTotal == 0 || hdcpIndex == 0) {
        ui->Print("error: information isn't correct in %s (total(%d)/index(%d) = 0)\n",
            keyInfoPath, hdcpCalculateTotal, hdcpIndex);
        goto ERR3;
    } else if(hdcpIndex > hdcpCalculateTotal) {
        ui->Print("error: havn't found any hdcp can be written in %s (index:%d > total:%d)\n",
            keyInfoPath, hdcpIndex, hdcpCalculateTotal);
        goto ERR3;
    }

    /* judge the total number of hdcp key */
    for (i = 0; i < 4; i ++) {
        iVal[i] = fgetc(fpKey);
        sprintf(sBuf, "%02x", iVal[i]);
        buf[i] = Char2Dial(sBuf[0], sBuf[1]);
    }
    hdcpKeyTotal = (buf[0]<<24) | (buf[1]<<16) | (buf[2]<<8) | (buf[3]<<0);
    if (hdcpCalculateTotal != hdcpKeyTotal) {
        ui->Print("error: total number of hdcp in %s not mach with %s\n",
            keyFilePath, keyInfoPath);
        goto ERR3;
    }

    /* get the specified location hdcp keys */
    fseek(fpKey, 0, SEEK_SET);
    positionOffset = 4 + (hdcpIndex - 1) * HDCP_KEY_SIZE;
    fseek(fpKey, positionOffset, SEEK_SET);
    for (i = 0; i < HDCP_KEY_SIZE; i ++) {
        iVal[0] = fgetc(fpKey);
        sprintf(sBuf, "%02x", iVal[0]);
        hdcpKey[i] = Char2Dial(sBuf[0], sBuf[1]);
    }

#if 0
    printf("NO.%d hdcp keys in %s are(total:308, include 20 verify datas):\n", hdcpIndex, keyFilePath);
    for (i = 0; i < HDCP_KEY_SIZE; i++) {
        printf("%02x:", hdcpKey[i]);
    }
    printf("\n");
#endif

    /* hdcp verify */
    printf("start to verify hdcp key datas...\n");
    printf("20 hdcp key verify datas:\n");
    for (i = 288; i < HDCP_KEY_SIZE; i ++)
        printf("%02x:", hdcpKey[i]);

    SHA1_Perform(hdcpKey, HDCP_KEY_LEN, (uint8_t*)hdcpVerifyDataCalculate);
    printf("\nverify & get 20 hdcp verify datas:\n");
    for (i = 0; i < 20; i ++)
        printf("%02x:", hdcpVerifyDataCalculate[i]);
    printf("\n");

    if (memcmp((char *)&hdcpKey[HDCP_KEY_LEN], hdcpVerifyDataCalculate, 20)) {
        ui->Print("error: hdcp verify failed\n");
        goto ERR3;
    } else {
        printf("hdcp verify successful, start to write...\n");
        if (FlashWriteKey(keyTitle[HDCP].name, (char *)hdcpKey) < 0) {
            goto ERR3;
        } else {
            memset(infoBuf, 0, infoFileSize + 128);
            strncpy(infoBuf, infoBackupBuf, hdcpIndexPositionOffset);
            hdcpIndex ++;
            memset(sBuf, 0, sizeof(sBuf));
            sprintf(sBuf, "%d\n", hdcpIndex);
            strncpy(infoBuf + hdcpIndexPositionOffset, sBuf, strlen(sBuf));
            if (fpInfo != NULL) {
                fclose(fpInfo);
                fpInfo = NULL;
            }

            BackupFile(keyInfoPath);// the best to save file first
            fpInfo = fopen(keyInfoPath, "w+");
            if (fpInfo == NULL) {
               ui->Print("open %s failed (%s)\n", keyInfoPath, strerror(errno));
               goto ERR3;
            }
            count = fwrite(infoBuf, 1, strlen(infoBuf), fpInfo);
            if (count != strlen(infoBuf)) {
                ui->Print("rewrite information to %s failed(size:%d,count:%d).\n%s",
                    keyInfoPath, strlen(infoBuf), count, infoBuf);
                goto ERR3;
            }
            sync();
            rc = 0;                             // successful
            printf("rewrite information to %s successful(size:%d,count:%d).\n%s",
                keyInfoPath, strlen(infoBuf), count, infoBuf);
        }
    }


ERR3:
    if (keyBuf != NULL) {
        free(keyBuf);
        keyBuf = NULL;
    }
    if (infoBuf != NULL) {
        free(infoBuf);
        infoBuf = NULL;
    }
    if (infoBackupBuf != NULL) {
        free(infoBackupBuf);
        infoBackupBuf = NULL;
    }

ERR2:
    if (fpInfo != NULL) {
        fclose(fpInfo);
        fpInfo = NULL;
    }

ERR1:
    if (fpKey != NULL) {
        fclose(fpKey);
        fpKey = NULL;
    }

    return rc;
}

static int WriteKey2Efuse(const char *keyFilePath,
        const char *keyInfoPath,
        const char *keyName,
        const int force) {
    // TODO: not support efuse at present
    ui->Print("can't support write key(%s) to efuse at present\n",
        keyName);
    return -1;
}

/**
  *  --- write key to flash
  *  @keyFilePath: key file
  *  @keyInfoPath: key info file
  *  @keyName: mac/mac_bt/mac_wifi/usid/hdcp ...
  *  @force: 0 said read key first,if key doesn't be writen before,
        so start to write;if key has been writen,so key will not be writen;
        non-zero said write force,not care key has been writen
  *  return: 0->write success or key exist, -1->write failed
  */
static int WriteKey2Flash(const char *keyFilePath,
        const char *keyInfoPath,
        const char *keyName,
        const int force) {
    int i = 0, result = -1;
    char rKey[SECUKEY_BYTES] = {0};
    char wKey[SECUKEY_BYTES] = {0};

    if (EnsureSecukeyInit() < 0) return -1;

    if (!strcmp(keyName, keyTitle[MAC_WIFI].name) ||
        !strcmp(keyName, keyTitle[MAC_BT].name) ||
        !strcmp(keyName, keyTitle[MAC].name)) {
        if (!force) {   // read first before write
            result = FlashReadKey(keyName, rKey);
            if (result == 0) {
                ui->Print("flash have writen %s(%s) before!\n", keyName, rKey);
            } else if (result < 0) {
                ui->Print("flash read %s failed!\n", keyName);
            }
            if (result <= 0) return result;
        }

        result = FlashWriteMacFun(keyFilePath, keyName, wKey);
        if (!result) {
            ui->Print("flash write %s(%s) successful!\n", keyName, wKey);
        } else {
            ui->Print("flash write %s failed!\n", keyName);
        }
    } else if (!strcmp(keyName, keyTitle[USID].name)) {
        if (!force) {   // read first before write
            result = FlashReadKey(keyName, rKey);
            if (result == 0) {
                ui->Print("flash have writen %s(%s) before!\n", keyName, rKey);
            } else if (result < 0) {
                ui->Print("flash read %s failed!\n", keyName);
            }
            if (result <= 0) return result;
        }

        result = FlashWriteUsidFun(keyFilePath, keyInfoPath, wKey);
        if (!result) {
            ui->Print("flash write %s(%s) successful!\n", keyName, wKey);
        } else {
            ui->Print("flash write %s failed!\n", keyName);
        }
    } else if (!strcmp(keyName, keyTitle[HDCP].name)) {
        if (!force) {
            result = FlashReadKey(keyName, rKey);
            if (result == 0) {
                ui->Print("flash have writen %s before!\n", keyName);
                /*for (i = 0; i < HDCP_KEY_LEN; i ++) {
                    printf("%02x:", rKey[i]);
                }
                printf("\n");*/
            } else if (result < 0) {
                ui->Print("flash read %s failed!\n", keyName);
            }
            if (result <= 0) return result;
        }

        result = FlashWriteHdcpFun(keyFilePath, keyInfoPath);
        if (!result) {
            ui->Print("flash write %s successful!\n", keyName);
        } else {
            ui->Print("flash write %s failed!\n", keyName);
        }
    } else {
        ui->Print("can't support write %s!\n", keyName);
    }

    return result;
}

char *trim(char * src)
{
    int i = 0;
    char *begin = src;

    while (src[i] != '\0') {
        if (src[i] != ' ') {
            break;
        } else {
            begin++;
        }
        i++;
    }

    for (i = strlen(begin) - 1; i >= 0;  i --) {
        if (begin[i] != ' ') {
            break;
        } else {
            begin[i] = '\0';
        }
    }
    return begin;
}

static const char *FindKeyFileDir(void)
{
    const char *dir = NULL;
    const char *UDISK_COMMAND_FILE = "/udisk/factory_update_param.aml";
    const char *SDCARD_COMMAND_FILE = "/sdcard/factory_update_param.aml";

    if (!access(SDCARD_COMMAND_FILE, F_OK)) {
        dir = "/sdcard";
    } else if (!access(UDISK_COMMAND_FILE, F_OK)) {
        dir = "/udisk";
    } else {
        return NULL;
    }
    return dir;
}

static int ParseKey(T_WriteKey key[], const char *optarg)
{
    int i = 0;
    char *buffer = NULL, *str = NULL;

    buffer = strdup(optarg);
    if (!buffer) {
        printf("strdup for buffer failed\n");
        return -1;
    }

    str = strtok(buffer, ",");
    while (str != NULL && i < KEY_TYPE_MAX) {
        if (strchr(str, ':')) {
            char buf[128] = {0};
            sscanf(str,"%[^:]:%d", buf, &key[i].force);
            strcpy(key[i].name, trim(buf));
            key[i].exist = 1;
        } else {
            strcpy(key[i].name, str);
            key[i].force  = 0;
            key[i].exist = 1;
        }
        str = strtok(NULL, ",");
        i ++;
    }

    if (buffer != NULL) {
        free(buffer);
        buffer = NULL;
    }

    return 0;
}

/**
  *  --- write key to flash/efuse cycle
  *  @keyOptarg: key args
  *  return: 0->success, -1->failed
  */
int RecoveryWriteKey(const char *keyOptarg)
{
    int i = 0, ret = -1;
    char keyInfoFile[128] = {0};
    char key2FlashFile[128] = {0};
    char key2EfuseFile[128] = {0};
    const char *keyFileDir = NULL;
    T_WriteKey key[KEY_TYPE_MAX];

    ui->SetBackground(RecoveryUI::INSTALLING_UPDATE);
    ui->SetProgressType(RecoveryUI::EMPTY);
    ui->Print("\n-- Writing Key...\n");
    ui->Print("Args: %s\n", keyOptarg);

    keyFileDir = FindKeyFileDir();
    if (keyFileDir == NULL) {
        ui->Print("can't find factory_update_param.aml in /sdcard or /udisk\n");
        return -1;
    }

    memset(key, 0, sizeof(key));
    if (ParseKey(key, keyOptarg) < 0) {
        ui->Print("parse key optargs failed\n");
        return -1;
    }

    for (i = 0; i < KEY_TYPE_MAX; i ++) {
        if (key[i].exist) {
            printf("--- [%d] name:%s, force:%d\n", i, key[i].name, key[i].force);
            memset(keyInfoFile, 0, sizeof(keyInfoFile));
            memset(key2FlashFile, 0, sizeof(key2FlashFile));
            memset(key2EfuseFile, 0, sizeof(key2EfuseFile));
            sprintf(key2FlashFile, "%s/%s.flash", keyFileDir, key[i].name);
            sprintf(key2EfuseFile, "%s/%s.efuse", keyFileDir, key[i].name);
            sprintf(keyInfoFile, "%s/%s.ini", keyFileDir, key[i].name);

            if (!access(key2FlashFile, F_OK)) { // if exist at the same time, write to flash priority
                ret = WriteKey2Flash(key2FlashFile, keyInfoFile, key[i].name, key[i].force);
            } else if (!access(key2EfuseFile, F_OK)) {
                ret = WriteKey2Efuse(key2EfuseFile, keyInfoFile, key[i].name, key[i].force);
            } else {
                ui->Print("can't find any key(%s) files in %s.\n", key[i].name, keyFileDir);
                break;
            }

            if (ret < 0) {
                ui->Print("Write %s failed.\n", key[i].name);
                break;
            }
            printf("\n");
        }
    }

    return ret;
}
