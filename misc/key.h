/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _KEY_H_
#define _KEY_H_

#define MAC_KEY_LEN	17
#define HDCP_KEY_SIZE	308
#define HDCP_KEY_LEN	288
#define USID_KEY_LEN	512
#define USID_GROUP_NUM	2
#define USID_NUM_MAX	1000000

#define BUF_SIZE	512
#define SECUKEY_BYTES	BUF_SIZE

#define SECUKEY_LIST	"/sys/class/aml_keys/aml_keys/key_list"
#define SECUKEY_NAME	"/sys/class/aml_keys/aml_keys/key_name"
#define SECUKEY_READ	"/sys/class/aml_keys/aml_keys/key_read"
#define SECUKEY_WRITE	"/sys/class/aml_keys/aml_keys/key_write"
#define SECUKEY_VERSION	"/sys/class/aml_keys/aml_keys/version"

typedef struct Group {
    char base[BUF_SIZE];
    char start[BUF_SIZE];
    char end[BUF_SIZE];
} T_Group;

static T_Group usidGroup[USID_GROUP_NUM];

#define USID_BASE(i) usidGroup[i].base
#define USID_START(i) usidGroup[i].start
#define USID_END(i) usidGroup[i].end

typedef enum KeyType {
    MAC,
    MAC_BT,
    MAC_WIFI,
    USID,
    HDCP,
    KEY_TYPE_MAX,
} T_KeyType;

typedef struct KeyTitle {
    const char *name;
    int id;
} T_KeyTitle;

static T_KeyTitle keyTitle[KEY_TYPE_MAX] = {
    { "mac",	  MAC },
    { "mac_bt",   MAC_BT },
    { "mac_wifi", MAC_WIFI },
    { "usid", 	  USID },
    { "hdcp",	  HDCP }
};

typedef struct WriteKey {
    char name[50];
    int force;
    int exist;
} T_WriteKey;

extern RecoveryUI *ui;
char *trim(char * src);

#endif  /* _KEY_H_ */
