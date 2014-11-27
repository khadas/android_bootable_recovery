/*
 * Copyright (C) 2009 The Android Open Source Project
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/input.h>

#include "common.h"
#include "device.h"
#include "screen_ui.h"

static const char* HEADERS[] = { "Volume up/down to move highlight;",
                                 "enter button to select.",
                                 "",
                                 NULL };

static const char* ITEMS[] =  {"reboot system now",
                               "apply update from EXT",
                               "apply update from cache",
                               "apply update from ADB",
                               "wipe data/factory reset",
                               "wipe cache partition",
                               "reboot to bootloader",
                               "power down",
                               "view recovery logs",
                               NULL };

typedef struct {
    const char* type;
    int value;
    int key[6];
} KeyMapItem;

static int num_keys = 0;
static KeyMapItem* device_keys = NULL;
static KeyMapItem g_default_keymap[] = {
    { "select", Device::kInvokeItem, {KEY_ENTER, KEY_TAB, KEY_BACK, -1, -1, -1} },
    { "down", Device::kHighlightDown, {KEY_DOWN,  KEY_VOLUMEDOWN, KEY_PAGEDOWN, -1, -1, -1} },
    { "up", Device::kHighlightUp, {KEY_UP, KEY_VOLUMEUP, KEY_PAGEUP, -1, -1, -1} },
};

#define NUM_DEFAULT_KEY_MAP (sizeof(g_default_keymap) / sizeof(g_default_keymap[0]))

typedef struct {
    const char *type;
    int value;
} CtrlInfo;

static CtrlInfo g_ctrlinfo[] = {
    { "select", Device::kInvokeItem },
    { "down", Device::kHighlightDown },
    { "up", Device::kHighlightUp },
    { "no_action", Device::kNoAction },
    { "mode_switch", Device::kSwitchMode },
    { "back_door", Device::kBackDoor },
};

#define NUM_CTRLINFO (sizeof(g_ctrlinfo) / sizeof(g_ctrlinfo[0]))

static KeyMapItem g_presupposed_keymap[] = {
    { "select", Device::kInvokeItem, {BTN_MOUSE, BTN_LEFT, -1, -1, -1, -1} },
};

#define NUM_PRESUPPOSED_KEY_MAP (sizeof(g_presupposed_keymap) / sizeof(g_presupposed_keymap[0]))

class DefaultUI : public ScreenRecoveryUI {
  public:
    virtual KeyAction CheckKey(int key) {
        /*if (key == KEY_HOME) {
            return TOGGLE;
        }*/
        return ENQUEUE;
    }
};

class DefaultDevice : public Device {
  public:
    DefaultDevice() :
        ui(new DefaultUI) {
        load_key_map();
    }

    RecoveryUI* GetUI() { return ui; }

    int HandleMenuKey(int key, int visible) {
        if (visible) {
#if 0
            switch (key) {
              case KEY_DOWN:
              case KEY_VOLUMEDOWN:
                return kHighlightDown;

              case KEY_UP:
              case KEY_VOLUMEUP:
                return kHighlightUp;

              case KEY_ENTER:
              case KEY_POWER:
                return kInvokeItem;
            }
#else
            int i,j;
            for (i = 0; i < num_keys; i++) {
                for (j = 0; j < 6; j++) {
                KeyMapItem* v = &device_keys[i];
                    if(v->key[j] == key)
                        return v->value;
                }
            }

            for (i = 0; i < (int)NUM_PRESUPPOSED_KEY_MAP; i++) {
                for (j = 0; j < 6; j++) {
                    if(g_presupposed_keymap[i].key[j] == key)
                        return g_presupposed_keymap[i].value;
                }
            }
#endif
        }

        return kNoAction;
    }

    BuiltinAction InvokeMenuItem(int menu_position) {
        switch (menu_position) {
          case 0: return REBOOT;
          case 1: return APPLY_EXT;
          case 2: return APPLY_CACHE;
          case 3: return APPLY_ADB_SIDELOAD;
          case 4: return WIPE_DATA;
          case 5: return WIPE_CACHE;
          case 6: return REBOOT_BOOTLOADER;
          case 7: return SHUTDOWN;
          case 8: return READ_RECOVERY_LASTLOG;
          default: return NO_ACTION;
        }
    }

    const char* const* GetMenuHeaders() { return HEADERS; }
    const char* const* GetMenuItems() { return ITEMS; }

    int getKey(char *key) {
        unsigned int i;
        for (i = 0; i < NUM_CTRLINFO; i++) {
            CtrlInfo *info = &g_ctrlinfo[i];
            if (strcmp(info->type, key) == 0) {
                return info->value;
            }
        }
        return kNoAction;
    }

    void load_key_map() {
        FILE* fstab = fopen("/etc/recovery.kl", "r");
        if (fstab != NULL) {
            LOGI("loaded /etc/recovery.kl\n");
            int alloc = 2;
            device_keys = (KeyMapItem*)malloc(alloc * sizeof(KeyMapItem));

            device_keys[0].type = "select";
            device_keys[0].value = kNoAction;
            device_keys[0].key[0] = -1;
            device_keys[0].key[1] = -1;
            device_keys[0].key[2] = -1;
            device_keys[0].key[3] = -1;
            device_keys[0].key[4] = -1;
            device_keys[0].key[5] = -1;
            num_keys = 0;

            char buffer[1024];
            int i;
            while (fgets(buffer, sizeof(buffer)-1, fstab)) {
                for (i = 0; buffer[i] && isspace(buffer[i]); ++i);
                if (buffer[i] == '\0' || buffer[i] == '#') continue;

                char* original = strdup(buffer);

                char* type = strtok(original+i, " \t\n");
                char* key1 = strtok(NULL, " \t\n");
                char* key2 = strtok(NULL, " \t\n");
                char* key3 = strtok(NULL, " \t\n");
                char* key4 = strtok(NULL, " \t\n");
                char* key5 = strtok(NULL, " \t\n");
                char* key6 = strtok(NULL, " \t\n");

                if (type && key1) {
                    while (num_keys >= alloc) {
                        alloc *= 2;
                        device_keys = (KeyMapItem*)realloc(device_keys, alloc*sizeof(KeyMapItem));
                    }
                    device_keys[num_keys].type = strdup(type);
                    device_keys[num_keys].value = getKey(type);
                    device_keys[num_keys].key[0] = key1?atoi(key1):-1;
                    device_keys[num_keys].key[1] = key2?atoi(key2):-1;
                    device_keys[num_keys].key[2] = key3?atoi(key3):-1;
                    device_keys[num_keys].key[3] = key4?atoi(key4):-1;
                    device_keys[num_keys].key[4] = key5?atoi(key5):-1;
                    device_keys[num_keys].key[5] = key6?atoi(key6):-1;

                    ++num_keys;
                } else {
                    LOGE("skipping malformed recovery.lk line: %s\n", original);
                }
                free(original);
            }

            fclose(fstab);
        } else {
            LOGE("failed to open /etc/recovery.kl, use default map\n");
            num_keys = NUM_DEFAULT_KEY_MAP;
            device_keys = g_default_keymap;
        }

        LOGI("recovery key map table\n");
        LOGI("=========================\n");

        int i;
        for (i = 0; i < num_keys; ++i) {
            KeyMapItem* v = &device_keys[i];
            LOGI("  %d type:%s value:%d key:%d %d %d %d %d %d\n", i, v->type, v->value,
                   v->key[0], v->key[1], v->key[2], v->key[3], v->key[4], v->key[5]);
        }
        LOGI("\n");
    }

  private:
    RecoveryUI* ui;
};

Device* make_device() {
    return new DefaultDevice();
}
