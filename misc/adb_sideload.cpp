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

#include <fs_mgr.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/input.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "bootloader.h"
#include "common.h"
#include "cutils/properties.h"
#include "cutils/android_reboot.h"
#include "install.h"
#include "minui/minui.h"
#include "minzip/DirUtil.h"
#include "roots.h"
#include "ui.h"
#include "screen_ui.h"
#include "device.h"
#include "adb_install.h"
#include "mtdutils/mtdutils.h"
#include "adb_install.h"
#include "adb_sideload.h"

extern "C" {
#include "minadbd/adb.h"
}

static RecoveryUI* ui = NULL;

static int
exec_cmd(const char* path, const char *argv[]) {
    int status, i;
    pid_t child;
    if ((child = vfork()) == 0) {
        execv(path, (char* const*)argv);
        _exit(-1);
    }
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        LOGE("failed to exec %s\n", path);
        return INSTALL_CORRUPT;
    }

    return INSTALL_SUCCESS;
}

static void
reset_bootloader_message(void) {
    struct bootloader_message boot;
    memset(&boot, 0, sizeof(boot));
    set_bootloader_message(&boot);
}

static void
adb_reboot(void) {
    property_set(ANDROID_RB_PROPERTY, "reboot,");
    kill(getpid(), SIGABRT);
}

static int
adb_sideload(void) {
    int status = INSTALL_SUCCESS;

    if (!access(ADB_SIDELOAD_OK, F_OK)) {
        const char *argvs1[] = {
            "rm", ADB_SIDELOAD_OK, NULL};
        exec_cmd("/sbin/busybox", argvs1);
    }

    if (!access(ADB_SIDELOAD_FAIL, F_OK)) {
        const char *argvs2[] = {
            "rm", ADB_SIDELOAD_FAIL, NULL};
        exec_cmd("/sbin/busybox", argvs2);
    }

    int wipe_cache;
    status = apply_from_adb(ui, &wipe_cache, TEMPORARY_INSTALL_FILE);
    if (status >= 0) {
        if (status != INSTALL_SUCCESS) {
            ui->SetBackground(RecoveryUI::ERROR);
            ui->Print("Installation aborted.\n");

            adb_copy_logs();
            const char *argvs3[] = {
                "touch", ADB_SIDELOAD_FAIL, NULL};
            exec_cmd("/sbin/busybox", argvs3);
            return status;
        } else {
            ui->SetBackground(RecoveryUI::NO_COMMAND);
            ui->Print("\nInstall from ADB complete.\n");

            const char *argvs4[] = {
                "touch", ADB_SIDELOAD_OK, NULL};
            exec_cmd("/sbin/busybox", argvs4);
        }
    }

    ui->SetProgressType(RecoveryUI::EMPTY);
    return status;
}

void
*adb_sideload_listener_thread(void *arg) {
    int status = INSTALL_SUCCESS;

    while (1) {
        /*  Command for sideload mode:
        *   adb shell touch /tmp/adb_sideload
        */
        while (access(ADB_SIDELOAD, F_OK)) {
            usleep(10000);
        }

        const char *argvs[] = {
            "rm", ADB_SIDELOAD, NULL};
        exec_cmd("/sbin/busybox", argvs);

        status = adb_sideload();
        if (status == INSTALL_SUCCESS) {
            continue;
        } else {
            break;
        }
    }

    pthread_exit(NULL);
    return NULL;
}

void
*adb_wipe_listener_thread(void *arg) {
    typedef struct AdbWipe {
        int wipe_data;
        int wipe_cache;
    } T_AdbWipe;

    T_AdbWipe *adb_wipe = NULL;
    adb_wipe = (T_AdbWipe *)arg;
    int wipe_data = adb_wipe->wipe_data;
    int wipe_cache = adb_wipe->wipe_cache;

    if (wipe_data) {
        ui->Print("\nAdb wipe data...\n");
        if (adb_erase_volume("/data")) {
            ui->Print("Adb wipe data failed.\n");
        } else {
            ui->Print("Adb wipe data successful.\n");
        }
    }

    if (wipe_cache) {
        ui->Print("\nAdb wipe cache...\n");
        if (adb_erase_volume("/cache")) {
            ui->Print("Adb wipe cache failed.\n");
        } else {
            ui->Print("Adb wipe cache successful.\n");
        }
    }

    ui->SetProgressType(RecoveryUI::EMPTY);
    ui->SetBackground(RecoveryUI::NO_COMMAND);

    reset_bootloader_message();
    if (adb_wipe != NULL) {
        free(adb_wipe);
        adb_wipe = NULL;
    }

    kill(getpid(), SIGABRT);
    pthread_exit(NULL);
    return NULL;
}

void
adb_listeners(RecoveryUI* rui, int argc, char **argv) {
    ui = rui;
    pthread_t tid1, tid2;
    int adb_wipe_data = 0;
    int adb_wipe_cache = 0;

    switch (argc) {
        case 2:
            if (!strcmp(argv[1], "adb_reboot")) {
                adb_reboot();
            } else if (!strcmp(argv[1], "--adb_wipe_data")) {
                adb_wipe_data = 1;
            } else if (!strcmp(argv[1], "--adb_wipe_cache")) {
                adb_wipe_cache = 1;
            }
            break;

        case 3:
            if ((!strcmp(argv[1], "--adb_wipe_data") &&
                !strcmp(argv[2], "--adb_wipe_cache")) ||
                (!strcmp(argv[1], "--adb_wipe_cache") &&
                !strcmp(argv[2], "--adb_wipe_data"))) {
                adb_wipe_data = 1;
                adb_wipe_cache = 1;
            }
            break;
    }

    /* Thread for adb sideloader */
    if (!adb_wipe_data && !adb_wipe_cache) {
        if (pthread_create(&tid1, NULL,
            adb_sideload_listener_thread, NULL)) {
            LOGW("create adb sideload listener thread (%s)\n",
                strerror(errno));
        }
        ui->Print("\nRecovery is listening adb sideload...\n");
        ui->Print("Waiting adb sideload command...\n");
    }

    /* Thread for adb wipe */
    if (adb_wipe_data || adb_wipe_cache) {
        // must set show_text here
        ui->ShowText(true);

        typedef struct AdbWipe {
            int wipe_data;
            int wipe_cache;
        } T_AdbWipe;

        T_AdbWipe *adb_wipe =
            (T_AdbWipe *) calloc(1, sizeof(T_AdbWipe));
        if (adb_wipe == NULL) {
            LOGW("adb listeners calloc failed (%s)\n",
                strerror(errno));
            return;
        }
        adb_wipe->wipe_data = adb_wipe_data;
        adb_wipe->wipe_cache = adb_wipe_cache;

        if (pthread_create(&tid2, NULL,
            adb_wipe_listener_thread, (void *)adb_wipe)) {
            LOGW("create adb wipe listener thread (%s)\n",
                strerror(errno));
            kill(getpid(), SIGABRT);
        } else {
            // wait for killed
            pthread_join(tid2, NULL);
        }
    }
}
