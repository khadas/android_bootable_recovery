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
#include <sys/klog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <base/file.h>
#include <base/stringprintf.h>

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
#include "adb.h"
#include "fuse_sideload.h"
#include "fuse_sdcard_provider.h"

#include "ubootenv/set_display_mode.h"

#include "misc/misc.h"

extern "C" {
#include "ubootenv/uboot_env.h"
}




struct selabel_handle *sehandle;

static const struct option OPTIONS[] = {
  { "send_intent", required_argument, NULL, 'i' },
  { "update_package", required_argument, NULL, 'u' },

  { "wipe_data", no_argument, NULL, 'w' },

  { "wipe_cache", no_argument, NULL, 'c' },
#ifdef RECOVERY_HAS_PARAM
  { "wipe_param", no_argument, NULL, 'P' },
#endif /*RECOVERY_HAS_PARAM */
  { "show_text", no_argument, NULL, 't' },
  { "sideload", no_argument, NULL, 's' },
  { "sideload_auto_reboot", no_argument, NULL, 'a' },
  { "just_exit", no_argument, NULL, 'x' },
  { "locale", required_argument, NULL, 'l' },
  { "stages", required_argument, NULL, 'g' },
  { "shutdown_after", no_argument, NULL, 'p' },
  { "reason", required_argument, NULL, 'r' },
  { "force_stop", no_argument, NULL, 'f' },
  { "wipe_data_condition", no_argument, NULL, 'h' },
  { "update_patch", required_argument, NULL, 'e' },
  { "write_key", required_argument, NULL, 'k' },
  { "data_ro_wipe", no_argument, NULL, 'y' },
  { "setenv", required_argument, NULL, 'n' },
  { "getenv", required_argument, NULL, 'm' },
  { NULL, 0, NULL, 0 },
};

static const char *CACHE_LOG_DIR = "/cache/recovery";
static const char *COMMAND_FILE = "/cache/recovery/command";
static const char *INTENT_FILE = "/cache/recovery/intent";
static const char *LOG_FILE = "/cache/recovery/log";
static const char *LAST_INSTALL_FILE = "/cache/recovery/last_install";
static const char *LOCALE_FILE = "/cache/recovery/last_locale";
static const char *CACHE_ROOT = "/cache";
static const char *SDCARD_ROOT = "/sdcard";
static const char *UDISK_ROOT = "/udisk";
static const char *UDISK_COMMAND_FILE = "/udisk/factory_update_param.aml";
static const char *SDCARD_COMMAND_FILE = "/sdcard/factory_update_param.aml";
static const char *TEMPORARY_LOG_FILE = "/tmp/recovery.log";
static const char *TEMPORARY_INSTALL_FILE = "/tmp/last_install";
static const char *LAST_KMSG_FILE = "/cache/recovery/last_kmsg";
static const char *LAST_LOG_FILE = "/cache/recovery/last_log";
#ifdef RECOVERY_HAS_PARAM
    static const char *PARAM_ROOT = "/param";
#endif /* RECOVERY_HAS_PARAM */
static const int KEEP_LOG_COUNT = 10;

#define KEEP_LOG_COUNT 10

RecoveryUI* ui = NULL;
char* locale = NULL;
char* stage = NULL;
char* reason = NULL;
bool modified_flash = false;

#define  SAVE_MAX    (16)

char g_save_name[SAVE_MAX][PATH_MAX] = {0};

/*
 * The recovery tool communicates with the main system through /cache files.
 *   /cache/recovery/command - INPUT - command line for tool, one arg per line
 *   /cache/recovery/log - OUTPUT - combined log file from recovery run(s)
 *   /cache/recovery/intent - OUTPUT - intent that was passed in
 *
 * The arguments which may be supplied in the recovery.command file:
 *   --send_intent=anystring - write the text out to recovery.intent
 *   --update_package=path - verify install an OTA package file
 *   --wipe_data - erase user data (and cache), then reboot
 *   --wipe_cache - wipe cache (but not user data), then reboot
 *   --set_encrypted_filesystem=on|off - enables / diasables encrypted fs
 *   --just_exit - do nothing; exit and reboot
 *
 * After completing, we remove /cache/recovery/command and reboot.
 * Arguments may also be supplied in the bootloader control block (BCB).
 * These important scenarios must be safely restartable at any point:
 *
 * FACTORY RESET
 * 1. user selects "factory reset"
 * 2. main system writes "--wipe_data" to /cache/recovery/command
 * 3. main system reboots into recovery
 * 4. get_args() writes BCB with "boot-recovery" and "--wipe_data"
 *    -- after this, rebooting will restart the erase --
 * 5. erase_volume() reformats /data
 * 6. erase_volume() reformats /cache
 * 7. finish_recovery() erases BCB
 *    -- after this, rebooting will restart the main system --
 * 8. main() calls reboot() to boot main system
 *
 * OTA INSTALL
 * 1. main system downloads OTA package to /cache/some-filename.zip
 * 2. main system writes "--update_package=/cache/some-filename.zip"
 * 3. main system reboots into recovery
 * 4. get_args() writes BCB with "boot-recovery" and "--update_package=..."
 *    -- after this, rebooting will attempt to reinstall the update --
 * 5. install_package() attempts to install the update
 *    NOTE: the package install must itself be restartable from any point
 * 6. finish_recovery() erases BCB
 *    -- after this, rebooting will (try to) restart the main system --
 * 7. ** if install failed **
 *    7a. prompt_and_wait() shows an error icon and waits for the user
 *    7b; the user reboots (pulling the battery, etc) into the main system
 * 8. main() calls maybe_install_firmware_update()
 *    ** if the update contained radio/hboot firmware **:
 *    8a. m_i_f_u() writes BCB with "boot-recovery" and "--wipe_cache"
 *        -- after this, rebooting will reformat cache & restart main system --
 *    8b. m_i_f_u() writes firmware image into raw cache partition
 *    8c. m_i_f_u() writes BCB with "update-radio/hboot" and "--wipe_cache"
 *        -- after this, rebooting will attempt to reinstall firmware --
 *    8d. bootloader tries to flash firmware
 *    8e. bootloader writes BCB with "boot-recovery" (keeping "--wipe_cache")
 *        -- after this, rebooting will reformat cache & restart main system --
 *    8f. erase_volume() reformats /cache
 *    8g. finish_recovery() erases BCB
 *        -- after this, rebooting will (try to) restart the main system --
 * 9. main() calls reboot() to boot main system
 */

static const int MAX_ARG_LENGTH = 4096;
static const int MAX_ARGS = 100;

extern "C"
{
    extern int remoteinit(const char* path);
}

// open a given path, mounting partitions as necessary
FILE*
fopen_path(const char *path, const char *mode) {
    if (ensure_path_mounted(path) != 0) {
        LOGE("Can't mount %s\n", path);
        return NULL;
    }

    // When writing, try to create the containing directory, if necessary.
    // Use generous permissions, the system (init.rc) will reset them.
    if (strchr("wa", mode[0])) dirCreateHierarchy(path, 0777, NULL, 1, sehandle);

    FILE *fp = fopen(path, mode);
    return fp;
}

bool is_ro_debuggable() {
    char value[PROPERTY_VALUE_MAX+1];
    return (property_get("ro.debuggable", value, NULL) == 1 && value[0] == '1');
}

static void redirect_stdio(const char* filename) {
    // If these fail, there's not really anywhere to complain...
    freopen(filename, "a", stdout); setbuf(stdout, NULL);
    freopen(filename, "a", stderr); setbuf(stderr, NULL);
}

// close a file, log an error if the error indicator is set
static void
check_and_fclose(FILE *fp, const char *name) {
    fflush(fp);
    if (ferror(fp)) LOGE("Error in %s\n(%s)\n", name, strerror(errno));
    fclose(fp);
}

// command line args come from, in decreasing precedence:
//   - the actual command line
//   - the bootloader control block (one per line, after "recovery")
//   - the contents of COMMAND_FILE (one per line)
static void
get_args(int *argc, char ***argv) {
    struct bootloader_message boot;
    memset(&boot, 0, sizeof(boot));
    get_bootloader_message(&boot);  // this may fail, leaving a zeroed structure
    stage = strndup(boot.stage, sizeof(boot.stage));

    if (boot.command[0] != 0 && boot.command[0] != 255) {
        LOGI("Boot command: %.*s\n", (int)sizeof(boot.command), boot.command);
    }

    if (boot.status[0] != 0 && boot.status[0] != 255) {
        LOGI("Boot status: %.*s\n", (int)sizeof(boot.status), boot.status);
    }

    // --- if arguments weren't supplied, look in the bootloader control block
    if (*argc <= 1) {
        boot.recovery[sizeof(boot.recovery) - 1] = '\0';  // Ensure termination
        const char *arg = strtok(boot.recovery, "\n");
        if (arg != NULL && !strcmp(arg, "recovery")) {
            *argv = (char **) malloc(sizeof(char *) * MAX_ARGS);
            (*argv)[0] = strdup(arg);
            for (*argc = 1; *argc < MAX_ARGS; ++*argc) {
                if ((arg = strtok(NULL, "\n")) == NULL) break;
                (*argv)[*argc] = strdup(arg);
            }
            LOGI("Got arguments from boot message\n");
        } else if (boot.recovery[0] != 0 && boot.recovery[0] != 255) {
            LOGE("Bad boot message\n\"%.20s\"\n", boot.recovery);
        }
    }

    // --- if that doesn't work, try the command file form environment:recovery_command
    if (*argc <= 1) {
        char *parg = NULL;
        char *recovery_command = get_bootloader_env("recovery_command");
        if (recovery_command != NULL && strcmp(recovery_command, "")) {
            char *argv0 = (*argv)[0];
            *argv = (char **) malloc(sizeof(char *) * MAX_ARGS);
            (*argv)[0] = argv0;  // use the same program name

            char buf[MAX_ARG_LENGTH];
            strcpy(buf, recovery_command);

            if ((parg = strtok(buf, "#")) == NULL) {
                LOGE("Bad bootloader arguments\n\"%.20s\"\n", recovery_command);
            } else {
                (*argv)[1] = strdup(parg);  // Strip newline.
                for (*argc = 2; *argc < MAX_ARGS; ++*argc) {
                    if ((parg = strtok(NULL, "#")) == NULL) {
                        break;
                    } else {
                        (*argv)[*argc] = strdup(parg);  // Strip newline.
                    }
                }
                LOGI("Got arguments from bootloader\n");
            }
        } else {
            LOGE("Bad bootloader arguments\n\"%.20s\"\n", recovery_command);
        }
    }

    // --- if that doesn't work, try the command file
    char * temp_args = NULL;
    if (*argc <= 1) {
        FILE *fp = fopen_path(COMMAND_FILE, "r");
        if (fp != NULL) {
            char *argv0 = (*argv)[0];
            *argv = (char **) malloc(sizeof(char *) * MAX_ARGS);
            (*argv)[0] = argv0;  // use the same program name

            char buf[MAX_ARG_LENGTH];
            for (*argc = 1; *argc < MAX_ARGS; ) {
                if (!fgets(buf, sizeof(buf), fp)) break;
                temp_args = strtok(buf, "\r\n");
                if (temp_args == NULL)  continue;
                (*argv)[*argc]  = strdup(temp_args);   // Strip newline.
                ++*argc;
            }

            check_and_fclose(fp, COMMAND_FILE);
            LOGI("Got arguments from %s\n", COMMAND_FILE);
        }
    }

    // --- sleep 1 second to ensure SD card initialization complete
    usleep(1000000);

    // --- if that doesn't work, try the sdcard command file
    if (*argc <= 1) {
        FILE *fp = fopen_path(SDCARD_COMMAND_FILE, "r");
        if (fp != NULL) {
            char *argv0 = (*argv)[0];
            *argv = (char **) malloc(sizeof(char *) * MAX_ARGS);
            (*argv)[0] = argv0;  // use the same program name

            char buf[MAX_ARG_LENGTH];
            for (*argc = 1; *argc < MAX_ARGS; ) {
                if (!fgets(buf, sizeof(buf), fp)) break;
                temp_args = strtok(buf, "\r\n");
                if (temp_args == NULL)  continue;
                (*argv)[*argc]  = strdup(temp_args);  // Strip newline.
                ++*argc;
            }

            check_and_fclose(fp, SDCARD_COMMAND_FILE);
            LOGI("Got arguments from %s\n", SDCARD_COMMAND_FILE);
        }
    }

    // --- if that doesn't work, try the udisk command file
    if (*argc <= 1) {
        FILE *fp = fopen_path(UDISK_COMMAND_FILE, "r");
        if (fp != NULL) {
            char *argv0 = (*argv)[0];
            *argv = (char **) malloc(sizeof(char *) * MAX_ARGS);
            (*argv)[0] = argv0;  // use the same program name

            char buf[MAX_ARG_LENGTH];
            for (*argc = 1; *argc < MAX_ARGS; ) {
                if (!fgets(buf, sizeof(buf), fp)) break;
                temp_args = strtok(buf, "\r\n");
                if (temp_args == NULL)  continue;
                (*argv)[*argc]  = strdup(temp_args);   // Strip newline.
                ++*argc;
            }

            check_and_fclose(fp, UDISK_COMMAND_FILE);
            LOGI("Got arguments from %s\n", UDISK_COMMAND_FILE);
        }
    }

    // --- if no argument, then force show_text
    if (*argc <= 1) {
        char *argv0 = (*argv)[0];
        *argv = (char **) malloc(sizeof(char *) * MAX_ARGS);
        (*argv)[0] = argv0;  // use the same program name
        (*argv)[1] = (char *)"--show_text";
        *argc = 2;
    }

    // --> write the arguments we have back into the bootloader control block
    // always boot into recovery after this (until finish_recovery() is called)
    strlcpy(boot.command, "boot-recovery", sizeof(boot.command));
    strlcpy(boot.recovery, "recovery\n", sizeof(boot.recovery));
    int i;
    for (i = 1; i < *argc; ++i) {
        strlcat(boot.recovery, (*argv)[i], sizeof(boot.recovery));
        strlcat(boot.recovery, "\n", sizeof(boot.recovery));
    }
    set_bootloader_message(&boot);
}

static void
factory_reset_poweroff_protect(int *argc, char ***argv) {
    const char *param = NULL;
    const char *wipe_data = get_bootloader_env("wipe_data");
    const char *wipe_cache = get_bootloader_env("wipe_cache");
    const char *wipe_param = get_bootloader_env("wipe_param");
    const char *data_condition = get_bootloader_env("data_condition");

    if ((wipe_data != NULL) && !strcmp(wipe_data, "failed")) {
        if ((data_condition != NULL) && !strcmp(data_condition, "failed")) {
            param = "--wipe_data_condition";
        } else {
            param = "--wipe_data";
        }
    } else if((wipe_cache != NULL) && !strcmp(wipe_cache, "failed")) {
        param = "--wipe_cache";
    } else if((wipe_param != NULL) && !strcmp(wipe_param, "failed")) {
        param = "--wipe_param";
    }

    if (param != NULL) {
        bool force_stop = false;
        for (int i = 0; i < *argc; i++) {
            if (!strcmp((*argv)[i], "--force_stop")) {
                force_stop = true;
                break;
            }
        }
        char *argv0 = (*argv)[0];
        *argv = (char **) malloc(sizeof(char *) * MAX_ARGS);
        (*argv)[0] = argv0;  // use the same program name
        (*argv)[1] = (char *)param;
        if (!force_stop) {
            *argc = 2;
        } else {
            (*argv)[2] = (char *)"--force_stop";
            *argc = 3;
        }
    }
}

static void
factory_reset_poweroff_env_set(
    const char *volume, const int flag) {
    if (volume == NULL ||
        (strcmp(volume, "/data")&&strcmp(volume, "/param")&&strcmp(volume, "/cache")&&strcmp(volume, "/data_condition"))) {
        return;
    }
    const char *env_name = NULL;
    const char *env_val = flag ? "successful" : "failed";
    if (!strcmp(volume, "/cache")) {
        env_name = "wipe_cache";
    } else if (!strcmp(volume, "/param")){
        env_name = "wipe_param";
    } else {
        env_name = "wipe_data";
    }

    int ret = set_bootloader_env(env_name, env_val);
    printf("setenv %s=%s %s.(%d)\n", env_name, env_val,
        (ret < 0) ? "failed" : "successful", ret);

    if (!strcmp(volume, "/data_condition")) {
        env_name = "data_condition";
        ret = set_bootloader_env(env_name, env_val);
        printf("setenv %s=%s %s.(%d)\n", env_name, env_val,
            (ret < 0) ? "failed" : "successful", ret);
    }
}

static void
set_sdcard_update_bootloader_message() {
    struct bootloader_message boot;
    memset(&boot, 0, sizeof(boot));
    strlcpy(boot.command, "boot-recovery", sizeof(boot.command));
    strlcpy(boot.recovery, "recovery\n", sizeof(boot.recovery));
    set_bootloader_message(&boot);
}

// Read from kernel log into buffer and write out to file.
static void save_kernel_log(const char* destination) {
    int klog_buf_len = klogctl(KLOG_SIZE_BUFFER, 0, 0);
    if (klog_buf_len <= 0) {
        LOGE("Error getting klog size: %s\n", strerror(errno));
        return;
    }

    std::string buffer(klog_buf_len, 0);
    int n = klogctl(KLOG_READ_ALL, &buffer[0], klog_buf_len);
    if (n == -1) {
        LOGE("Error in reading klog: %s\n", strerror(errno));
        return;
    }
    buffer.resize(n);
    android::base::WriteStringToFile(buffer, destination);
}

// How much of the temp log we have copied to the copy in cache.
static long tmplog_offset = 0;

static void copy_log_file(const char* source, const char* destination, bool append) {
    FILE* dest_fp = fopen_path(destination, append ? "a" : "w");
    if (dest_fp == nullptr) {
        LOGE("Can't open %s\n", destination);
    } else {
        FILE* source_fp = fopen(source, "r");
        if (source_fp != nullptr) {
            if (append) {
                fseek(source_fp, tmplog_offset, SEEK_SET);  // Since last write
            }
            char buf[4096];
            size_t bytes;
            while ((bytes = fread(buf, 1, sizeof(buf), source_fp)) != 0) {
                fwrite(buf, 1, bytes, dest_fp);
            }
            if (append) {
                tmplog_offset = ftell(source_fp);
            }
            check_and_fclose(source_fp, source);
        }
        check_and_fclose(dest_fp, destination);
    }
}

// Rename last_log -> last_log.1 -> last_log.2 -> ... -> last_log.$max.
// Similarly rename last_kmsg -> last_kmsg.1 -> ... -> last_kmsg.$max.
// Overwrite any existing last_log.$max and last_kmsg.$max.
static void rotate_logs(int max) {
    // Logs should only be rotated once.
    static bool rotated = false;
    if (rotated) {
        return;
    }
    rotated = true;
    ensure_path_mounted(LAST_LOG_FILE);
    ensure_path_mounted(LAST_KMSG_FILE);

    for (int i = max-1; i >= 0; --i) {
        std::string old_log = android::base::StringPrintf((i == 0) ? "%s" : "%s.%d",
                LAST_LOG_FILE, i);
        std::string new_log = android::base::StringPrintf("%s.%d", LAST_LOG_FILE, i+1);
        // Ignore errors if old_log doesn't exist.
        rename(old_log.c_str(), new_log.c_str());

        std::string old_kmsg = android::base::StringPrintf((i == 0) ? "%s" : "%s.%d",
                LAST_KMSG_FILE, i);
        std::string new_kmsg = android::base::StringPrintf("%s.%d", LAST_KMSG_FILE, i+1);
        rename(old_kmsg.c_str(), new_kmsg.c_str());
    }
}

static void copy_logs() {
    // We only rotate and record the log of the current session if there are
    // actual attempts to modify the flash, such as wipes, installs from BCB
    // or menu selections. This is to avoid unnecessary rotation (and
    // possible deletion) of log files, if it does not do anything loggable.
    if (!modified_flash) {
        return;
    }

    rotate_logs(KEEP_LOG_COUNT);

    // Copy logs to cache so the system can find out what happened.
    copy_log_file(TEMPORARY_LOG_FILE, LOG_FILE, true);
    copy_log_file(TEMPORARY_LOG_FILE, LAST_LOG_FILE, false);
    copy_log_file(TEMPORARY_INSTALL_FILE, LAST_INSTALL_FILE, false);
    save_kernel_log(LAST_KMSG_FILE);
    chmod(LOG_FILE, 0600);
    chown(LOG_FILE, 1000, 1000);   // system user
    chmod(LAST_KMSG_FILE, 0600);
    chown(LAST_KMSG_FILE, 1000, 1000);   // system user
    chmod(LAST_LOG_FILE, 0640);
    chmod(LAST_INSTALL_FILE, 0644);
    sync();
}

// clear the recovery command and prepare to boot a (hopefully working) system,
// copy our log file to cache as well (for the system to read), and
// record any intent we were asked to communicate back to the system.
// this function is idempotent: call it as many times as you like.
static void
finish_recovery(const char *send_intent) {
    // By this point, we're ready to return to the main system...
    if (send_intent != NULL) {
        FILE *fp = fopen_path(INTENT_FILE, "w");
        if (fp == NULL) {
            LOGE("Can't open %s\n", INTENT_FILE);
        } else {
            fputs(send_intent, fp);
            check_and_fclose(fp, INTENT_FILE);
        }
    }

    // Save the locale to cache, so if recovery is next started up
    // without a --locale argument (eg, directly from the bootloader)
    // it will use the last-known locale.
    if (locale != NULL) {
        LOGI("Saving locale \"%s\"\n", locale);
        FILE* fp = fopen_path(LOCALE_FILE, "w");
        fwrite(locale, 1, strlen(locale), fp);
        fflush(fp);
        fsync(fileno(fp));
        check_and_fclose(fp, LOCALE_FILE);
    }

    copy_logs();

    // Reset to normal system boot so recovery won't cycle indefinitely.
    struct bootloader_message boot;
    memset(&boot, 0, sizeof(boot));
    set_bootloader_message(&boot);

    // Remove the command file, so recovery won't repeat indefinitely.
    if (ensure_path_mounted(COMMAND_FILE) != 0 ||
        (unlink(COMMAND_FILE) && errno != ENOENT)) {
        LOGW("Can't unlink %s\n", COMMAND_FILE);
    }

    ensure_path_unmounted(CACHE_ROOT);
    sync();  // For good measure.
}

static unsigned char *
remove_unshow_char(unsigned char *s) {
    unsigned char *s1=s;
    unsigned char *s2=s;

    while (*s1) {
        if (*s1 > 0x20) {
            *s2 = *s1;
            s2++;
        }
        s1++;
    }
    *s2 = 0;
    return s;
}

static int
check_name(const char *pname, int num) {
    int i = 0;
    int ret = -1;

    for (i=0; i<num; i++) {
        if (strcmp(pname, g_save_name[i]) == 0) {
            ret = 0;
            break;
        }
    }

    return ret;
}


static int
get_erase_conf_list(int *num, const char *path) {
    FILE *fp = NULL;
    int filenum = 0;
    char buf[128+1];
    char *str = NULL;
    char *key = NULL;
    char *value_s = NULL;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(buf,128, fp)) {
        if (strstr(buf, "#") != NULL) {
            continue;
        }

        str = (char *)remove_unshow_char((unsigned char *)buf);
        key = strtok(str, "=");
        if ( key && (value_s=strtok(NULL, "="))) {
            int value=atoi(value_s);
            if (value == 1) {
                printf("need save dir:%s\n",key);
                memcpy(g_save_name[filenum], key, strlen(key));
                filenum++;
                if (filenum == SAVE_MAX) {
                    break;
                }
            }
        }
    }

     *num = filenum;
    fclose(fp);
    return 0;
}

typedef struct _saved_log_file {
    char* name;
    struct stat st;
    unsigned char* data;
    struct _saved_log_file* next;
} saved_log_file;

static bool erase_volume(const char* volume) {
    factory_reset_poweroff_env_set(volume, 0);

    bool is_cache = (strcmp(volume, CACHE_ROOT) == 0);

    ui->SetBackground(RecoveryUI::ERASING);
    ui->SetProgressType(RecoveryUI::INDETERMINATE);

    saved_log_file* head = NULL;

    if (is_cache) {
        // If we're reformatting /cache, we load any past logs
        // (i.e. "/cache/recovery/last_*") and the current log
        // ("/cache/recovery/log") into memory, so we can restore them after
        // the reformat.

        ensure_path_mounted(volume);

        DIR* d;
        struct dirent* de;
        d = opendir(CACHE_LOG_DIR);
        if (d) {
            char path[PATH_MAX];
            strcpy(path, CACHE_LOG_DIR);
            strcat(path, "/");
            int path_len = strlen(path);
            while ((de = readdir(d)) != NULL) {
                if (strncmp(de->d_name, "last_", 5) == 0 || strcmp(de->d_name, "log") == 0) {
                    saved_log_file* p = (saved_log_file*) malloc(sizeof(saved_log_file));
                    strcpy(path+path_len, de->d_name);
                    p->name = strdup(path);
                    if (stat(path, &(p->st)) == 0) {
                        // truncate files to 512kb
                        if (p->st.st_size > (1 << 19)) {
                            p->st.st_size = 1 << 19;
                        }
                        p->data = (unsigned char*) malloc(p->st.st_size);
                        FILE* f = fopen(path, "rb");
                        fread(p->data, 1, p->st.st_size, f);
                        fclose(f);
                        p->next = head;
                        head = p;
                    } else {
                        free(p);
                    }
                }
            }
            closedir(d);
        } else {
            if (errno != ENOENT) {
                printf("opendir failed: %s\n", strerror(errno));
            }
        }
    }

    ui->Print("Formatting %s...\n", volume);

    ensure_path_unmounted(volume);
    int result = format_volume(volume);

    if (is_cache) {
        while (head) {
            FILE* f = fopen_path(head->name, "wb");
            if (f) {
                fwrite(head->data, 1, head->st.st_size, f);
                fclose(f);
                chmod(head->name, head->st.st_mode);
                chown(head->name, head->st.st_uid, head->st.st_gid);
            }
            free(head->name);
            free(head->data);
            saved_log_file* temp = head->next;
            free(head);
            head = temp;
        }

        // Any part of the log we'd copied to cache is now gone.
        // Reset the pointer so we copy from the beginning of the temp
        // log.
        tmplog_offset = 0;
        copy_logs();
    }

    factory_reset_poweroff_env_set(volume, 1);

    return (result == 0);
}


static int
dirUnlinkCondition(const char *s_path, int num)
{
    int flag = 0;
    int result = 0;
    char tmp_path[PATH_MAX] ={0};
    DIR *dir_s = NULL;
    struct stat st;
    struct dirent *sp = NULL;

    dir_s = opendir(s_path);
    if (dir_s == NULL)
    {
        printf("This directory don't exist !s_path:%s\n", s_path);
        return -1;
    }

    strcpy(tmp_path,s_path);

    while ((sp=readdir(dir_s)) != NULL) {
        if ((strcmp(sp->d_name,".") != 0) && (strcmp(sp->d_name,"..") != 0)) {
             strcat(tmp_path,"/");
             strcat(tmp_path,sp->d_name);

            /* is it a file or directory? */
            if (lstat(tmp_path, &st) < 0) {
                return -1;
            }

            /* a file, so unlink it */
            if (!S_ISDIR(st.st_mode)) {
                result = check_name(tmp_path, num);
                if (result != 0) {
                    printf("rm file %s\n", tmp_path);
                    unlink(tmp_path);
                } else {
                    flag=1;
                }
                strcpy(tmp_path,s_path);
                continue;
            }

            result = check_name(tmp_path, num);
            if (result == 0) {
                flag=1;
                strcpy(tmp_path,s_path);
                continue;
            }

            result = dirUnlinkCondition(tmp_path, num);
            if (result != 0) {
                closedir(dir_s);
                return -1;
            }

            strcpy(tmp_path,s_path);
        }
    }

    if (closedir(dir_s) < 0) {
        return -1;
    }

    if (flag != 1) {
        printf("rm dir %s\n", tmp_path);
        rmdir(s_path);
    }

    return 0;
}



static int
erase_data_condition(const char *s_path) {
    int num = 0;
    int result = 0;

    if (!s_path) {
        printf("ERR:the %s for erase is NULL! \n", s_path);
        return -1;
    }

    result = get_erase_conf_list(&num, "/res/wipe_data.cfg");
    if (result != 0) {
        ui->Print("get erase config file failed!\n");
    }

    factory_reset_poweroff_env_set("/data_condition", 0);

    ui->Print("Formatting %s...\n", s_path);
    ensure_path_mounted(s_path);

    result = dirUnlinkCondition(s_path, num);

    ensure_path_unmounted(s_path);

    factory_reset_poweroff_env_set("/data_condition", 1);
    return result;
}


static int
get_menu_selection(const char* const * headers, const char* const * items,
                   int menu_only, int initial_selection, Device* device) {
    // throw away keys pressed previously, so user doesn't
    // accidentally trigger menu items.
    ui->FlushKeys();

    ui->StartMenu(headers, items, initial_selection);
    int selected = initial_selection;
    int chosen_item = -1;

    while (chosen_item < 0) {
        int key = ui->WaitKey();
        int visible = ui->IsTextVisible();

        if (key == -1) {   // ui_wait_key() timed out
            if (ui->WasTextEverVisible()) {
                continue;
            } else {
                LOGI("timed out waiting for key input; rebooting.\n");
                ui->EndMenu();
                return 0; // XXX fixme
            }
        }

        int action = device->HandleMenuKey(key, visible);

        if (action < 0) {
            switch (action) {
                case Device::kHighlightUp:
                    selected = ui->SelectMenu(--selected);
                    break;
                case Device::kHighlightDown:
                    selected = ui->SelectMenu(++selected);
                    break;
                case Device::kInvokeItem:
                    chosen_item = selected;
                    break;
                case Device::kNoAction:
                    break;
            }
        } else if (!menu_only) {
            chosen_item = action;
        }
    }

    ui->EndMenu();
    return chosen_item;
}

static int compare_string(const void* a, const void* b) {
    return strcmp(*(const char**)a, *(const char**)b);
}

// Returns a malloc'd path, or NULL.
static char* browse_directory(const char* path, Device* device) {
    ensure_path_mounted(path);

    DIR* d = opendir(path);
    if (d == NULL) {
        LOGE("error opening %s: %s\n", path, strerror(errno));
        return NULL;
    }

    int d_size = 0;
    int d_alloc = 10;
    char** dirs = (char**)malloc(d_alloc * sizeof(char*));
    int z_size = 1;
    int z_alloc = 10;
    char** zips = (char**)malloc(z_alloc * sizeof(char*));
    zips[0] = strdup("../");

    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        int name_len = strlen(de->d_name);

        if (de->d_type == DT_DIR) {
            // skip "." and ".." entries
            if (name_len == 1 && de->d_name[0] == '.') continue;
            if (name_len == 2 && de->d_name[0] == '.' &&
                de->d_name[1] == '.') continue;

            if (d_size >= d_alloc) {
                d_alloc *= 2;
                dirs = (char**)realloc(dirs, d_alloc * sizeof(char*));
            }
            dirs[d_size] = (char*)malloc(name_len + 2);
            strcpy(dirs[d_size], de->d_name);
            dirs[d_size][name_len] = '/';
            dirs[d_size][name_len+1] = '\0';
            ++d_size;
        } else if (de->d_type == DT_REG &&
                   name_len >= 4 &&
                   strncasecmp(de->d_name + (name_len-4), ".zip", 4) == 0) {
            if (z_size >= z_alloc) {
                z_alloc *= 2;
                zips = (char**)realloc(zips, z_alloc * sizeof(char*));
            }
            zips[z_size++] = strdup(de->d_name);
        }
    }
    closedir(d);

    qsort(dirs, d_size, sizeof(char*), compare_string);
    qsort(zips, z_size, sizeof(char*), compare_string);

    // append dirs to the zips list
    if (d_size + z_size + 1 > z_alloc) {
        z_alloc = d_size + z_size + 1;
        zips = (char**)realloc(zips, z_alloc * sizeof(char*));
    }
    memcpy(zips + z_size, dirs, d_size * sizeof(char*));
    free(dirs);
    z_size += d_size;
    zips[z_size] = NULL;

    const char* headers[] = { "Choose a package to install:", path, NULL };

    char* result;
    int chosen_item = 0;
    while (true) {
        chosen_item = get_menu_selection(headers, zips, 1, chosen_item, device);

        char* item = zips[chosen_item];
        int item_len = strlen(item);
        if (chosen_item == 0) {          // item 0 is always "../"
            // go up but continue browsing (if the caller is update_directory)
            result = NULL;
            break;
        }

        char new_path[PATH_MAX];
        strlcpy(new_path, path, PATH_MAX);
        strlcat(new_path, "/", PATH_MAX);
        strlcat(new_path, item, PATH_MAX);

        if (item[item_len-1] == '/') {
            // recurse down into a subdirectory
            new_path[strlen(new_path)-1] = '\0';  // truncate the trailing '/'
            result = browse_directory(new_path, device);
            if (result) break;
        } else {
            // selected a zip file: return the malloc'd path to the caller.
            result = strdup(new_path);
            break;
        }
    }

    for (int i = 0; i < z_size; ++i) free(zips[i]);
    free(zips);

    return result;
}

static void file_to_ui(const char* fn) {
    FILE *fp = fopen_path(fn, "re");
    if (fp == NULL) {
        ui->Print("  Unable to open %s: %s\n", fn, strerror(errno));
        return;
	}
}

static bool yes_no(Device* device, const char* question1, const char* question2) {
    const char* headers[] = { question1, question2, NULL };
    const char* items[] = { " No", " Yes", NULL };

    int chosen_item = get_menu_selection(headers, items, 1, 0, device);
    return (chosen_item == 1);
}

// Return true on success.
static bool wipe_data(int should_confirm, Device* device) {
    if (should_confirm && !yes_no(device, "Wipe all user data?", "  THIS CAN NOT BE UNDONE!")) {
        return false;
    }

    modified_flash = true;

    ui->Print("\n-- Wiping data...\n");
    instaboot_clear();

    bool success =
        device->PreWipeData() &&
        erase_volume("/data") &&
        erase_volume("/cache") &&
#ifdef RECOVERY_HAS_PARAM
        erase_volume("/param") &&
#endif
        device->PostWipeData();
    ui->Print("Data wipe %s.\n", success ? "complete" : "failed");
    return success;
}

// Return true on success.
static bool wipe_data_with_headers(
    int should_confirm, Device* device, const char* title[]) {
    char** headers = NULL;
    if (should_confirm) {
        const char* items[] = { " No", " Yes", NULL };
        const char* default_headers[] = {
            "Wipe all user data?", "  THIS CAN NOT BE UNDONE!", NULL };
        headers = (title != NULL) ? (char **)title : (char **)default_headers;
        int chosen_item = get_menu_selection(headers, items, 1, 0, device);
        if (chosen_item != 1) {
            return false;
        }
    }

    modified_flash = true;

    ui->Print("\n-- Wiping data...\n");
    instaboot_clear();

    bool success =
        device->PreWipeData() &&
        erase_volume("/data") &&
        erase_volume("/cache") &&
        device->PostWipeData();
    ui->Print("Data wipe %s.\n", success ? "complete" : "failed");
    return success;
}

// Return true on success.
static bool wipe_cache(bool should_confirm, Device* device) {
    if (should_confirm && !yes_no(device, "Wipe cache?", "  THIS CAN NOT BE UNDONE!")) {
        return false;
    }

    modified_flash = true;

    ui->Print("\n-- Wiping cache...\n");
    bool success = erase_volume("/cache");
    ui->Print("Cache wipe %s.\n", success ? "complete" : "failed");
    return success;
}

static void choose_recovery_file(Device* device) {
    // "Back" + KEEP_LOG_COUNT * 2 + terminating nullptr entry
    char* entries[1 + KEEP_LOG_COUNT * 2 + 1];
    memset(entries, 0, sizeof(entries));

    unsigned int n = 0;

    // Add LAST_LOG_FILE + LAST_LOG_FILE.x
    // Add LAST_KMSG_FILE + LAST_KMSG_FILE.x
    for (int i = 0; i < KEEP_LOG_COUNT; i++) {
        char* log_file;
        if (asprintf(&log_file, (i == 0) ? "%s" : "%s.%d", LAST_LOG_FILE, i) == -1) {
            // memory allocation failure - return early. Should never happen.
            return;
        }
        if ((ensure_path_mounted(log_file) != 0) || (access(log_file, R_OK) == -1)) {
            free(log_file);
        } else {
            entries[n++] = log_file;
        }

        char* kmsg_file;
        if (asprintf(&kmsg_file, (i == 0) ? "%s" : "%s.%d", LAST_KMSG_FILE, i) == -1) {
            // memory allocation failure - return early. Should never happen.
            return;
        }
        if ((ensure_path_mounted(kmsg_file) != 0) || (access(kmsg_file, R_OK) == -1)) {
            free(kmsg_file);
        } else {
            entries[n++] = kmsg_file;
        }
    }

    entries[n++] = strdup("Back");

    const char* headers[] = { "Select file to view", nullptr };

    while (true) {
        int chosen_item = get_menu_selection(headers, entries, 1, 0, device);
        if (strcmp(entries[chosen_item], "Back") == 0) break;

        // TODO: do we need to redirect? ShowFile could just avoid writing to stdio.
        redirect_stdio("/dev/null");
        ui->ShowFile(entries[chosen_item]);
        redirect_stdio(TEMPORARY_LOG_FILE);
    }

    for (size_t i = 0; i < (sizeof(entries) / sizeof(*entries)); i++) {
        free(entries[i]);
    }
}

static int ext_update(Device* device, bool wipe_cache) {
    int status = 0;
    int found_upgrade = 0;
    char* update_package = NULL;
    const char** title_headers = NULL;
    const char* headers[] = { "Confirm update?",
                    "  THIS CAN NOT BE UNDONE.",
                    "",
                    NULL };
    const char* items[] = { " ../",
                    " Update from sdcard",
                    " Update from udisk",
                    NULL };


    int chosen_item = get_menu_selection(nullptr, items, 1, 0, device);
        if (chosen_item != 1 && chosen_item != 2){
        return 1;
    }

    switch(chosen_item) {
        case 1:
            // Some packages expect /cache to be mounted (eg,
            // standard incremental packages expect to use /cache
            // as scratch space).
            ensure_path_mounted(CACHE_ROOT);
            ensure_path_unmounted(SDCARD_ROOT); // umount, if pull card and then insert card
            ensure_path_mounted(SDCARD_ROOT);
            update_package = browse_directory(SDCARD_ROOT, device);
            if (update_package == NULL) {
                ui->Print("\n-- No package file selected.\n", update_package);
                break;
            }
            found_upgrade = 1;
            break;

        case 2:
            ensure_path_mounted(CACHE_ROOT);
            ensure_path_unmounted(UDISK_ROOT);
            ensure_path_mounted(UDISK_ROOT);
            update_package = browse_directory(UDISK_ROOT, device);
            if (update_package == NULL) {
                ui->Print("\n-- No package file selected.\n", update_package);
                break;
            }
            found_upgrade = 2;
            break;
    }

    if (!found_upgrade) return 1;

    ui->Print("\n-- Install %s ...\n", update_package);
    set_sdcard_update_bootloader_message();
    instaboot_disable();
    instaboot_clear();
    status = install_package(update_package, &wipe_cache, TEMPORARY_INSTALL_FILE, true);

    if (status == INSTALL_SUCCESS && wipe_cache) {
        ui->Print("\n-- Wiping cache (at package request)...\n");
        if (erase_volume("/cache")) {
            ui->Print("Cache wipe failed.\n");
        } else {
            ui->Print("Cache wipe complete.\n");
        }
    }

    if (status >= 0) {
        if (status != INSTALL_SUCCESS) {
            ui->SetBackground(RecoveryUI::ERROR);
            ui->Print("Installation aborted.\n");
        } else if (!ui->IsTextVisible()) {
            return 0;   // reboot if logs aren't visible
        } else {
            ui->Print("\nInstall from %s complete.\n",
                (found_upgrade == 1) ? "sdcard" : "udisk");
        }
    }

    return 1;
}

static int cache_update(Device* device, bool wipe_cache) {
    int status = 0;
    char *update_package = browse_directory(CACHE_ROOT, device);
    if (update_package == NULL) {
        ui->Print("\n-- No package file selected.\n", update_package);
        return 1;
    }

    ui->Print("\n-- Install %s ...\n", update_package);
    set_sdcard_update_bootloader_message();
    instaboot_disable();
    instaboot_clear();
    status = install_package(update_package, &wipe_cache, TEMPORARY_INSTALL_FILE, true);
    if (status == INSTALL_SUCCESS && wipe_cache) {
        ui->Print("\n-- Wiping cache (at package request)...\n");
        if (erase_volume("/cache")) {
            ui->Print("Cache wipe failed.\n");
        } else {
            ui->Print("Cache wipe complete.\n");
        }
    }

    if (status >= 0) {
        if (status != INSTALL_SUCCESS) {
            ui->SetBackground(RecoveryUI::ERROR);
            ui->Print("Installation aborted.\n");
        } else if (!ui->IsTextVisible()) {
            return 0;   // reboot if logs aren't visible
        } else {
            ui->Print("\nInstall from cache complete.\n");
        }
    }

    return 1;
}

static int apply_from_sdcard(Device* device, bool* wipe_cache) {
    modified_flash = true;

    if (ensure_path_mounted(SDCARD_ROOT) != 0) {
        ui->Print("\n-- Couldn't mount %s.\n", SDCARD_ROOT);
        return INSTALL_ERROR;
    }

    char* path = browse_directory(SDCARD_ROOT, device);
    if (path == NULL) {
        ui->Print("\n-- No package file selected.\n");
        return INSTALL_ERROR;
    }

    ui->Print("\n-- Install %s ...\n", path);
    set_sdcard_update_bootloader_message();
    void* token = start_sdcard_fuse(path);

    int status = install_package(FUSE_SIDELOAD_HOST_PATHNAME, wipe_cache,
                                 TEMPORARY_INSTALL_FILE, false);

    finish_sdcard_fuse(token);
    ensure_path_unmounted(SDCARD_ROOT);
    return status;
}

// Return REBOOT, SHUTDOWN, or REBOOT_BOOTLOADER.  Returning NO_ACTION
// means to take the default, which is to reboot or shutdown depending
// on if the --shutdown_after flag was passed to recovery.
static Device::BuiltinAction
prompt_and_wait(Device* device, int status) {
    for (;;) {
        finish_recovery(NULL);
        switch (status) {
            case INSTALL_SUCCESS:
            case INSTALL_NONE:
                ui->SetBackground(RecoveryUI::NO_COMMAND);
                break;

            case INSTALL_ERROR:
            case INSTALL_CORRUPT:
                ui->SetBackground(RecoveryUI::ERROR);
                break;
        }
        ui->SetProgressType(RecoveryUI::EMPTY);

        int chosen_item = get_menu_selection(nullptr, device->GetMenuItems(), 0, 0, device);

        // device-specific code may take some action here.  It may
        // return one of the core actions handled in the switch
        // statement below.
        Device::BuiltinAction chosen_action = device->InvokeMenuItem(chosen_item);

        bool should_wipe_cache = false;
        switch (chosen_action) {
            case Device::NO_ACTION:
                break;

            case Device::REBOOT:
            case Device::SHUTDOWN:
            case Device::REBOOT_BOOTLOADER:
                return chosen_action;

            case Device::WIPE_DATA:
                wipe_data(ui->IsTextVisible(), device);
                if (!ui->IsTextVisible()) return Device::NO_ACTION;
                break;

            case Device::WIPE_CACHE:
                wipe_cache(ui->IsTextVisible(), device);
                if (!ui->IsTextVisible()) return Device::NO_ACTION;
                break;
#ifdef RECOVERY_HAS_PARAM
                case Device::WIPE_PARAM:
                    ui->Print("\n-- Wiping param...\n");
                    erase_volume("/param");
                    ui->Print("Param wipe complete.\n");
                    if (!ui->IsTextVisible()) return Device::NO_ACTION;
                    break;
#endif /* RECOVERY_HAS_PARAM */

            case Device::APPLY_EXT:
                ext_update(device, should_wipe_cache);
                break;

            case Device::APPLY_CACHE:
                if (!cache_update(device, should_wipe_cache))
                    return Device::NO_ACTION;
                break;

            case Device::APPLY_ADB_SIDELOAD:
                {
                    bool adb = (chosen_action == Device::APPLY_ADB_SIDELOAD);
                    if (adb) {
                        status = apply_from_adb(ui, &should_wipe_cache, TEMPORARY_INSTALL_FILE);
                    } else {
                        status = apply_from_sdcard(device, &should_wipe_cache);
                    }

                    if (status == INSTALL_SUCCESS && should_wipe_cache) {
                        if (!wipe_cache(false, device)) {
                            status = INSTALL_ERROR;
                        }
                    }

                    if (status != INSTALL_SUCCESS) {
                        ui->SetBackground(RecoveryUI::ERROR);
                        ui->Print("Installation aborted.\n");
                        copy_logs();
                    } else if (!ui->IsTextVisible()) {
                        return Device::NO_ACTION;  // reboot if logs aren't visible
                    } else {
                        ui->Print("\nInstall from %s complete.\n", adb ? "ADB" : "SD card");
                    }
                }
                break;

            case Device::VIEW_RECOVERY_LOGS:
                choose_recovery_file(device);
                break;

            case Device::MOUNT_SYSTEM:
                if (ensure_path_mounted("/system") != -1) {
                    ui->Print("Mounted /system.\n");
                }
                break;
        }
    }
}

static void
print_property(const char *key, const char *name, void *cookie) {
    printf("%s=%s\n", key, name);
}

static void
load_locale_from_cache() {
    FILE* fp = fopen_path(LOCALE_FILE, "r");
    char buffer[80];
    if (fp != NULL) {
        fgets(buffer, sizeof(buffer), fp);
        int j = 0;
        unsigned int i;
        for (i = 0; i < sizeof(buffer) && buffer[i]; ++i) {
            if (!isspace(buffer[i])) {
                buffer[j++] = buffer[i];
            }
        }
        buffer[j] = 0;
        locale = strdup(buffer);
        check_and_fclose(fp, LOCALE_FILE);
    }
}

static RecoveryUI* gCurrentUI = NULL;

void
ui_print(const char* format, ...) {
    char buffer[256];

    va_list ap;
    va_start(ap, format);
    vsnprintf(buffer, sizeof(buffer), format, ap);
    va_end(ap);

    if (gCurrentUI != NULL) {
        gCurrentUI->Print("%s", buffer);
    } else {
        fputs(buffer, stdout);
    }
}

void
adb_copy_logs(void) {
    copy_logs();
}

int
adb_erase_volume(const char *volume) {
    return erase_volume(volume);
}

int
main(int argc, char **argv) {
    time_t start = time(NULL);
    redirect_stdio(TEMPORARY_LOG_FILE);

    set_display_mode("/etc/mesondisplay.cfg");
    remoteinit("/etc/remote.conf");

    // If this binary is started with the single argument "--adbd",
    // instead of being the normal recovery binary, it turns into kind
    // of a stripped-down version of adbd that only supports the
    // 'sideload' command.  Note this must be a real argument, not
    // anything in the command file or bootloader control block; the
    // only way recovery should be run with this argument is when it
    // starts a copy of itself from the apply_from_adb() function.
    if (argc == 2 && strcmp(argv[1], "--adbd") == 0) {
        adb_main(0, DEFAULT_ADB_PORT);
        return 0;
    }

    printf("Starting recovery (pid %d) on %s", getpid(), ctime(&start));

    load_volume_table();
    get_args(&argc, &argv);
    factory_reset_poweroff_protect(&argc, &argv);

    const char *send_intent = NULL;
    const char *update_package = NULL;

    bool should_wipe_data = false;
    bool should_wipe_cache = false;
    bool show_text = false;
    bool sideload = false;
    bool sideload_auto_reboot = false;
    bool wipe_data_condition = false;
    const char *update_patch = NULL;
    bool force_stop = false;
#ifdef RECOVERY_HAS_PARAM
    int wipe_param = 0;
#endif /* RECOVERY_HAS_PARAM */
    bool just_exit = false;
    bool shutdown_after = false;
    char *key_optarg = NULL;
    char *env_set = NULL;
    char *env_get = NULL;
    int data_ro_wipe = 0;

    int arg;
    while ((arg = getopt_long(argc, argv, "", OPTIONS, NULL)) != -1) {
        switch (arg) {
        case 'i': send_intent = optarg; break;
        case 'u': update_package = optarg; break;
        case 'w': should_wipe_data = true; break;
        case 'c': should_wipe_cache = true; break;
        case 't': show_text = true; break;
        case 's': sideload = true; break;
        case 'a': sideload = true; sideload_auto_reboot = true; break;
        case 'x': just_exit = true; break;
        case 'l': locale = optarg; break;
        case 'h': wipe_data_condition = should_wipe_cache = true; break;
        case 'e': update_patch = optarg; break;
        case 'k': key_optarg = optarg; break;
        case 'f': force_stop = true; break;
        case 'y': data_ro_wipe = 1; break;
#ifdef RECOVERY_HAS_PARAM
        case 'P': wipe_param = 1; break;
#endif /* RECOVERY_HAS_PARAM */
        case 'g': {
            if (stage == NULL || *stage == '\0') {
                char buffer[20] = "1/";
                strncat(buffer, optarg, sizeof(buffer)-3);
                stage = strdup(buffer);
            }
            break;
        }
        case 'p': shutdown_after = true; break;
        case 'r': reason = optarg; break;
        case 'n': env_set = optarg; break;
        case 'm': env_get = optarg; break;
        case '?':
            LOGE("Invalid command argument\n");
            continue;
        }
    }

    if (locale == NULL) {
        load_locale_from_cache();
    }
    printf("locale is [%s]\n", locale);
    printf("stage is [%s]\n", stage);
    printf("reason is [%s]\n", reason);

    Device* device = make_device();
    ui = device->GetUI();
    gCurrentUI = ui;

    ui->SetLocale(locale);
    ui->Init();

    int st_cur, st_max;
    if (stage != NULL && sscanf(stage, "%d/%d", &st_cur, &st_max) == 2) {
        ui->SetStage(st_cur, st_max);
    }

    ui->SetBackground(RecoveryUI::NONE);
    if (show_text) ui->ShowText(true);

    struct selinux_opt seopts[] = {
      { SELABEL_OPT_PATH, "/file_contexts" }
    };

    sehandle = selabel_open(SELABEL_CTX_FILE, seopts, 1);

    if (!sehandle) {
        ui->Print("Warning: No file_contexts\n");
    }

    device->StartRecovery();

    printf("Command:");
    for (arg = 0; arg < argc; arg++) {
        printf(" \"%s\"", argv[arg]);
    }
    printf("\n");

    if (update_package) {
        // For backwards compatibility on the cache partition only, if
        // we're given an old 'root' path "CACHE:foo", change it to
        // "/cache/foo".
        if (strncmp(update_package, "CACHE:", 6) == 0) {
            int len = strlen(update_package) + 10;
            char* modified_path = (char*)malloc(len);
            strlcpy(modified_path, "/cache/", len);
            strlcat(modified_path, update_package+6, len);
            printf("(replacing path \"%s\" with \"%s\")\n",
                   update_package, modified_path);
            update_package = modified_path;
        }
    }
    printf("\n");

    property_list(print_property, NULL);
    printf("\n");

    ui->Print("Supported API: %d\n", RECOVERY_API_VERSION);

    int status = INSTALL_SUCCESS;

    if (update_package != NULL) {

        instaboot_disable();
        instaboot_clear();
        status = install_package(update_package, &should_wipe_cache, TEMPORARY_INSTALL_FILE, true);
        if (status == INSTALL_SUCCESS && should_wipe_cache) {
            wipe_cache(false, device);
        }
        if (status != INSTALL_SUCCESS) {
            ui->Print("Installation aborted.\n");
            ui->Print("OTA failed! Please power off the device to keep it in this state and file a bug report!\n");

            // If this is an eng or userdebug build, then automatically
            // turn the text display on if the script fails so the error
            // message is visible.
            if (is_ro_debuggable()) {
                ui->ShowText(true);
            }
        }
    }

    if (update_patch != NULL) {
        instaboot_disable();
        instaboot_clear();
        status = install_package(update_patch, &should_wipe_cache, TEMPORARY_INSTALL_FILE, true);
        if (status != INSTALL_SUCCESS) {
            ui->Print("Installation aborted.\n");

            // If this is an eng or userdebug build, then automatically
            // turn the text display on if the script fails so the error
            // message is visible.
            char buffer[PROPERTY_VALUE_MAX+1];
            property_get("ro.build.fingerprint", buffer, "");
            if (strstr(buffer, ":userdebug/") || strstr(buffer, ":eng/")) {
                ui->ShowText(true);
            }
        }
    }

#ifdef RECOVERY_HAS_PARAM
    if (wipe_param) {
        if (wipe_param && erase_volume(PARAM_ROOT)) status = INSTALL_ERROR;
        if (status != INSTALL_SUCCESS) ui->Print("Param wipe failed.\n");
    }
#endif /* RECOVERY_HAS_PARAM */

    // Recovery write keys
    if (key_optarg != NULL) {
        if (RecoveryWriteKey(key_optarg) < 0) {
            ui->Print("Write key failed.\n");
            ui->ShowText(true);
        } else {
            ui->Print("Write key complete.\n");
        }
     } else if (wipe_data_condition) {
        instaboot_clear();
        if (erase_data_condition("/data")) status = INSTALL_ERROR;
        if (!wipe_cache(false, device)) {
            status = INSTALL_ERROR;
        }
    } else if (should_wipe_data) {
        if (!wipe_data(false, device)) {
            status = INSTALL_ERROR;
        }
    } else if (should_wipe_cache) {
        if (!wipe_cache(false, device)) {
            status = INSTALL_ERROR;
        }
    } else if (sideload) {
        // 'adb reboot sideload' acts the same as user presses key combinations
        // to enter the sideload mode. When 'sideload-auto-reboot' is used, text
        // display will NOT be turned on by default. And it will reboot after
        // sideload finishes even if there are errors. Unless one turns on the
        // text display during the installation. This is to enable automated
        // testing.
        if (!sideload_auto_reboot) {
            ui->ShowText(true);
        }
        status = apply_from_adb(ui, &should_wipe_cache, TEMPORARY_INSTALL_FILE);
        if (status == INSTALL_SUCCESS && should_wipe_cache) {
            if (!wipe_cache(false, device)) {
                status = INSTALL_ERROR;
            }
        }
        ui->Print("\nInstall from ADB complete (status: %d).\n", status);
        if (sideload_auto_reboot) {
            ui->Print("Rebooting automatically.\n");
        }
    }

    if (env_set != NULL) {
        if (set_env_optarg(env_set) < 0) {
            ui->Print("Set env failed.\n");
            ui->ShowText(true);
        } else {
            ui->Print("Set env complete.\n");
            ui->ShowText(true);
        }
    }

    if (env_get != NULL) {
        if (get_env_optarg(env_get) < 0) {
            ui->Print("Get env failed.\n");
            ui->ShowText(true);
        } else {
            ui->Print("Get env complete.\n");
            ui->ShowText(true);
        }
    }

    if (!sideload_auto_reboot && (status == INSTALL_ERROR || status == INSTALL_CORRUPT)) {
        copy_logs();
        ui->SetBackground(RecoveryUI::ERROR);
    }


    if (data_ro_wipe) {
        printf("data_ro_wipe tip\n");
        ui->ShowText(true);
        const char* headers[] = {
                    "Data partition is read-only,maybe damaged.",
                    "Do you want to wipe data?",
                    "  THIS CAN NOT BE UNDONE.",
                    "",
                    NULL };
        wipe_data_with_headers(1, device, headers);
        status = INSTALL_SUCCESS;
        ui->ShowText(false);
    }

#ifndef RECOVERY_DISABLE_ADB_SIDELOAD
    adb_listeners(ui, argc, argv);
#endif

    Device::BuiltinAction after = shutdown_after ? Device::SHUTDOWN : Device::REBOOT;
    if (just_exit) {
        after = Device::REBOOT;
    } else if ((status != INSTALL_SUCCESS && !sideload_auto_reboot) || ui->IsTextVisible()) {
        Device::BuiltinAction temp = prompt_and_wait(device, status);
        if (temp != Device::NO_ACTION) {
            after = temp;
        }
    }

    // Save logs and clean up before rebooting or shutting down.
    finish_recovery(send_intent);

    switch (after) {
        case Device::SHUTDOWN:
            ui->Print("Shutting down...\n");
            property_set(ANDROID_RB_PROPERTY, "shutdown,");
            break;

        case Device::REBOOT_BOOTLOADER:
            ui->Print("Rebooting to bootloader...\n");
            property_set(ANDROID_RB_PROPERTY, "reboot,bootloader");
            break;

        default:
            ui->Print("Rebooting...\n");
            property_set(ANDROID_RB_PROPERTY, "reboot,");
            break;
    }
    sleep(5); // should reboot before this finishes
    return EXIT_SUCCESS;
}
