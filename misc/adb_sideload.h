/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef _ADB_LISTENER_H
#define _ADB_LISTENER_H

#define ADB_SIDELOAD    	"/tmp/adb_sideload"
#define ADB_SIDELOAD_OK 	"/tmp/adb_sideload_ok"
#define ADB_SIDELOAD_FAIL       "/tmp/adb_sideload_fail"
#define TEMPORARY_INSTALL_FILE  "/tmp/last_install"

extern void adb_copy_logs(void);
extern int adb_erase_volume(const char *volume);

#endif /* _ADB_LISTENER_H */
