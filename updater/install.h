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

#ifndef _UPDATER_INSTALL_H_
#define _UPDATER_INSTALL_H_

void RegisterInstallFunctions();
int RebootToRecovery(const char* package_filename, int wipe_flag);


// uiPrintf function prints msg to screen as well as logs
void uiPrintf(State* state, const char* format, ...);

static int make_parents(char* name);

#endif
