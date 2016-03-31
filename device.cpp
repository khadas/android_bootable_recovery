/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "device.h"

static const char* MENU_ITEMS[] = {
    "Reboot system now",
    "Reboot to bootloader",
    "Apply update from EXT",
    "Apply update from cache",
    "Apply update from ADB",
    "Wipe data/factory reset",
    "Wipe cache partition",
#ifdef RECOVERY_HAS_PARAM
    "Wipe param partition",
#endif
    "Mount /system",
    "View recovery logs",
    "Power off",
    NULL
};

const char* const* Device::GetMenuItems() {
  return MENU_ITEMS;
}

Device::BuiltinAction ITEMS_ACTION[] = {Device::REBOOT,
                                         Device::REBOOT_BOOTLOADER,
                                         Device::APPLY_EXT,
                                         Device::APPLY_CACHE,
                                         Device::APPLY_ADB_SIDELOAD,
                                         Device::WIPE_DATA,
                                         Device::WIPE_CACHE,
#ifdef RECOVERY_HAS_PARAM
                                         Device::WIPE_PARAM,
#endif
                                         Device::MOUNT_SYSTEM,
                                         Device::VIEW_RECOVERY_LOGS,
                                         Device::SHUTDOWN,
};

#define NUM_ACTIONS (sizeof(ITEMS_ACTION) / sizeof(ITEMS_ACTION[0]))

Device::BuiltinAction Device::InvokeMenuItem(int menu_position) {
    if (menu_position < NUM_ACTIONS)
        return ITEMS_ACTION[menu_position];
    else
        return NO_ACTION;
}

int Device::HandleMenuKey(int key, int visible) {
  if (!visible) {
    return kNoAction;
  }

  switch (key) {
    case KEY_DOWN:
    case KEY_VOLUMEDOWN:
      return kHighlightDown;

    case KEY_UP:
    case KEY_VOLUMEUP:
      return kHighlightUp;

    case KEY_ENTER:
    case KEY_POWER:
    case BTN_LEFT:
      return kInvokeItem;

    default:
      // If you have all of the above buttons, any other buttons
      // are ignored. Otherwise, any button cycles the highlight.
      return ui_->HasThreeButtons() ? kNoAction : kHighlightDown;
  }
}
