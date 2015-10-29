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

#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>
#include <stdio.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <linux/fb.h>
#include <linux/kd.h>

#include <time.h>

#include "minui.h"
#include "graphics.h"

int main() {
    gr_init();
    GRSurface *ts;
    int result = res_create_display_surface("test", &ts);
    if (result < 0) {
        printf("create surface fail %d\n", result);
        gr_exit();
        return -1;
    }

    //gr_color(191, 0, 0, 255);
    //gr_clear();

    gr_color(0, 0, 255, 255);
    gr_fill(0,0, 100, 100);


    gr_color(191, 0, 0, 255);
    gr_fill(180,180, 500, 500);
    gr_color(0, 255, 0, 255);
    gr_fill(700,180, 1500, 500);

    gr_blit(ts, 0, 0, ts->width, ts->height, 200, 200);

    //gr_color(0, 90, 0, 255);
    //gr_fill(50, 50, 100, 100);

    gr_flip();
    usleep(10000000);
return 0;

/*
    time_t start = time(NULL);
    int x;
    for (x = 0; x <= 1200; ++x) {
        if (x < 400) {
            gr_color(0, 0, 0, 255);
        } else {
            gr_color(0, (x-400)%128, 0, 255);
        }
        gr_clear();

        gr_color(255, 0, 0, 255);
        gr_surface frame = images[x%frames];
        gr_blit(frame, 0, 0, frame->width, frame->height, x, 0);

        gr_color(255, 0, 0, 128);
        gr_fill(400, 150, 600, 350);

        gr_color(255, 255, 255, 255);
        gr_text(500, 225, "hello, world!", 0);
        gr_color(255, 255, 0, 128);
        gr_text(300+x, 275, "pack my box with five dozen liquor jugs", 1);

        gr_color(0, 0, 255, 128);
        gr_fill(gr_draw->width - 200 - x, 300, gr_draw->width - x, 500);

        gr_draw = gr_backend->flip(gr_backend);
    }
    printf("getting end time\n");
    time_t end = time(NULL);
    printf("got end time\n");
    printf("start %ld end %ld\n", (long)start, (long)end);
    if (end > start) {
        printf("%.2f fps\n", ((double)x) / (end-start));
    }
*/
}

