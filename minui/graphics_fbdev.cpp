/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "graphics_fbdev.h"

#include <fcntl.h>
#include <linux/fb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>

#include <android-base/unique_fd.h>
#include <android-base/properties.h>
#include "minui/minui.h"

/*
* ebc buf format
*/
#define EBC_Y4 (0)
#define EBC_Y8 (1)

#define EINK_FB_SIZE		(0x500000) /* 5M */
#define EBC_GET_BUFFER				(0x7000)
#define EBC_SEND_BUFFER			(0x7001)
#define EBC_GET_BUFFER_INFO		(0x7002)
#define EBC_SET_FULL_MODE_NUM	(0x7003)
#define EBC_ENABLE_OVERLAY		(0x7004)
#define EBC_DISABLE_OVERLAY		(0x7005)
#define EBC_GET_OSD_BUFFER		(0x7006)
#define EBC_SEND_OSD_BUFFER		(0x7007)
#define EBC_NEW_BUF_PREPARE		(0x7008)
#define EBC_SET_DIFF_PERCENT		(0x7009)
#define EBC_WAIT_NEW_BUF_TIME	(0x700a)
#define EBC_GET_OVERLAY_STATUS	(0x700b)
#define EBC_ENABLE_BG_CONTROL	(0x700c)
#define EBC_DISABLE_BG_CONTROL	(0x700d)
#define EBC_ENABLE_RESUME_COUNT	(0x700e)
#define EBC_DISABLE_RESUME_COUNT	(0x700f)
#define EBC_GET_BUF_FORMAT		(0x7010)
#define EBC_DROP_PREV_BUFFER		(0x7011)

#define EPD_NULL            (-1)
#define EPD_AUTO            (0)
#define EPD_OVERLAY         (1)
#define EPD_FULL_GC16       (2)
#define EPD_FULL_GL16       (3)
#define EPD_FULL_GLR16     	(4)
#define EPD_FULL_GLD16      (5)
#define EPD_FULL_GCC16     	(6)
#define EPD_PART_GC16       (7)
#define EPD_PART_GL16       (8)
#define EPD_PART_GLR16      (9)
#define EPD_PART_GLD16		(10)
#define EPD_PART_GCC16     	(11)
#define EPD_A2       		(12)
#define EPD_A2_DITHER       		(13)
#define EPD_DU				(14)
#define EPD_DU4				(15)
#define EPD_A2_ENTER		(16)
#define EPD_RESET        	(17)
#define EPD_SUSPEND        	(18)
#define EPD_RESUME        	(19)
#define EPD_POWER_OFF       (20)
#define EPD_FORCE_FULL		(21)

/*android use struct*/
struct ebc_buf_info_t{
  int offset;
  int epd_mode;
  int height;
  int width;
  int panel_color;
  int win_x1;
  int win_y1;
  int win_x2;
  int win_y2;
  int width_mm;
  int height_mm;
  int dropable;
  char tid_name[16];
}__packed;


static unsigned long ebc_buffer_base = 0;
static int ebc_buf_format = EBC_Y4;

static void rgba8888_2_gray16(uint8_t *dest, uint32_t *src, int h, int vir_w)
{
	uint32_t red, green, blue, gray_px1, gray_px2;
	uint32_t rgba_data;
	int total_pixel = vir_w * h / 2;

	while (total_pixel--) {
		rgba_data = *src;
		red = rgba_data & 0x000000ff;
		green = (rgba_data & 0x0000ff00) >> 8;
		blue = (rgba_data & 0x00ff0000) >> 16;
		gray_px1 = ((red * 38 + green * 75 + blue * 15) >> 7) >> 4;
		src++;

		rgba_data = *src;
		red = rgba_data & 0x000000ff;
		green = (rgba_data & 0x0000ff00) >> 8;
		blue = (rgba_data & 0x00ff0000) >> 16;
		gray_px2 = ((red * 38 + green * 75 + blue * 15) >> 7) >> 4;
		src++;

		*dest++ = gray_px1 | (gray_px2 << 4);
	}
}

static void rgba8888_2_gray256(uint8_t *dest, uint32_t *src, int h, int vir_w)
{
	uint32_t red, green, blue, gray_px;
	uint32_t rgba_data;
	int total_pixel = vir_w * h;

	while (total_pixel--) {
		rgba_data = *src++;
		red = rgba_data & 0x000000ff;
		green = (rgba_data & 0x0000ff00) >> 8;
		blue = (rgba_data & 0x00ff0000) >> 16;
		gray_px = ((red * 38 + green * 75 + blue * 15) >> 7) & 0xf0;
		*dest++ = gray_px;
	}
}

std::unique_ptr<GRSurfaceFbdev> GRSurfaceFbdev::Create(size_t width, size_t height,
                                                       size_t row_bytes, size_t pixel_bytes) {
  // Cannot use std::make_unique to access non-public ctor.
  return std::unique_ptr<GRSurfaceFbdev>(new GRSurfaceFbdev(width, height, row_bytes, pixel_bytes));
}

void MinuiBackendFbdev::Blank(bool blank) {
  bool is_ebook_fb = android::base::GetBoolProperty("sys.ebook.recovery.ebook_fb", false);
  if (is_ebook_fb) {
    return;
  } else {
    int ret = ioctl(fb_fd, FBIOBLANK, blank ? FB_BLANK_POWERDOWN : FB_BLANK_UNBLANK);
    if (ret < 0) perror("ioctl(): blank");
  }
}

void MinuiBackendFbdev::Blank(bool blank, DrmConnector index) {
  if (index == DRM_MAIN) {
    MinuiBackendFbdev::Blank(blank);
  } else {
    fprintf(stderr, "Unsupported multiple connectors, blank = %d, index = %d\n", blank, index);
  }
}

bool MinuiBackendFbdev::HasMultipleConnectors() {
  fprintf(stderr, "Unsupported multiple connectors\n");
  return false;
}

void MinuiBackendFbdev::SetDisplayedFramebuffer(size_t n) {
  bool is_ebook_fb = android::base::GetBoolProperty("sys.ebook.recovery.ebook_fb", false);

  if (is_ebook_fb) {
    return;
  } else {
    if (n > 1 || !double_buffered) return;

    vi.yres_virtual = gr_framebuffer[0]->height * 2;
    vi.yoffset = n * gr_framebuffer[0]->height;
    vi.bits_per_pixel = gr_framebuffer[0]->pixel_bytes * 8;
    if (ioctl(fb_fd, FBIOPUT_VSCREENINFO, &vi) < 0) {
      perror("active fb swap failed");
    }
    displayed_buffer = n;
  }
}

GRSurface* MinuiBackendFbdev::Init() {
  bool is_ebook_fb = android::base::GetBoolProperty("sys.ebook.recovery.ebook_fb", false);
  printf("Fbdev Init is_ebook_fb=%d\n", is_ebook_fb);
  if (is_ebook_fb) {
    struct ebc_buf_info_t ebc_buf_info;
    void* vaddr = NULL;

    android::base::unique_fd ebc_fd(open("/dev/ebc", O_RDWR | O_CLOEXEC));
    if (ebc_fd == -1) {
      perror("cannot open open /dev/ebc\n");
      return nullptr;
    }

    if (ioctl(ebc_fd, EBC_GET_BUFFER_INFO, &ebc_buf_info) != 0) {
      perror("cannot get ebc buffer info\n");
      return nullptr;
    }

    if (ioctl(ebc_fd, EBC_GET_BUF_FORMAT, &ebc_buf_format) != 0) {
      perror("cannot get ebc buffer format info\n");
    }
    printf("ebc buffer format=%d\n", ebc_buf_format);

    vaddr = mmap(0, EINK_FB_SIZE * 4, PROT_READ|PROT_WRITE, MAP_SHARED, ebc_fd, 0);
    if (vaddr == MAP_FAILED) {
      perror("Error mapping the ebc buffer\n");
      return nullptr;
    }
    ebc_buffer_base = intptr_t(vaddr);

    gr_framebuffer[0] =
        GRSurfaceFbdev::Create(ebc_buf_info.width, ebc_buf_info.height, ebc_buf_info.width * 4, 4);
    memory_buffer.resize(gr_framebuffer[0]->height * gr_framebuffer[0]->row_bytes);
    gr_framebuffer[0]->buffer_ = memory_buffer.data();
    memset(gr_framebuffer[0]->buffer_, 0, gr_framebuffer[0]->height * gr_framebuffer[0]->row_bytes);
	gr_draw = gr_framebuffer[0].get();
    memset(gr_draw->buffer_, 0, gr_draw->height * gr_draw->row_bytes);

	fb_fd = std::move(ebc_fd);
    printf("framebuffer: %d (%zu x %zu)\n", fb_fd.get(), gr_draw->width, gr_draw->height);
  } else {
    android::base::unique_fd fd(open("/dev/graphics/fb0", O_RDWR | O_CLOEXEC));
    if (fd == -1) {
      perror("cannot open fb0");
      return nullptr;
    }

    fb_fix_screeninfo fi;
    if (ioctl(fd, FBIOGET_FSCREENINFO, &fi) < 0) {
      perror("failed to get fb0 info");
      return nullptr;
    }

    if (ioctl(fd, FBIOGET_VSCREENINFO, &vi) < 0) {
      perror("failed to get fb0 info");
      return nullptr;
    }

    // We print this out for informational purposes only, but
    // throughout we assume that the framebuffer device uses an RGBX
    // pixel format.  This is the case for every development device I
    // have access to.  For some of those devices (eg, hammerhead aka
    // Nexus 5), FBIOGET_VSCREENINFO *reports* that it wants a
    // different format (XBGR) but actually produces the correct
    // results on the display when you write RGBX.
    //
    // If you have a device that actually *needs* another pixel format
    // (ie, BGRX, or 565), patches welcome...

    printf(
        "fb0 reports (possibly inaccurate):\n"
        "  vi.bits_per_pixel = %d\n"
        "  vi.red.offset   = %3d   .length = %3d\n"
        "  vi.green.offset = %3d   .length = %3d\n"
        "  vi.blue.offset  = %3d   .length = %3d\n",
        vi.bits_per_pixel, vi.red.offset, vi.red.length, vi.green.offset, vi.green.length,
        vi.blue.offset, vi.blue.length);

    void* bits = mmap(0, fi.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (bits == MAP_FAILED) {
      perror("failed to mmap framebuffer");
      return nullptr;
    }

    memset(bits, 0, fi.smem_len);

    gr_framebuffer[0] =
        GRSurfaceFbdev::Create(vi.xres, vi.yres, fi.line_length, vi.bits_per_pixel / 8);
    gr_framebuffer[0]->buffer_ = static_cast<uint8_t*>(bits);
    memset(gr_framebuffer[0]->buffer_, 0, gr_framebuffer[0]->height * gr_framebuffer[0]->row_bytes);

    gr_framebuffer[1] =
        GRSurfaceFbdev::Create(gr_framebuffer[0]->width, gr_framebuffer[0]->height,
                               gr_framebuffer[0]->row_bytes, gr_framebuffer[0]->pixel_bytes);

    /* check if we can use double buffering */
    if (vi.yres * fi.line_length * 2 <= fi.smem_len) {
      double_buffered = true;

      gr_framebuffer[1]->buffer_ =
          gr_framebuffer[0]->buffer_ + gr_framebuffer[0]->height * gr_framebuffer[0]->row_bytes;
    } else {
      double_buffered = false;

      // Without double-buffering, we allocate RAM for a buffer to draw in, and then "flipping" the
      // buffer consists of a memcpy from the buffer we allocated to the framebuffer.
      memory_buffer.resize(gr_framebuffer[1]->height * gr_framebuffer[1]->row_bytes);
      gr_framebuffer[1]->buffer_ = memory_buffer.data();
    }

    gr_draw = gr_framebuffer[1].get();
    memset(gr_draw->buffer_, 0, gr_draw->height * gr_draw->row_bytes);
    fb_fd = std::move(fd);
    SetDisplayedFramebuffer(0);

    printf("framebuffer: %d (%zu x %zu)\n", fb_fd.get(), gr_draw->width, gr_draw->height);
    Blank(false);
  }

  return gr_draw;
}

GRSurface* MinuiBackendFbdev::Flip() {
  bool is_ebook_fb = android::base::GetBoolProperty("sys.ebook.recovery.ebook_fb", false);

  if (is_ebook_fb) {
    struct ebc_buf_info_t buf_info;

    snprintf(buf_info.tid_name, 16, "minui");

    if (ioctl(fb_fd, EBC_GET_BUFFER, &buf_info) != 0) {
        perror("GET_EBC_BUFFER failed\n");
    }
    if (ebc_buf_format == EBC_Y4)
        rgba8888_2_gray16((uint8_t *)(ebc_buffer_base + buf_info.offset), (uint32_t *)(gr_draw->buffer_), buf_info.height, buf_info.width);
    else
        rgba8888_2_gray256((uint8_t *)(ebc_buffer_base + buf_info.offset), (uint32_t *)(gr_draw->buffer_), buf_info.height, buf_info.width);
    buf_info.win_x1= 0;
    buf_info.win_y1= 0;
    buf_info.win_x2= buf_info.width;
    buf_info.win_y2= buf_info.height;
    buf_info.epd_mode = EPD_PART_GC16;

    if (ioctl(fb_fd, EBC_SEND_BUFFER, &buf_info) !=0 ) {
        perror("SET_EBC_SEND_BUFFER failed");
    }
  } else {
    if (double_buffered) {
      // Change gr_draw to point to the buffer currently displayed, then flip the driver so we're
      // displaying the other buffer instead.
      gr_draw = gr_framebuffer[displayed_buffer].get();
      SetDisplayedFramebuffer(1 - displayed_buffer);
    } else {
      // Copy from the in-memory surface to the framebuffer.
      memcpy(gr_framebuffer[0]->buffer_, gr_draw->buffer_, gr_draw->height * gr_draw->row_bytes);
    }
  }
  return gr_draw;
}
