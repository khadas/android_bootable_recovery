#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ubootenv.h"


// ------------------------------------
// for uboot environment variable operation
// ------------------------------------

static int s_bootloaderEnvInited = -1;

int bootloader_env_init(void)
 {
    int ret = bootenv_init();
     printf("ubootenv init %s.(%d)\n",
        (ret < 0) ? "failed" : "successful", ret);
    return ret;
 }


/*
* bootloader environment variable init
* 0: success, <0: fail
*/
static int ensure_bootloader_env_init(void)
{
    if (!s_bootloaderEnvInited)
        return 0;

    s_bootloaderEnvInited = bootenv_init();
    printf("ubootenv init %s.(%d)\n",
        (s_bootloaderEnvInited < 0) ? "failed" : "successful", s_bootloaderEnvInited);

    return s_bootloaderEnvInited;
}

int set_bootloader_env(const char* name, const char* value)
{
    int ret = ensure_bootloader_env_init();
    if (ret < 0) {
        return ret;
    }

    char ubootenv_name[128] = {0};
    const char *ubootenv_var = "ubootenv.var.";
    sprintf(ubootenv_name, "%s%s", ubootenv_var, name);

    return bootenv_update(ubootenv_name, value);
}

char *get_bootloader_env(const char * name)
{
    int ret = ensure_bootloader_env_init();
    if (ret < 0) {
        return NULL;
    }

    char ubootenv_name[128] = {0};
    const char *ubootenv_var = "ubootenv.var.";
    sprintf(ubootenv_name, "%s%s", ubootenv_var, name);
    return (char *)bootenv_get(ubootenv_name);
}
