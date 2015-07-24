/*
* bootloader env init
* 0: success, <0: fail
*/
extern int bootloader_env_init(void);

/*
* set bootloader environment variable
* 0: success, <0: fail
*/
extern int set_bootloader_env(const char* name, const char* value);

/*
* get bootloader environment variable
* NULL: init failed or get env value is NULL
* NONE NULL: env value
*/
extern char *get_bootloader_env(const char * name);
