--- Recovery Key Instructions:
Usage:
Args config in "factory_update_param.aml"
--write_key=mac:0,mac_bt:1,mac_wifi:0,usid:1,hdcp:1
Notice:
0: said to read key first,if key doesn't be writen before,so start
   to write,if key has been writen,so key will not be writen
1: said to write force,not care key has been writen.

The follow is key files instructions
1. mac/mac_bt/mac_wifi:
 the key file suffix name is ".flash" said to write key to flash,
 else if suffix name is ".efuse"  said to write key to efuse
 such as mac.flash,mac_bt.flash,mac_wifi.flash
example for mac.flash,contents:
00:22:33:44:55:66
11:22:33:44:55:77
22:22:33:44:55:88
33:22:33:44:55:88
......

2. usid:
 write usid needs two files: usid.flash,usid.ini.contents:
<usid.flash>
[Group1]
base=ABCDEFG456
start=00100
end=20000

[Group2]
start=00100
end=20000
base=abcdefg456

<usid.ini>
[USID usage information]
use:[Group1]
usid total:19901
prepare to write usid index:1

3. hdcp:
 write hdcp needs two files: hdcp.flash,hdcp.ini.contents:
<hdcp.flash>
this file content is HDCP_LICENSE

<hdcp.ini>
[HDCP usage information]
hdcp total:4
prepare to write hdcp index:1


--- Recovery Secure Check Instructions:
-The main function which is to judge upgrade package's image and platform whether
are consistent or not about encryption.

-This function is default disabled,if you will use it,you must config it first in kernel,
let kernel generate two nodes:
"/dev/defendkey" and "/sys/class/defendkey/defendkey/secure_check"

-You can add/modify code like the followimg to generate two nodes, such as n200
platform:
1). meson8m2_n200_1G.dtd: (in arch/arm/boot/dts/amlogic)
///    -     defendkey
//$$ MODULE="defendkey"
//$$ DEVICE="defendkey"
//$$ L2 PROP_STR = "status"
    defendkey{
        compatible = "amlogic,defendkey";
        status = "ok";
    };

2). Kconfig: (drivers/amlogic/defendkey)
 config DEFEND_IMG
        depends on EFUSE
        bool "defend img update"
-       default n
+       default y
        help
            defend update system for board, when system is encrypted, the system img

3). Kconfig: (drivers/amlogic/efuse)
 config EFUSE
        bool "EFUSE Driver"
-       default n
+       default y
        help
            EFUSE device driver.

-There are several kinds of situations to judge whether upgrade or not in recovery:
1. bootkey hasn't been writen to platform before(has not been encrypted before)
   and upgrade package has been not encrypted.
   -- can upgrade

2. bootkey hasn't been writen to platform before(has not benn encrypted before)
   and upgrade package has been encrypted.
   -- can't upgrade

3. bootkey has been writen to platform before(has been encrypted before)
   and upgrade package has been not encrypted.
   -- can't upgrade

4. bootkey has been writen to platform before(has been encrypted before)
   and upgrade package has been encrypted,and rsa used is the same.
   -- can upgrade

5. bootkey has been writen to platform before(has been encrypted before)
   and upgrade package has been encrypted,but rsa used is not the same.
   -- can't upgrade
