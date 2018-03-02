$XenstoreTemplate = @"
tool = ""
 xenstored = ""
local = ""
 domain = ""
  0 = ""
   vm = "/vm/00000000-0000-0000-0000-000000000000"
   device = ""
   control = ""
    platform-feature-multiprocessor-suspend = "1"
   error = ""
   memory = ""
    target = "3227648"
   guest = ""
   hvmpv = ""
   data = ""
   cpu = ""
    15 = ""
     availability = "online"
    3 = ""
     availability = "online"
    8 = ""
     availability = "online"
    9 = ""
     availability = "online"
    6 = ""
     availability = "online"
    5 = ""
     availability = "online"
    13 = ""
     availability = "online"
    0 = ""
     availability = "online"
    18 = ""
     availability = "online"
    17 = ""
     availability = "online"
    12 = ""
     availability = "online"
    14 = ""
     availability = "online"
    19 = ""
     availability = "online"
    2 = ""
     availability = "online"
    11 = ""
     availability = "online"
    1 = ""
     availability = "online"
    7 = ""
     availability = "online"
    16 = ""
     availability = "online"
    4 = ""
     availability = "online"
    10 = ""
     availability = "online"
   description = ""
   console = ""
    limit = "1048576"
    type = "xenconsoled"
   name = "Domain-0"
   domid = "{DomID*:0}"
   backend = ""
    vkbd = ""
     1 = ""
      0 = ""
       frontend-id = "1"
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vkbd/0"
       state = "4"
       online = "1"
       feature-abs-pointer = "1"
       hotplug-status = "connected"
    vfb = ""
     1 = ""
      0 = ""
       vncunused = "1"
       domain = "0004fb0000060000c5fee5922b83ac28"
       vnc = "1"
       uuid = "7614df2f-02d2-c31c-f1f2-479f12c6b89f"
       vnclisten = "127.0.0.1"
       frontend = "/local/domain/1/device/vfb/0"
       state = "4"
       keymap = "en-us"
       online = "1"
       frontend-id = "1"
       xauthority = "/root/.Xauthority"
       feature-resize = "1"
       hotplug-status = "connected"
       location = "127.0.0.1:5900"
       request-update = "1"
    vbd = ""
     1 = ""
      {BlockID*:51712} = ""
       domain = "{Domain:0004fb0000060000c5fee5922b83ac28}"
       frontend = "{FrontendPath:/local/domain/1/device/vbd/51712}"
       uuid = "4ebe3c81-ba8c-ae08-e229-7c1fe41c5d26"
       bootable = "1"
       dev = "{Device:xvda}"
       state = "4"
       params = "/OVS/Repositories/0004fb00000300007a71d85fde7ca820/VirtualD\..."
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "file"
       node = "/dev/loop2"
       physical-device = "7:2"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "25165824"
       info = "0"
       sector-size = "512"
      {BlockID*:51760} = ""
       domain = "{Domain:0004fb0000060000c5fee5922b83ac28}"
       frontend = "{FrontendPath:/local/domain/1/device/vbd/51760}"
       uuid = "d4c45327-6bc8-4e54-0a0a-c44720801b28"
       bootable = "0"
       dev = "{Device:xvdd}"
       state = "4"
       params = "/OVS/Repositories/0004fb00000300007a71d85fde7ca820/VirtualD\..."
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "file"
       node = "/dev/loop1"
       physical-device = "7:1"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "33554432"
       info = "0"
       sector-size = "512"
      {BlockID*:51856} = ""
       domain = "{Domain:0004fb0000060000c5fee5922b83ac28}"
       frontend = "{FrontendPath:/local/domain/1/device/vbd/51856}"
       uuid = "102e14d2-511e-be62-94ef-51e1302edd4e"
       bootable = "0"
       dev = "{Device:xvdj}"
       state = "4"
       params = "/dev/mapper/36006016020b03800f117af276337e411"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:8"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-secure = "0"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "3145728000"
       info = "0"
       sector-size = "512"
      51872 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/51872"
       uuid = "93014a2f-b89f-e3ab-d871-c602ec4d26bc"
       bootable = "0"
       dev = "xvdk"
       state = "4"
       params = "/OVS/Repositories/0004fb00000300007a71d85fde7ca820/VirtualD\..."
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "file"
       node = "/dev/loop0"
       physical-device = "7:0"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "62914560"
       info = "0"
       sector-size = "512"
      51888 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/51888"
       uuid = "faaccc1b-6ac4-3441-deba-fc7ec6292818"
       bootable = "0"
       dev = "xvdl"
       state = "4"
       params = "/dev/mapper/36006016020b03800283daf7f92ffe311"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:2"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-secure = "0"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "2147483648"
       info = "0"
       sector-size = "512"
      51904 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/51904"
       uuid = "a053328a-591c-36e6-ed7b-3919d5a8f732"
       bootable = "0"
       dev = "xvdm"
       state = "4"
       params = "/dev/mapper/36006016020b03800c9d0d06792ffe311"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:1"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-secure = "0"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "1048576000"
       info = "0"
       sector-size = "512"
      51920 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/51920"
       uuid = "9b861dba-9492-0f2a-0bdb-95861f026c22"
       bootable = "0"
       dev = "xvdn"
       state = "4"
       params = "/dev/mapper/36006016020b038001738c0b57624e411"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:3"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-secure = "0"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "2147483648"
       info = "0"
       sector-size = "512"
      51952 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/51952"
       uuid = "c63ec58a-76a3-5cc5-b4bf-261c1ce2e01b"
       bootable = "0"
       dev = "xvdp"
       state = "4"
       params = "/dev/mapper/36006016020b03800ec77e62fef98e511"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:b"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-granularity = "512"
       discard-alignment = "0"
       discard-secure = "0"
       feature-discard = "1"
       feature-barrier = "1"
       sectors = "8589934592"
       info = "0"
       sector-size = "512"
      268439552 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/268439552"
       uuid = "f91666f6-0ce0-6456-0e7b-2f56242e986c"
       bootable = "0"
       dev = "xvdq"
       state = "4"
       params = "/dev/mapper/36006016020b03800d89aa641ef98e511"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:c"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-granularity = "512"
       discard-alignment = "0"
       discard-secure = "0"
       feature-discard = "1"
       feature-barrier = "1"
       sectors = "8589934592"
       info = "0"
       sector-size = "512"
      268439808 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/268439808"
       uuid = "4204a71d-9d4b-9947-1e8b-fa2ac5ce27b5"
       bootable = "0"
       dev = "xvdr"
       state = "4"
       params = "/dev/mapper/36006016020b03800b72a01ad67f7e511"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:9"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-secure = "0"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "1048576000"
       info = "0"
       sector-size = "512"
    vif = ""
     1 = ""
      0 = ""
       bridge = "0004fb00103588d"
       domain = "0004fb0000060000c5fee5922b83ac28"
       handle = "0"
       uuid = "456c8e29-7396-3125-6839-e728aa12bee8"
       script = "/etc/xen/scripts/vif-bridge"
       state = "4"
       frontend = "/local/domain/1/device/vif/0"
       mac = "00:21:f6:1c:2b:5a"
       online = "1"
       frontend-id = "1"
       feature-sg = "1"
       feature-gso-tcpv4 = "1"
       feature-rx-copy = "1"
       feature-rx-flip = "0"
       hotplug-status = "connected"
    console = ""
     1 = ""
      0 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       protocol = "vt100"
       uuid = "18a3763f-c8d0-0282-2ed2-b6f985174871"
       frontend = "/local/domain/1/device/console/0"
       state = "4"
       location = "2"
       online = "1"
       frontend-id = "1"
       hotplug-status = "connected"
   device-model = ""
    1 = ""
     state = "running"
  1 = ""
   vm = "/vm/0004fb00-0006-0000-c5fe-e5922b83ac28"
   device = ""
    vkbd = ""
     0 = ""
      protocol = "x86_64-abi"
      state = "4"
      backend-id = "0"
      backend = "/local/domain/0/backend/vkbd/1/0"
      request-abs-pointer = "1"
      page-ref = "2341224"
      page-gref = "8"
      event-channel = "116"
    vfb = ""
     0 = ""
      protocol = "x86_64-abi"
      state = "4"
      backend-id = "0"
      backend = "/local/domain/0/backend/vfb/1/0"
      page-ref = "2349472"
      event-channel = "115"
      feature-update = "1"
    vbd = ""
     51712 = ""
      virtual-device = "51712"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51712"
      ring-ref = "9"
      event-channel = "117"
      feature-persistent = "1"
     51760 = ""
      virtual-device = "51760"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51760"
      ring-ref = "10"
      event-channel = "118"
      feature-persistent = "1"
     51856 = ""
      virtual-device = "51856"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51856"
      ring-ref = "11"
      event-channel = "119"
      feature-persistent = "1"
     51872 = ""
      virtual-device = "51872"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51872"
      ring-ref = "12"
      event-channel = "120"
      feature-persistent = "1"
     51888 = ""
      virtual-device = "51888"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51888"
      ring-ref = "14"
      event-channel = "121"
      feature-persistent = "1"
     51904 = ""
      virtual-device = "51904"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51904"
      ring-ref = "15"
      event-channel = "122"
      feature-persistent = "1"
     51920 = ""
      virtual-device = "51920"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51920"
      ring-ref = "16"
      event-channel = "123"
      feature-persistent = "1"
     51952 = ""
      virtual-device = "51952"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51952"
      ring-ref = "18"
      event-channel = "124"
      feature-persistent = "1"
     268439552 = ""
      virtual-device-ext = "268439552"
      state = "4"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      backend = "/local/domain/0/backend/vbd/1/268439552"
      ring-ref = "19"
      event-channel = "125"
      feature-persistent = "1"
     268439808 = ""
      virtual-device-ext = "268439808"
      state = "4"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      backend = "/local/domain/0/backend/vbd/1/268439808"
      ring-ref = "20"
      event-channel = "126"
      feature-persistent = "1"
    vif = ""
     0 = ""
      mac = "00:21:f6:1c:2b:5a"
      handle = "0"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vif/1/0"
      tx-ring-ref = "415"
      rx-ring-ref = "416"
      event-channel = "127"
      request-rx-copy = "1"
      feature-rx-notify = "1"
      feature-sg = "1"
      feature-gso-tcpv4 = "1"
    console = ""
     0 = ""
      protocol = "x86_64-abi"
      state = "1"
      backend-id = "0"
      backend = "/local/domain/0/backend/console/1/0"
   control = ""
    platform-feature-multiprocessor-suspend = "1"
   error = ""
   memory = ""
    target = "256000000"
   guest = ""
   hvmpv = ""
   data = ""
   console = ""
    tty = "/dev/pts/2"
    ring-ref = "34791160"
    port = "2"
    limit = "1048576"
    type = "ioemu"
    vnc-port = "5900"
    vnc-listen = "127.0.0.1"
   device-misc = ""
    vif = ""
     nextDeviceID = "1"
    console = ""
     nextDeviceID = "1"
   image = ""
    device-model-fifo = "/var/run/xend/dm-1-1505263975.fifo"
    device-model-pid = "13452"
    entry = "18446744071589106176"
    loader = "generic"
    hv-start-low = "18446603336221196288"
    guest-os = "linux"
    hypercall-page = "18446744071578849280"
    guest-version = "2.6"
    pae-mode = "yes"
    paddr-offset = "0"
    virt-base = "18446744071562067968"
    suspend-cancel = "1"
    features = ""
     pae-pgdir-above-4gb = "1"
     writable-page-tables = "0"
    xen-version = "xen-3.0"
   cpu = ""
    3 = ""
     availability = "online"
    6 = ""
     availability = "online"
    14 = ""
     availability = "online"
    13 = ""
     availability = "online"
    11 = ""
     availability = "online"
    1 = ""
     availability = "online"
    7 = ""
     availability = "online"
    4 = ""
     availability = "online"
    15 = ""
     availability = "online"
    8 = ""
     availability = "online"
    9 = ""
     availability = "online"
    5 = ""
     availability = "online"
    0 = ""
     availability = "online"
    12 = ""
     availability = "online"
    2 = ""
     availability = "online"
    10 = ""
     availability = "online"
   store = ""
    ring-ref = "34791161"
    port = "1"
   description = ""
   name = "0004fb0000060000c5fee5922b83ac28"
   domid = "{DomID*:1}"
   serial = ""
    0 = ""
     tty = "/dev/pts/1"
 pool = ""
  0 = ""
   other_config = ""
   description = "Pool-0"
   uuid = "ec70e4ec-0595-9497-5c14-2da6fd5f6c94"
   name = "Pool-0"
vm = ""
 00000000-0000-0000-0000-000000000000 = ""
  on_xend_stop = "ignore"
  pool_name = "Pool-0"
  shadow_memory = "0"
  uuid = "00000000-0000-0000-0000-000000000000"
  on_reboot = "restart"
  image = "(linux (kernel '') (expose_host_uuid 0) (superpages 0) (tsc_mode \..."
   ostype = "linux"
   kernel = ""
   cmdline = ""
   ramdisk = ""
  on_poweroff = "destroy"
  bootloader_args = ""
  on_xend_start = "ignore"
  on_crash = "restart"
  xend = ""
   restart_count = "0"
  vcpus = "20"
  vcpu_avail = "1048575"
  bootloader = ""
  name = "Domain-0"
 0004fb00-0006-0000-c5fe-e5922b83ac28 = ""
  image = "(linux (kernel '') (expose_host_uuid 0) (superpages 0) (tsc_mode \..."
   ostype = "linux"
   kernel = "/var/run/xend/boot/boot_kernel.1Qsf2_"
   cmdline = "ro root=LABEL=/ numa=off "
   ramdisk = "/var/run/xend/boot/boot_ramdisk.LaCKAd"
  device = ""
   vkbd = ""
    0 = ""
     frontend = "/local/domain/1/device/vkbd/0"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vkbd/1/0"
   vfb = ""
    0 = ""
     frontend = "/local/domain/1/device/vfb/0"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vfb/1/0"
   vbd = ""
    51712 = ""
     frontend = "/local/domain/1/device/vbd/51712"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51712"
    51760 = ""
     frontend = "/local/domain/1/device/vbd/51760"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51760"
    51856 = ""
     frontend = "/local/domain/1/device/vbd/51856"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51856"
    51872 = ""
     frontend = "/local/domain/1/device/vbd/51872"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51872"
    51888 = ""
     frontend = "/local/domain/1/device/vbd/51888"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51888"
    51904 = ""
     frontend = "/local/domain/1/device/vbd/51904"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51904"
    51920 = ""
     frontend = "/local/domain/1/device/vbd/51920"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51920"
    51952 = ""
     frontend = "/local/domain/1/device/vbd/51952"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51952"
    268439552 = ""
     frontend = "/local/domain/1/device/vbd/268439552"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/268439552"
    268439808 = ""
     frontend = "/local/domain/1/device/vbd/268439808"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/268439808"
   vif = ""
    0 = ""
     frontend = "/local/domain/1/device/vif/0"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vif/1/0"
   console = ""
    0 = ""
     frontend = "/local/domain/1/device/console/0"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/console/1/0"
  on_xend_stop = "ignore"
  pool_name = "Pool-0"
  shadow_memory = "0"
  uuid = "0004fb00-0006-0000-c5fe-e5922b83ac28"
  on_reboot = "restart"
  start_time = "1505263975.5"
  on_poweroff = "destroy"
  bootloader_args = "-q"
  on_xend_start = "ignore"
  on_crash = "restart"
  xend = ""
   restart_count = "0"
  vcpus = "16"
  vcpu_avail = "65535"
  bootloader = "/usr/bin/pygrub"
  name = "0004fb0000060000c5fee5922b83ac28"
"@

$XMListTemplate = @"
Name                                        ID   Mem VCPUs      State   Time(s)
{DomainID*:0004fb0000060000c5fee5922b83ac28}             {ID:1} 250000    16     r----- 5447521.2
Domain-0                                     0  3152    20     r----- 259938.1
"@

$XenstoreLSTemplate = @"
vm = "/vm/0004fb00-0006-0000-c5fe-e5922b83ac28"
device = ""
 vkbd = ""
  0 = ""
   protocol = "x86_64-abi"
   state = "4"
   backend-id = "0"
   backend = "/local/domain/0/backend/vkbd/1/0"
   request-abs-pointer = "1"
   page-ref = "2341224"
   page-gref = "8"
   event-channel = "116"
 vfb = ""
  0 = ""
   protocol = "x86_64-abi"
   state = "4"
   backend-id = "0"
   backend = "/local/domain/0/backend/vfb/1/0"
   page-ref = "2349472"
   event-channel = "115"
   feature-update = "1"
 vbd = ""
  51712 = ""
   virtual-device = "{VirtualDevice*:51712}"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "{DevicePath:/local/domain/0/backend/vbd/1/51712}"
   ring-ref = "9"
   event-channel = "117"
   feature-persistent = "1"
  51760 = ""
   virtual-device = "{VirtualDevice*:51760}"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51760"
   ring-ref = "10"
   event-channel = "118"
   feature-persistent = "1"
  51856 = ""
   virtual-device = "51856"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51856"
   ring-ref = "11"
   event-channel = "119"
   feature-persistent = "1"
  51872 = ""
   virtual-device = "51872"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51872"
   ring-ref = "12"
   event-channel = "120"
   feature-persistent = "1"
  51888 = ""
   virtual-device = "51888"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51888"
   ring-ref = "14"
   event-channel = "121"
   feature-persistent = "1"
  51904 = ""
   virtual-device = "51904"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51904"
   ring-ref = "15"
   event-channel = "122"
   feature-persistent = "1"
  51920 = ""
   virtual-device = "51920"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51920"
   ring-ref = "16"
   event-channel = "123"
   feature-persistent = "1"
  51952 = ""
   virtual-device = "51952"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51952"
   ring-ref = "18"
   event-channel = "124"
   feature-persistent = "1"
  268439552 = ""
   virtual-device-ext = "268439552"
   state = "4"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   backend = "/local/domain/0/backend/vbd/1/268439552"
   ring-ref = "19"
   event-channel = "125"
   feature-persistent = "1"
  268439808 = ""
   virtual-device-ext = "268439808"
   state = "4"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   backend = "/local/domain/0/backend/vbd/1/268439808"
   ring-ref = "20"
   event-channel = "126"
   feature-persistent = "1"
 vif = ""
  0 = ""
   mac = "00:21:f6:1c:2b:5a"
   handle = "0"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vif/1/0"
   tx-ring-ref = "415"
   rx-ring-ref = "416"
   event-channel = "127"
   request-rx-copy = "1"
   feature-rx-notify = "1"
   feature-sg = "1"
   feature-gso-tcpv4 = "1"
 console = ""
  0 = ""
   protocol = "x86_64-abi"
   state = "1"
   backend-id = "0"
   backend = "/local/domain/0/backend/console/1/0"
control = ""
 platform-feature-multiprocessor-suspend = "1"
error = ""
memory = ""
 target = "256000000"
guest = ""
hvmpv = ""
data = ""
console = ""
 tty = "/dev/pts/2"
 ring-ref = "34791160"
 port = "2"
 limit = "1048576"
 type = "ioemu"
 vnc-port = "5900"
 vnc-listen = "127.0.0.1"
device-misc = ""
 vif = ""
  nextDeviceID = "1"
 console = ""
  nextDeviceID = "1"
image = ""
 device-model-fifo = "/var/run/xend/dm-1-1505263975.fifo"
 device-model-pid = "13452"
 entry = "18446744071589106176"
 loader = "generic"
 hv-start-low = "18446603336221196288"
 guest-os = "linux"
 hypercall-page = "18446744071578849280"
 guest-version = "2.6"
 pae-mode = "yes"
 paddr-offset = "0"
 virt-base = "18446744071562067968"
 suspend-cancel = "1"
 features = ""
  pae-pgdir-above-4gb = "1"
  writable-page-tables = "0"
 xen-version = "xen-3.0"
cpu = ""
 3 = ""
  availability = "online"
 6 = ""
  availability = "online"
 14 = ""
  availability = "online"
 13 = ""
  availability = "online"
 11 = ""
  availability = "online"
 1 = ""
  availability = "online"
 7 = ""
  availability = "online"
 4 = ""
  availability = "online"
 15 = ""
  availability = "online"
 8 = ""
  availability = "online"
 9 = ""
  availability = "online"
 5 = ""
  availability = "online"
 0 = ""
  availability = "online"
 12 = ""
  availability = "online"
 2 = ""
  availability = "online"
 10 = ""
  availability = "online"
store = ""
 ring-ref = "34791161"
 port = "1"
description = ""
name = "0004fb0000060000c5fee5922b83ac28"
domid = "1"
serial = ""
 0 = ""
  tty = "/dev/pts/1"
"@

$BlockDeviceDetailTemplate2 = @"
domain = "{DomainID*:0004fb0000060000c5fee5922b83ac28}"
frontend = "{Frontend:/local/domain/1/device/vbd/51856}"
uuid = "102e14d2-511e-be62-94ef-51e1302edd4e"
bootable = "{Bootable:0}"
dev = "{Device:xvdj}"
state = "{State:4}"
params = "{Params:/dev/mapper/36006016020b03800f117af276337e411}"
mode = "{Mode:w}"
online = "{Online:1}"
frontend-id = "{FrontendID:1}"
type = "{Type:phy}"
physical-device = "{PhysicalDevice:fc:8}"
hotplug-status = "{HotplugStatus:connected}"
feature-flush-cache = "{FeatureFlushCache:1}"
discard-secure = "{DiscardSecure:0}"
feature-discard = "{FeatureDiscard:0}"
feature-barrier = "{FeatureBarrier:1}"
sectors = "{Sectors:3145728000}"
info = "{Info:0}"
sector-size = "{SectorSize:512}"
"@