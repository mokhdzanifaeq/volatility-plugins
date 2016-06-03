#pylint: disable-msg=C0111

import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.common as common
import volatility.utils as utils

class UsbParse(common.AbstractWindowsCommand):
    "parse usb information from registry"

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self.regapi = None
        self.usb_devices = {}

    def USBSTOR(self):
        usbstor = self.regapi.reg_get_currentcontrolset() + "\\Enum\\USBSTOR"
        for subkey in self.regapi.reg_get_all_subkeys(None, key = usbstor):
            device = {}
            device["time"] = {}
            part = subkey.Name.split("&")
            if part[0].lower() != "disk":
                continue
            if len(part) == 4:
                device["vendor"] = part[1][4:]
                device["product"] = part[2][5:]
                device["version"] = part[3][4:]
            for serial in self.regapi.reg_get_all_subkeys(None, key = usbstor + "\\" + subkey.Name):
                device["time"]["ven_prod_rev"] = serial.LastWriteTime
                serial_part = serial.Name.split('&')
                serial_no = serial_part[0] if len(serial_part) == 2 else serial.Name
                val = self.regapi.reg_get_value(None, key = usbstor + "\\" + subkey.Name + "\\" + serial.Name, value = "FriendlyName")
                if val:
                    device["device_name"] = utils.remove_unprintable(val)
                val = self.regapi.reg_get_value(None, key = usbstor + "\\" + subkey.Name + "\\" + serial.Name, value = "ParentIdPrefix")
                if val:
                    device["parent_prefix_id"] = utils.remove_unprintable(val)
                for properties in self.regapi.reg_get_all_subkeys(None, key = usbstor + "\\" + subkey.Name + "\\" + serial.Name + "\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}"):
                    name = str(properties.Name)
                    if "0064" in name:
                        device["time"]["install_date"] = properties.LastWriteTime
                    elif "0065" in name:
                        device["time"]["first_install_date"] = properties.LastWriteTime
                    elif "0066" in name:
                        device["time"]["last_arrival_date"] = properties.LastWriteTime
                    elif "0067" in name:
                        device["time"]["last_removal_date"] = properties.LastWriteTime
                self.usb_devices[serial_no] = device

    def USB(self):
        usb = self.regapi.reg_get_currentcontrolset() + "\\Enum\\USB"
        for subkey in self.regapi.reg_get_all_subkeys(None, key = usb):
            name = str(subkey.Name)
            if not "PID" in name or not "VID" in name:
                continue
            for serial in self.regapi.reg_get_all_subkeys(None, key = usb + "\\" + name):
                serial_no = str(serial.Name)
                if serial_no in self.usb_devices:
                    id_part = name.split("&")
                    self.usb_devices[serial_no]["vid"] = id_part[0][4:]
                    self.usb_devices[serial_no]["pid"] = id_part[1][4:]
                    self.usb_devices[serial_no]["time"]["vid_pid"] = subkey.LastWriteTime

    def MountedDevices(self):
        mounted = self.regapi.reg_yield_values(None, key = "MountedDevices", thetype = "REG_BINARY")
        for serial in self.usb_devices:
            for value, data in mounted:
                data = utils.remove_unprintable(data)
                value = str(value)
                if "Volume" in value:
                    if "parent_prefix_id" in self.usb_devices[serial]:
                        if self.usb_devices[serial]["parent_prefix_id"] in data:
                            self.usb_devices[serial]["guid"] = value[11:-1]
                    else:
                        if serial in data:
                            self.usb_devices[serial]["guid"] = value[11:-1]
                if "DosDevices" in value:
                    if "parent_prefix_id" in self.usb_devices[serial]:
                        if self.usb_devices[serial]["parent_prefix_id"] in data:
                            self.usb_devices[serial]["drive_letter"] = value[12:]
                    else:
                        if serial in data:
                            self.usb_devices[serial]["drive_letter"] = value[12:]
                if "drive_letter" in self.usb_devices[serial] and "guid" in self.usb_devices[serial]:
                    break

    def DeviceClasses(self):
        device_class = self.regapi.reg_get_currentcontrolset() + "\\Control\\DeviceClasses"
        for disk in self.regapi.reg_get_all_subkeys(None, key = device_class + "\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"):
            name = str(disk.Name)
            if not 'USBSTOR#Disk' in name:
                continue
            part = name.split("USBSTOR#Disk&")[1].split("#")[1]
            serial_part = part.split("&")
            serial_no = serial_part[0] if len(serial_part) == 2 else part
            if serial_no in self.usb_devices:
                self.usb_devices[serial_no]["time"]["disk_device"] = disk.LastWriteTime
        for volume in self.regapi.reg_get_all_subkeys(None, key = device_class + "\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"):
            name = str(volume.Name)
            if not 'USBSTOR#DISK' in name:
                continue
            part = name.split("USBSTOR#DISK&")[1].split("#")[1]
            serial_part = part.split("&")
            serial_no = serial_part[0] if len(serial_part) == 2 else part
            if serial_no in self.usb_devices:
                self.usb_devices[serial_no]["time"]["volume_device"] = volume.LastWriteTime

    def WindowsPortableDevices(self):
        for subkey in self.regapi.reg_get_all_subkeys(None, key = "Microsoft\\Windows Portable Devices\\Devices"):
            name = str(subkey.Name)
            if not 'USBSTOR#DISK' in name:
                continue
            val = self.regapi.reg_get_value(None, key = "Microsoft\\Windows Portable Devices\\Devices\\" + name, value = "FriendlyName")
            if val:
                part = name.split("USBSTOR#DISK&")[1].split("#")[1]
                serial_part = part.split("&")
                serial_no = serial_part[0] if len(serial_part) == 2 else part
                if serial_no in self.usb_devices:
                    self.usb_devices[serial_no]["volume_name"] = utils.remove_unprintable(val)

    def EMDMgmt(self):
        for subkey in self.regapi.reg_get_all_subkeys(None, key = "Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt"):
            name = str(subkey.Name)
            if not "USBSTOR#Disk" in name or not "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" in name:
                continue
            part = name.split("USBSTOR#Disk&")[1].split("#")
            serial_part = part[1].split("&")
            serial_no = serial_part[0] if len(serial_part) == 2 else part[1]
            data = part[2][38:].split("_")
            if serial_no in self.usb_devices:
                if not "volume_name" in self.usb_devices[serial_no]:
                    self.usb_devices[serial_no]["volume_name"] = data[0]
                self.usb_devices[serial_no]["volume_serial_no"] = data[1]

    def MountPoints2(self):
        for serial in self.usb_devices:
            user = []
            if not "guid" in self.usb_devices[serial]:
                continue
            for name, path in self.regapi.reg_yield_key(None, key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\{" + self.usb_devices[serial]["guid"] + "}"):
                part = path.split("\\")
                user.append(part[-2])
            self.usb_devices[serial]["associated_user"] = user

    def calculate(self):
        self.regapi = registryapi.RegistryApi(self._config)
        # system hive
        self.regapi.reset_current()
        self.regapi.set_current(hive_name = "system")
        print "[+] parsing USBSTOR"
        self.USBSTOR()
        if self.usb_devices:
            print "[+] parsing USB"
            self.USB()
            print "[+] parsing MountedDevices"
            self.MountedDevices()
            print "[+] parsing DeviceClasses"
            self.DeviceClasses()
            # software hive
            self.regapi.reset_current()
            self.regapi.set_current(hive_name = "software")
            print "[+] parsing WindowsPortableDevices"
            self.WindowsPortableDevices()
            print "[+] parsing EMDMgmt"
            self.EMDMgmt()
            # ntuser.dat hive
            self.regapi.reset_current()
            self.regapi.set_current(hive_name = "ntuser.dat")
            print "[+] parsing MountPoints2"
            self.MountPoints2()
            # setupapi log - TODO
        for serial in self.usb_devices:
            yield serial, self.usb_devices[serial]

    def render_text(self, outfd, data):
        for serial, info in data:
            outfd.write("**************************************************\n")
            if "vendor" in info:
                outfd.write("vendor: {0}\n".format(info["vendor"]))
            if "product" in info:
                outfd.write("product: {0}\n".format(info["product"]))
            if "version" in info:
                outfd.write("version: {0}\n".format(info["version"]))
            if "device_name" in info:
                outfd.write("device name: {0}\n".format(info["device_name"]))
            outfd.write("serial no: {0}\n".format(serial))
            if "vid" in info:
                outfd.write("vid: {0}\n".format(info["vid"]))
            if "pid" in info:
                outfd.write("pid: {0}\n".format(info["pid"]))
            if "parent_prefix_id" in info:
                outfd.write("parent prefix id: {0}\n".format(info["parent_prefix_id"]))
            if "drive_letter" in info:
                outfd.write("drive letter: {0}\n".format(info["drive_letter"]))
            if "volume_name" in info:
                outfd.write("volume name: {0}\n".format(info["volume_name"]))
            if "volume_serial_no" in info:
                outfd.write("volume serial no: {0}\n".format(info["volume_serial_no"]))
            if "guid" in info:
                outfd.write("guid: {0}\n".format(info["guid"]))
            if "associated_user" in info:
                outfd.write("associated user: {0}\n".format(", ".join(info["associated_user"])))
            if "vid_pid" in info["time"]:
                outfd.write("vid/pid key update: {0}\n".format(info["time"]["vid_pid"]))
            if "ven_prod_rev" in info["time"]:
                outfd.write("ven/prod/rev key update: {0}\n".format(info["time"]["ven_prod_rev"]))
            if "disk_device" in info["time"]:
                outfd.write("disk device update: {0}\n".format(info["time"]["disk_device"]))
            if "volume_device" in info["time"]:
                outfd.write("volume device update: {0}\n".format(info["time"]["volume_device"]))
            if "install_date" in info["time"]:
                outfd.write("install date: {0}\n".format(info["time"]["install_date"]))
            if "first_install_date" in info["time"]:
                outfd.write("first install date: {0}\n".format(info["time"]["first_install_date"]))
            if "last_arrival_date" in info["time"]:
                outfd.write("last arrival date: {0}\n".format(info["time"]["last_arrival_date"]))
            if "last_removal_date" in info["time"]:
                outfd.write("last removal date: {0}\n".format(info["time"]["last_removal_date"]))