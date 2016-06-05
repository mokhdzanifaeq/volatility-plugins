#pylint: disable-msg=C0111

import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.common as common
import volatility.utils as utils
from volatility.renderers import TreeGrid
from collections import OrderedDict

class UsbParser(common.AbstractWindowsCommand):
    "parse usb information from registry"

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self.regapi = None
        self.usb_devices = {}

    usb_struct = [
        "Vendor",
        "Product",
        "Version",
        "Device name",
        "VID",
        "PID",
        "GUID",
        "Parent prefix ID",
        "Drive letter",
        "Volume name",
        "Volume serial number",
        "Associated user",
        "Ven/Prod/Rev key update",
        "VID/PID key update",
        "Disk device update",
        "Volume device update",
        "Install date",
        "First install date",
        "Last arrival date",
        "Last removal date"
    ]

    def USBSTOR(self):
        usbstor = self.regapi.reg_get_currentcontrolset() + "\\Enum\\USBSTOR"
        for subkey in self.regapi.reg_get_all_subkeys(None, key = usbstor):
            device = OrderedDict((name, "") for name in self.usb_struct)
            part = subkey.Name.split("&")
            if part[0].lower() != "disk":
                continue
            if len(part) == 4:
                device["Vendor"] = part[1][4:]
                device["Product"] = part[2][5:]
                device["Version"] = part[3][4:]
            for serial in self.regapi.reg_get_all_subkeys(None, key = usbstor + "\\" + subkey.Name):
                device["Ven/Prod/Rev key update"] = serial.LastWriteTime
                serial_part = serial.Name.split('&')
                serial_no = serial_part[0] if len(serial_part) == 2 else serial.Name
                val = self.regapi.reg_get_value(None, key = usbstor + "\\" + subkey.Name + "\\" + serial.Name, value = "FriendlyName")
                if val:
                    device["Device name"] = utils.remove_unprintable(val)
                val = self.regapi.reg_get_value(None, key = usbstor + "\\" + subkey.Name + "\\" + serial.Name, value = "ParentIdPrefix")
                if val:
                    device["Parent prefix ID"] = utils.remove_unprintable(val)
                for properties in self.regapi.reg_get_all_subkeys(None, key = usbstor + "\\" + subkey.Name + "\\" + serial.Name + "\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}"):
                    name = str(properties.Name)
                    if "0064" in name:
                        device["Install date"] = properties.LastWriteTime
                    elif "0065" in name:
                        device["First install date"] = properties.LastWriteTime
                    elif "0066" in name:
                        device["Last arrival date"] = properties.LastWriteTime
                    elif "0067" in name:
                        device["Last removal date"] = properties.LastWriteTime
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
                    self.usb_devices[serial_no]["VID"] = id_part[0][4:]
                    self.usb_devices[serial_no]["PID"] = id_part[1][4:]
                    self.usb_devices[serial_no]["VID/PID key update"] = subkey.LastWriteTime

    def MountedDevices(self):
        mounted = self.regapi.reg_yield_values(None, key = "MountedDevices", thetype = "REG_BINARY")
        for serial in self.usb_devices:
            for value, data in mounted:
                data = utils.remove_unprintable(data)
                value = str(value)
                if "Volume" in value:
                    if self.usb_devices[serial]["Parent prefix ID"]:
                        if self.usb_devices[serial]["Parent prefix ID"] in data:
                            self.usb_devices[serial]["GUID"] = value[11:-1]
                    else:
                        if serial in data:
                            self.usb_devices[serial]["GUID"] = value[11:-1]
                if "DosDevices" in value:
                    if self.usb_devices[serial]["Parent prefix ID"]:
                        if self.usb_devices[serial]["Parent prefix ID"] in data:
                            self.usb_devices[serial]["Drive letter"] = value[12:]
                    else:
                        if serial in data:
                            self.usb_devices[serial]["Drive letter"] = value[12:]
                if self.usb_devices[serial]["Drive letter"] and self.usb_devices[serial]["GUID"]:
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
                self.usb_devices[serial_no]["Disk device update"] = disk.LastWriteTime
        for volume in self.regapi.reg_get_all_subkeys(None, key = device_class + "\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"):
            name = str(volume.Name)
            if not 'USBSTOR#DISK' in name:
                continue
            part = name.split("USBSTOR#DISK&")[1].split("#")[1]
            serial_part = part.split("&")
            serial_no = serial_part[0] if len(serial_part) == 2 else part
            if serial_no in self.usb_devices:
                self.usb_devices[serial_no]["Volume device update"] = volume.LastWriteTime

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
                    self.usb_devices[serial_no]["Volume name"] = utils.remove_unprintable(val)

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
                if not self.usb_devices[serial_no]["Volume name"]:
                    self.usb_devices[serial_no]["Volume name"] = data[0]
                self.usb_devices[serial_no]["Volume serial number"] = data[1]

    def MountPoints2(self):
        for serial in self.usb_devices:
            user = []
            if not self.usb_devices[serial]["GUID"]:
                continue
            for name, path in self.regapi.reg_yield_key(None, key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\{" + self.usb_devices[serial]["GUID"] + "}"):
                part = path.split("\\")
                user.append(part[-2])
            self.usb_devices[serial]["Associated user"] = ', '.join(user)

    def calculate(self):
        self.regapi = registryapi.RegistryApi(self._config)
        # system hive
        self.regapi.reset_current()
        self.regapi.set_current(hive_name = "system")
        print "parsing system hive..."
        self.USBSTOR()
        if self.usb_devices:
            self.USB()
            self.MountedDevices()
            self.DeviceClasses()
            # software hive
            self.regapi.reset_current()
            self.regapi.set_current(hive_name = "software")
            print "parsing software hive..."
            self.WindowsPortableDevices()
            self.EMDMgmt()
            # ntuser.dat hive
            self.regapi.reset_current()
            self.regapi.set_current(hive_name = "ntuser.dat")
            print "parsing ntuser.dat hive..."
            self.MountPoints2()
            # setupapi log - TODO
        for serial in self.usb_devices:
            yield serial, self.usb_devices[serial]

    def unified_output(self, data):
        return TreeGrid([("Serial number", str)] + [(name, str) for name in self.usb_struct], self.generator(data))

    def generator(self, data):
        for serial, info in data:
            yield (0, [str(serial)] + [str(value) for value in info.values()])

    def render_text(self, outfd, data):
        for serial, info in data:
            outfd.write("**************************************************\n")
            outfd.write("serial no: {0}\n".format(serial))
            for name, value in info.iteritems():
                if value:
                    outfd.write("{0}: {1}\n".format(name, value))
