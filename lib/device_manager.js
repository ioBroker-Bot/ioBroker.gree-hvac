const EventEmitter = require('node:events');
const Connection = require('./connection');
const { defaultKey, defaultKeyGCM } = require('./encryptor');
const TEMPERATURE_SENSOR_OFFSET = -40;

// https://github.com/tomikaa87/gree-remote
const statusKeys = [
    'Pow', 'Mod', 'TemUn', 'SetTem', 'TemRec', 'WdSpd', 'Air',
    'Blo', 'Health', 'SwhSlp', 'Lig', 'SwingLfRig', 'SwUpDn',
    'Quiet', 'Tur', 'SvSt', 'TemSen', 'time'
];

const DeviceScanTimeoutMs = 5000;

class DeviceManager extends EventEmitter {

    logger;

    constructor(devicesList, logger, requestTimeoutMs = 1000) {
        super();
        this.logger = logger;
        this.connection = new Connection(devicesList, logger, requestTimeoutMs);
        this.devices = {};
        this.rescanDevices(devicesList);
        this.connection.on('dev', this._registerDevice.bind(this));
    }

    rescanDevices(devicesList) {
        const rescanTimeout = setTimeout(() => {
            const items = devicesList.split(';');
            const readyDevices = Object.keys(this.devices).map((key) => this.devices[key].address);
            const rescanItems = items.filter((item) => !readyDevices.includes(item));
            if (rescanItems.length === 0) {
                return;
            }
            const addresses = rescanItems.join(';');
            try {
                this.connection.scan(addresses);
            } catch { } // eslint-disable-line no-empty
            clearTimeout(rescanTimeout);
            this.rescanDevices(devicesList);
        }, DeviceScanTimeoutMs);
    }

    async sendRegisterDevice(message, rinfo, encVersion) {
        const deviceId = message.cid || message.mac;
        this.logger.info(`New device found: ${message.name} (mac: ${deviceId}), binding encVer ${encVersion}...`);
        const { address, port } = rinfo;

        try {
            const { key } = await this.connection.sendRequest(address, port, {
                cid: 'app',
                tcid: deviceId,
                mac: deviceId,
                t: 'bind',
                uid: 0
            }, encVersion);

            if (key) {
                const device = {
                    ...message,
                    address,
                    port,
                    key,
                    encVersion,
                    t: undefined
                };

                this.devices[deviceId] = device;

                this.connection.registerKey(rinfo.address, key);
                this.connection.registerEncVersion(address, encVersion);

                this.emit('device_bound', deviceId, device);
                this.logger.info(`New device bound: ${device.name} (${device.address}:${device.port}) with encryption v${encVersion}`);

                return device;
            }
            return null;
        } catch (e) {
            this.logger.error(`Failed to bind device ${deviceId}: ${e.message}`);
            this.logger.error(e.stack);
            return null;
        }
    }

    async _registerDevice(message, rinfo) {
        let encVersion = this.connection.getEncVersion(rinfo.address);
        let device;
        try {
            device = await this.sendRegisterDevice(message, rinfo, encVersion);
            if (!device) {
                this.logger.info(`Registering failed, trying next encVer...`);
                this.connection.registerEncVersion(rinfo.address, (encVersion) % 2 + 1); //increase encryption version
                encVersion = this.connection.getEncVersion(rinfo.address);
                //set proper default keys for binding
                if (encVersion == 1) {
                    this.connection.registerKey(rinfo.address, defaultKey);
                } else if (encVersion == 2) {
                    this.connection.registerKey(rinfo.address, defaultKeyGCM);
                }
                device = await this.sendRegisterDevice(message, rinfo, encVersion);
            }
        } catch (e) {
            this.logger.error(e.stack);
        }
        return device;
    }

    getDevices() {
        return Object.values(this.devices);
    }

    async getDeviceStatus(deviceId) {
        const device = this.devices[deviceId];

        if (!device) {
            throw new Error(`Device ${deviceId} not found`);
        }

        const payload = {
            cols: statusKeys,
            mac: device.mac,
            t: 'status'
        };

        const response = await this.connection.sendRequest(device.address, device.port, payload);
        const deviceStatus = response.cols.reduce((acc, key, index) => ({
            ...acc,
            [key]: response.dat[index]
        }), {});

        if ('TemSen' in deviceStatus) {
            deviceStatus['TemSen'] += TEMPERATURE_SENSOR_OFFSET;
        }

        this.emit('device_status', deviceId, deviceStatus);
        return deviceStatus;
    }

    async setDeviceState(deviceId, state) {
        const device = this.devices[deviceId];

        if (!device) {
            return null;
        }

        const payload = {
            mac: device.mac,
            opt: Object.keys(state),
            p: Object.values(state),
            t: 'cmd'
        };

        const response = await this.connection.sendRequest(device.address, device.port, payload);
        const deviceStatus = response.opt.reduce((acc, key, index) => ({
            ...acc,
            [key]: response.p[index]
        }), {});

        this.emit('device_status', deviceId, deviceStatus);
        return deviceStatus;
    }
}

module.exports = DeviceManager;
