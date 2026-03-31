const dgram = require('node:dgram');
const EventEmitter = require('node:events');
const { encryptV1, decryptV1, defaultKey, defaultKeyGCM, encryptV2, decryptV2 } = require('./encryptor');

const commandsMap = {
    'bind': 'bindok',
    'status': 'dat',
    'cmd': 'res'
};

class Connection extends EventEmitter {

    requestTimeoutMs;
    logger;

    constructor(address, logger, requestTimeoutMs = 1000) {
        super();
        this.logger = logger;
        this.socket = dgram.createSocket('udp4');
        this.socketScan = dgram.createSocket('udp4');
        this.devices = {};
        this.requestTimeoutMs = requestTimeoutMs;
        this.deviceEncVer = {};

        this.socketScan.on('message', this.handleResponse.bind(this));

        this.socketScan.on('listening', () => {
            const socketAddress = this.socketScan.address();
            this.logger.info(`Socket server is listening on ${socketAddress.address}:${socketAddress.port}`);

            this.scan(address);
        });

        this.socket.on('error', (error) => {
            this.logger.error(error.message);
        });
        this.socketScan.on('error', (error) => {
            this.logger.error(error.message);
        });

        this.socket.bind();
        this.socketScan.bind();
    }

    registerKey(deviceId, key) {
        this.logger.debug(`Registering key: ${deviceId} - ${key}`);
        this.devices[deviceId] = key;
    }

    getEncryptionKey(deviceId) {
        return this.devices[deviceId] || defaultKey;
    }

    registerEncVersion(deviceId, encVer) {
        this.logger.debug(`Registering encVer: ${deviceId} - ${encVer}`);
        this.deviceEncVer[deviceId] = encVer;
    }

    getEncVersion(deviceId) {
        return this.deviceEncVer[deviceId] || 1;
    }

    scan(ipAddresses) {
        const message = Buffer.from(JSON.stringify({ cid: 'app', t: 'scan', i: 1, uid: 0 }));

        ipAddresses.split(';').forEach((deviceAddress) => {
            this.logger.debug(`Test address ${deviceAddress} for available device with message: ${message}`);
            this.socketScan.send(message, 0, message.length, 7000, deviceAddress);
        });
    }

    async sendRequest(address, port, payload, encVersion) {
        return new Promise((resolve, reject) => {
            let requestTimeout;
            try {
                let pack;
                let tag;
                const key = this.getEncryptionKey(address);
                if (encVersion == undefined) {
                    encVersion = this.getEncVersion(address);
                }
                if (encVersion == 1) {
                    pack = encryptV1(payload, key);
                } else {
                    const { encPack, encTag } = encryptV2(payload, key);
                    pack = encPack;
                    tag = encTag;
                }

                this.logger.debug(`Payload: ${JSON.stringify(payload)}`);
                this.logger.debug(`key: ${key}`);
                this.logger.debug(`pack: ${pack}`);
                this.logger.debug(`tag: ${tag}`);
                this.logger.debug(`encVersion: ${encVersion}`);
                const request = {
                    cid: 'app',
                    i: payload.t === 'bind' ? 1 : key === defaultKey ? 1 : 0,
                    t: 'pack',
                    uid: 0,
                    tcid: payload.mac,
                    pack: pack,
                    tag: tag,
                };

                const messageHandler = (msg, rinfo) => {
                    const message = JSON.parse(msg.toString());
                    this.logger.debug(`Received message from ${message.cid} (${rinfo.address}:${rinfo.port}) ${msg.toString()} - ${JSON.stringify(rinfo)}`);
                    let response;

                    // Check device address data
                    if (rinfo.address !== address || rinfo.port !== port) {
                        return;
                    }

                    const decKey = this.getEncryptionKey(rinfo.address);
                    //const decTag = payload.t === 'bind' ? undefined : message.tag;
                    const decTag = message.tag;
                    let encVersion = decTag != undefined ? 2 : 1;
                    if (encVersion == 2) {
                        this.registerEncVersion(rinfo.address, encVersion);
                    } else {
                        encVersion = this.getEncVersion(rinfo.address);
                    }
                    this.logger.debug(`decKey: ${decKey}`);
                    this.logger.debug(`decTag: ${decTag}`);
                    this.logger.debug(`encVersion: ${encVersion}`);

                    try {
                        if (encVersion == 1) {
                            response = decryptV1(message.pack, decKey);
                        } else if (encVersion == 2) {
                            response = decryptV2(message.pack, decKey, decTag);
                        }
                        this.logger.debug(`sendRequest - Response data: ${JSON.stringify(response)}`);
                    } catch (e) {
                        this.logger.error(`Can not decrypt message from ${message.cid} (${rinfo.address}:${rinfo.port}) with key ${decKey} and tag ${decTag}`);
                        this.logger.error(e.stack);
                        return;
                    }

                    if (response.t !== commandsMap[payload.t]) {
                        this.logger.debug(`No matching command: ${response.t}`);
                        return;
                    }

                    if (response.mac !== payload.mac) {
                        this.logger.debug(`No matching mac ${response.mac} - ${payload.mac}`);
                        return;
                    }

                    if (this.socket && this.socket.off) {
                        this.socket.off('message', messageHandler);
                    }

                    clearTimeout(requestTimeout);
                    resolve(response);
                };

                this.logger.debug(`Sending request to ${address}:${port}: ${JSON.stringify(request)}`);

                this.socket.on('message', messageHandler);

                const toSend = Buffer.from(JSON.stringify(request));
                this.socket.send(toSend, 0, toSend.length, port, address);
                requestTimeout = setTimeout(() => {
                    clearTimeout(requestTimeout);
                    reject(new Error(`Request to ${address}:${port} timed out`));
                }, this.requestTimeoutMs);
            } catch (e) {
                this.logger.error(e.stack);
            }
        });
    }

    handleResponse(msg, rinfo) {
        let message, response;

        try {
            message = JSON.parse(msg.toString());
        } catch {
            this.logger.error(`Device ${rinfo.address}:${rinfo.port} sent invalid JSON that can not be parsed`);
            this.logger.debug(msg);
            return;
        }

        const tag = message.tag;
        const encVersion = tag != undefined ? 2 : 1;
        const key = encVersion == 1 ? defaultKey : defaultKeyGCM;

        this.logger.silly(`key: ${key}`);
        this.logger.silly(`tag: ${tag}`);
        this.logger.silly(`encVersion: ${encVersion}`);

        try {
            if (encVersion == 1) {
                response = decryptV1(message.pack, key);
            } else if (encVersion == 2) {
                response = decryptV2(message.pack, key, tag);
            }
            this.logger.debug(`handleResponse - Response data: ${JSON.stringify(response)}`);
        } catch (e) {
            this.logger.error(`handleResponse - Can not decrypt message from ${message.cid} (${rinfo.address}:${rinfo.port}) with key ${key} and tag ${tag}`);
            this.logger.error(e.stack);
            return;
        }

        this.emit(response.t, response, rinfo, encVersion);
    }
}

module.exports = Connection;
