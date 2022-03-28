"use strict";

/*
 * Created with @iobroker/create-adapter v2.0.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios");
const qs = require("qs");
const crypto = require("crypto");
const Json2iob = require("./lib/json2iob");
const tough = require("tough-cookie");
const { HttpsCookieAgent } = require("http-cookie-agent");

class Porsche extends utils.Adapter {
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: "porsche",
        });
        this.on("ready", this.onReady.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));
        this.deviceArray = [];
        this.json2iob = new Json2iob(this);
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Reset the connection indicator during startup
        this.setState("info.connection", false, true);
        if (this.config.interval < 0.5) {
            this.log.info("Set interval to minimum 0.5");
            this.config.interval = 0.5;
        }
        if (!this.config.username || !this.config.password) {
            this.log.error("Please set username and password in the instance settings");
            return;
        }
        this.userAgent = "ioBroker v0.0.1";
        this.cookieJar = new tough.CookieJar();
        this.requestClient = axios.create({
            jar: this.cookieJar,
            withCredentials: true,
            httpsAgent: new HttpsCookieAgent({
                jar: this.cookieJar,
            }),
        });

        this.updateInterval = null;
        this.reLoginTimeout = null;
        this.refreshTokenTimeout = null;
        this.session = {};
        this.subscribeStates("*");

        await this.login();

        if (this.session.access_token) {
            await this.getDeviceList();
            await this.updateDevices();
            this.updateInterval = setInterval(async () => {
                await this.updateDevices();
            }, this.config.interval * 60 * 1000);
            this.refreshTokenInterval = setInterval(() => {
                this.refreshToken();
            }, this.session.expires_in * 1000);
        }
    }
    async login() {
        const [code_verifier, codeChallenge] = this.getCodeChallenge();
        const resumeUrl = await this.requestClient({
            method: "get",
            url:
                "https://login.porsche.com/as/authorization.oauth2?client_id=L20OiZ0kBgWt958NWbuCB8gb970y6V6U&response_type=code&redirect_uri=One-Product-App://porsche-id/oauth2redirect&scope=openid%20magiclink%20mbb&display=touch&country=de&locale=de_DE&code_challenge=" +
                codeChallenge +
                "&code_challenge_method=S256",
            headers: {
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "de-de",
                "User-Agent": this.userAgent,
            },
            jar: this.cookieJar,
            withCredentials: true,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.log.debug(res.request.path);
                return res.request.path.split("resume=")[1].split("&")[0];
            })
            .catch((error) => {
                this.log.error(error);
                if (error.response) {
                    this.log.error(JSON.stringify(error.response.data));
                }
            });

        await this.requestClient({
            method: "post",
            url: "https://login.porsche.com/auth/api/v1/de/de_DE/public/login",
            headers: {
                Origin: "https://login.porsche.com",
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "User-Agent": this.userAgent,
                "Accept-Language": "de-de",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            jar: this.cookieJar,
            withCredentials: true,
            data: qs.stringify({
                keeploggedin: "true",
                mobileApp: "true",
                sec: "high",
                resume: resumeUrl,
                thirdPartyId: "",
                state: "",
                "hidden-password": "",
                username: this.config.username,
                "country-code-select": "+86",
                phoneNumber: "",
                password: this.config.password,
                code: "",
            }),
            maxRedirects: 0,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                return;
            })
            .catch((error) => {
                if (error.response && error.response.status === 302) {
                    return;
                }
                this.log.error(error);
                if (error.response) {
                    this.log.error(JSON.stringify(error.response.data));
                }
            });

        const code = await this.requestClient({
            method: "get",
            url: "https://login.porsche.com" + resumeUrl,
            headers: {
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "de-de",
                "User-Agent": this.userAgent,
            },
            jar: this.cookieJar,
            withCredentials: true,
            maxRedirects: 0,
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.log.debug(res.request.path);
                return;
            })
            .catch((error) => {
                if (error.response && error.response.status === 302) {
                    return error.response.headers.location.split("code=")[1];
                }

                this.log.error(error);
                if (error.response) {
                    this.log.error(JSON.stringify(error.response.data));
                }
            });

        await this.requestClient({
            method: "post",
            url: "https://login.porsche.com/as/token.oauth2",
            headers: {
                Accept: "*/*",
                "User-Agent": this.userAgent,
                "Accept-Language": "de",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data: qs.stringify({
                client_id: "L20OiZ0kBgWt958NWbuCB8gb970y6V6U",
                code: code,
                code_verifier: code_verifier,
                grant_type: "authorization_code",
                redirect_uri: "One-Product-App://porsche-id/oauth2redirect",
            }),
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.setState("info.connection", true, true);
            })
            .catch((error) => {
                this.log.error(error);
                if (error.response) {
                    this.log.error(JSON.stringify(error.response.data));
                }
            });
    }
    async getDeviceList() {
        await this.requestClient({
            method: "get",
            url: "https://api.ppa.porsche.com/app/connect/v1/vehicles",
            headers: {
                accept: "*/*",
                "x-client-id": "52064df8-6daa-46f7-bc9e-e3232622ab26",
                authorization: "Bearer " + this.session.access_token,
                "user-agent": this.userAgent,
                "accept-language": "de",
            },
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));

                for (const device of res.data) {
                    this.deviceArray.push(device.vin);
                    let name = device.modelName;
                    if (device.customName) {
                        name += " " + device.customName;
                    }
                    await this.setObjectNotExistsAsync(device.vin, {
                        type: "device",
                        common: {
                            name: name,
                        },
                        native: {},
                    });
                    await this.setObjectNotExistsAsync(device.vin + ".remote", {
                        type: "channel",
                        common: {
                            name: "Remote Controls",
                        },
                        native: {},
                    });
                    await this.setObjectNotExistsAsync(device.vin + ".general", {
                        type: "channel",
                        common: {
                            name: "General Information",
                        },
                        native: {},
                    });

                    const remoteArray = [
                        { command: "REMOTE_HEATING_START", name: "True = Start" },
                        { command: "REMOTE_CLIMATIZER-temperature", name: "REMOTE_CLIMATIZER Temperature", type: "number", role: "value" },
                        { command: "REMOTE_HEATING_STOP", name: "True = Stop" },
                        { command: "REMOTE_ACV_START", name: "True = Start" },
                        { command: "REMOTE_ACV_STOP", name: "True = Stop" },
                        { command: "REMOTE_CLIMATIZER_START", name: "True = Start" },
                        { command: "REMOTE_CLIMATIZER_STOP", name: "True = Stop" },
                        { command: "LOCK", name: "True = Lokc" },
                        { command: "UNLOCK", name: "True = Unlock" },
                        { command: "Refresh", name: "True = Refresh" },
                    ];
                    remoteArray.forEach((remote) => {
                        this.setObjectNotExists(device.vin + ".remote." + remote.command, {
                            type: "state",
                            common: {
                                name: remote.name || "",
                                type: remote.type || "boolean",
                                role: remote.role || "boolean",
                                write: true,
                                read: true,
                            },
                            native: {},
                        });
                    });
                    this.json2iob.parse(device.vin + ".general", device);
                    await this.requestClient({
                        method: "get",
                        url: "https://api.ppa.porsche.com/app/connect/v1/vehicles/" + device.vin + "/pictures",
                        headers: {
                            accept: "*/*",
                            "x-client-id": "52064df8-6daa-46f7-bc9e-e3232622ab26",
                            authorization: "Bearer " + this.session.access_token,
                            "user-agent": this.userAgent,
                            "accept-language": "de",
                        },
                    })
                        .then(async (res) => {
                            this.log.debug(JSON.stringify(res.data));
                            this.json2iob.parse(device.vin + ".pictures", res.data, { preferedArrayName: "view" });
                        })
                        .catch((error) => {
                            this.log.error(error);
                            error.response && this.log.error(JSON.stringify(error.response.data));
                        });
                }
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    async updateDevices() {
        const statusArray = [
            {
                path: "status",
                url: "https://api.ppa.porsche.com/app/connect/v1/vehicles/$vin?mf=ACV_STATE&mf=BATTERY_CHARGING_STATE&mf=BATTERY_LEVEL&mf=BATTERY_TYPE&mf=BLEID_DDADATA&mf=CAR_ALARMS_HISTORY&mf=CHARGING_PROFILES&mf=CLIMATIZER_STATE&mf=E_RANGE&mf=FUEL_LEVEL&mf=FUEL_RESERVE&mf=GLOBAL_PRIVACY_MODE&mf=GPS_LOCATION&mf=HEATING_STATE&mf=INTERMEDIATE_SERVICE_RANGE&mf=INTERMEDIATE_SERVICE_TIME&mf=LOCATION_ALARMS&mf=LOCATION_ALARMS_HISTORY&mf=LOCK_STATE_VEHICLE&mf=MAIN_SERVICE_RANGE&mf=MAIN_SERVICE_TIME&mf=MILEAGE&mf=OIL_LEVEL_CURRENT&mf=OIL_LEVEL_MAX&mf=OIL_LEVEL_MIN_WARNING&mf=OIL_SERVICE_RANGE&mf=OIL_SERVICE_TIME&mf=OPEN_STATE_CHARGE_FLAP_LEFT&mf=OPEN_STATE_CHARGE_FLAP_RIGHT&mf=OPEN_STATE_DOOR_FRONT_LEFT&mf=OPEN_STATE_DOOR_FRONT_RIGHT&mf=OPEN_STATE_DOOR_REAR_LEFT&mf=OPEN_STATE_DOOR_REAR_RIGHT&mf=OPEN_STATE_LID_FRONT&mf=OPEN_STATE_LID_REAR&mf=OPEN_STATE_SERVICE_FLAP&mf=OPEN_STATE_SPOILER&mf=OPEN_STATE_SUNROOF&mf=OPEN_STATE_TOP&mf=OPEN_STATE_WINDOW_FRONT_LEFT&mf=OPEN_STATE_WINDOW_FRONT_RIGHT&mf=OPEN_STATE_WINDOW_REAR_LEFT&mf=OPEN_STATE_WINDOW_REAR_RIGHT&mf=PARKING_LIGHT&mf=RANGE&mf=REMOTE_ACCESS_AUTHORIZATION&mf=SERVICE_PREDICTIONS&mf=SPEED_ALARMS&mf=SPEED_ALARMS_HISTORY&mf=THEFT_MODE&mf=TIMERS&mf=TRIP_STATISTICS_CYCLIC&mf=TRIP_STATISTICS_LONG_TERM&mf=TRIP_STATISTICS_SHORT_TERM&mf=VALET_ALARM&mf=VALET_ALARM_HISTORY&mf=VTS_MODES",
                desc: "Status of the car",
            },
        ];

        const headers = {
            accept: "*/*",
            "x-client-id": "52064df8-6daa-46f7-bc9e-e3232622ab26",
            authorization: "Bearer " + this.session.access_token,
            "user-agent": this.userAgent,
            "accept-language": "de",
        };
        for (const vin of this.deviceArray) {
            for (const element of statusArray) {
                const url = element.url.replace("$vin", vin);

                await this.requestClient({
                    method: "get",
                    url: url,
                    headers: headers,
                })
                    .then((res) => {
                        this.log.debug(JSON.stringify(res.data));
                        if (!res.data) {
                            return;
                        }
                        const data = res.data;

                        const forceIndex = null;
                        const preferedArrayName = null;

                        this.json2iob.parse(vin + "." + element.path, data, { forceIndex: forceIndex, preferedArrayName: preferedArrayName, channelName: element.desc });
                    })
                    .catch((error) => {
                        if (error.response) {
                            if (error.response.status === 401) {
                                error.response && this.log.debug(JSON.stringify(error.response.data));
                                this.log.info(element.path + " receive 401 error. Refresh Token in 60 seconds");
                                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                                this.refreshTokenTimeout = setTimeout(() => {
                                    this.refreshToken();
                                }, 1000 * 60);

                                return;
                            }
                        }
                        this.log.error(url);
                        this.log.error(error);
                        error.response && this.log.error(JSON.stringify(error.response.data));
                    });
            }
        }
    }
    async refreshToken() {
        if (!this.session) {
            this.log.error("No session found relogin");
            await this.login();
            return;
        }
        await this.requestClient({
            method: "post",
            url: "https://login.porsche.com/as/token.oauth2",
            headers: {
                Accept: "*/*",
                "User-Agent": this.userAgent,
                "Accept-Language": "de",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data: qs.stringify({
                client_id: "L20OiZ0kBgWt958NWbuCB8gb970y6V6U",
                grant_type: "refresh_token",
                refresh_token: this.session.refresh_token,
            }),
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.setState("info.connection", true, true);
            })
            .catch((error) => {
                this.log.error("refresh token failed");
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
                this.log.error("Start relogin in 1min");
                this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
                this.reLoginTimeout = setTimeout(() => {
                    this.login();
                }, 1000 * 60 * 1);
            });
    }

    getCodeChallenge() {
        let hash = "";
        let result = "";
        const chars = "0123456789abcdef";
        result = "";
        for (let i = 64; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
        hash = crypto.createHash("sha256").update(result).digest("base64");
        hash = hash.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

        return [result, hash];
    }
    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    onUnload(callback) {
        try {
            this.setState("info.connection", false, true);
            this.refreshTimeout && clearTimeout(this.refreshTimeout);
            this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
            this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
            this.updateInterval && clearInterval(this.updateInterval);
            this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
            callback();
        } catch (e) {
            callback();
        }
    }

    /**
     * Is called if a subscribed state changes
     * @param {string} id
     * @param {ioBroker.State | null | undefined} state
     */
    async onStateChange(id, state) {
        if (state) {
            if (!state.ack) {
                const deviceId = id.split(".")[2];
                const command = id.split(".")[4];
                if (id.split(".")[3] !== "remote") {
                    return;
                }
                if (command === "REMOTE_CLIMATIZER-temperature") {
                    return;
                }
                if (command === "Refresh") {
                    this.updateDevices();
                }

                const data = {
                    payload: {},
                    key: command,
                };
                if (command === "REMOTE_CLIMATIZER_START") {
                    const temperatureState = await this.getStateAsync(deviceId + ".remote.REMOTE_CLIMATIZER-temperature");
                    if (temperatureState) {
                        data.payload.temperature = temperatureState.val ? temperatureState.val : 22;
                    } else {
                        data.payload.temperature = 22;
                    }
                }

                this.log.debug(JSON.stringify(data));

                await this.requestClient({
                    method: "post",
                    url: "https://api.ppa.porsche.com/app/connect/v1/vehicles/" + deviceId + "/commands",
                    headers: {
                        accept: "*/*",
                        "x-client-id": "52064df8-6daa-46f7-bc9e-e3232622ab26",
                        "content-type": "application/json",
                        "accept-language": "de",
                        authorization: "Bearer " + this.session.access_token,
                        "user-agent": this.userAgent,
                    },
                    data: data,
                })
                    .then((res) => {
                        this.log.info(JSON.stringify(res.data));
                        return res.data;
                    })
                    .catch((error) => {
                        this.log.error(error);
                        if (error.response) {
                            this.log.error(JSON.stringify(error.response.data));
                        }
                    });
                this.refreshTimeout && clearTimeout(this.refreshTimeout);
                this.refreshTimeout = setTimeout(async () => {
                    await this.updateDevices();
                }, 10 * 1000);
            }
        }
    }
}

if (require.main !== module) {
    // Export the constructor in compact mode
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    module.exports = (options) => new Porsche(options);
} else {
    // otherwise start the instance directly
    new Porsche();
}
