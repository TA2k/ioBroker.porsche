'use strict';

/*
 * Created with @iobroker/create-adapter v2.0.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const qs = require('qs');
const Json2iob = require('json2iob');
const tough = require('tough-cookie');
const { v4: uuidv4 } = require('uuid');
const { HttpsCookieAgent } = require('http-cookie-agent/http');

class Porsche extends utils.Adapter {
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  constructor(options) {
    super({
      ...options,
      name: 'porsche',
    });
    this.on('ready', this.onReady.bind(this));
    this.on('stateChange', this.onStateChange.bind(this));
    this.on('unload', this.onUnload.bind(this));
    this.on('message', this.onMessage.bind(this));
    this.deviceArray = [];
    this.pendingCaptcha = null;
    this.json2iob = new Json2iob(this);
    this.lastForceRefresh = 0;
    this.cookieJar = new tough.CookieJar();
    this.requestClient = axios.create({
      withCredentials: true,
      httpsAgent: new HttpsCookieAgent({ cookies: { jar: this.cookieJar } }),
    });
    this.userAgent = 'pyporscheconnectapi/0.2.0';
    this.clientId = 'XhygisuebbrqQ80byOuU5VncxLIm8E6H';
    this.xClientId = '41843fb4-691d-4970-85c7-2673e8ecef40';
    this.redirectUri = 'my-porsche-app://auth0/callback';
    this.scope = 'openid profile email offline_access mbb ssodb badge vin dealers cars charging manageCharging plugAndCharge climatisation manageClimatisation pid:user_profile.porscheid:read pid:user_profile.name:read pid:user_profile.vehicles:read pid:user_profile.dealers:read pid:user_profile.emails:read pid:user_profile.phones:read pid:user_profile.addresses:read pid:user_profile.birthdate:read pid:user_profile.locale:read pid:user_profile.legal:read';
  }

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  async onReady() {
    // Reset the connection indicator during startup
    this.setState('info.connection', false, true);
    if (this.config.interval < 0.5) {
      this.log.info('Set interval to minimum 0.5');
      this.config.interval = 0.5;
    }
    if (!this.config.username || !this.config.password) {
      this.log.error('Please set username and password in the instance settings');
      return;
    }
    this.userAgent = 'ioBroker v' + this.version;
    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.subscribeStates('*');

    await this.login();

    if (this.session.access_token) {
      await this.getDeviceList();
      await this.updateDevices(true);
      this.updateInterval = setInterval(async () => {
        await this.updateDevices();
      }, this.config.interval * 60 * 1000);
      this.refreshTokenInterval = setInterval(() => {
        this.refreshToken();
      }, this.session.expires_in * 1000);
    }
  }
  async login() {
    this.log.info('Starting login process...');
    const headers = {
      'User-Agent': this.userAgent,
      'X-Client-ID': this.xClientId,
    };

    // Step 1: GET /authorize to get the state parameter
    let state;
    try {
      const authorizeUrl = `https://identity.porsche.com/authorize?response_type=code&client_id=${this.clientId}&redirect_uri=${encodeURIComponent(this.redirectUri)}&audience=${encodeURIComponent('https://api.porsche.com')}&scope=${encodeURIComponent(this.scope)}&state=pyporscheconnectapi`;

      const authorizeResponse = await this.requestClient({
        method: 'get',
        url: authorizeUrl,
        headers: headers,
        maxRedirects: 0,
        validateStatus: (status) => status === 302 || status === 200,
      });

      this.log.debug('Authorize response status: ' + authorizeResponse.status);

      if (authorizeResponse.status === 302) {
        const location = authorizeResponse.headers.location;
        this.log.debug('Redirect location: ' + location);

        // Check if we already have an authorization code (existing session)
        if (location && location.includes('code=')) {
          const urlParams = new URL(location, 'http://dummy').searchParams;
          const code = urlParams.get('code');
          if (code) {
            this.log.info('Using existing session, exchanging code for token...');
            await this.exchangeCodeForToken(code, headers);
            return;
          }
        }

        // Extract state from redirect URL
        const urlParams = new URL(location, 'https://identity.porsche.com').searchParams;
        state = urlParams.get('state');
      }
    } catch (error) {
      if (error.response && error.response.status === 302) {
        const location = error.response.headers.location;
        this.log.debug('Redirect location from error: ' + location);
        const urlParams = new URL(location, 'https://identity.porsche.com').searchParams;
        state = urlParams.get('state');
      } else {
        this.log.error('Error in authorize request: ' + error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
        return;
      }
    }

    if (!state) {
      this.log.error('No state found in authorize response');
      return;
    }

    this.log.debug('Got state: ' + state);
    this.log.info('Submitting username...');

    // Step 2: POST /u/login/identifier with email
    try {
      await this.requestClient({
        method: 'post',
        url: 'https://identity.porsche.com/u/login/identifier',
        params: { state: state },
        headers: {
          ...headers,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        data: qs.stringify({
          state: state,
          username: this.config.username,
          'js-available': 'true',
          'webauthn-available': 'false',
          'is-brave': 'false',
          'webauthn-platform-available': 'false',
          action: 'default',
        }),
        maxRedirects: 0,
        validateStatus: (status) => status === 302 || status === 200,
      });
      this.log.info('Username accepted, submitting password...');
    } catch (error) {
      if (error.response && error.response.status === 401) {
        this.log.error('Wrong credentials');
        return;
      }
      if (error.response && error.response.status === 400) {
        const html = error.response.data;
        const match = html.match(/<img[^>]+alt="captcha"[^>]+src="([^"]+)"/);
        if (match) {
          this.pendingCaptcha = {
            svg: match[1],
            state: state,
          };
          this.log.warn('Captcha required - please enter captcha code in admin config');
        } else {
          this.log.error('Captcha required but could not extract image');
        }
        return;
      }
      // 302 redirect is expected, continue
      if (!error.response || error.response.status !== 302) {
        this.log.error('Error in identifier step: ' + error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
        return;
      }
      this.log.info('Username accepted, submitting password...');
    }

    // Step 3: POST /u/login/password with password
    let resumePath;
    try {
      const passwordResponse = await this.requestClient({
        method: 'post',
        url: 'https://identity.porsche.com/u/login/password',
        params: { state: state },
        headers: {
          ...headers,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        data: qs.stringify({
          state: state,
          username: this.config.username,
          password: this.config.password,
          action: 'default',
        }),
        maxRedirects: 0,
        validateStatus: (status) => status === 302 || status === 200,
      });

      if (passwordResponse.status === 302) {
        resumePath = passwordResponse.headers.location;
        this.log.debug('Resume path: ' + resumePath);
      }
    } catch (error) {
      if (error.response && error.response.status === 302) {
        resumePath = error.response.headers.location;
        this.log.debug('Resume path from error: ' + resumePath);
      } else if (error.response && error.response.status === 400) {
        this.log.error('Invalid credentials');
        return;
      } else {
        this.log.error('Error in password step: ' + error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
        return;
      }
    }

    if (!resumePath) {
      this.log.error('No resume path found after password step');
      return;
    }

    this.log.info('Password accepted, completing authorization...');

    // Wait a bit before resuming (as in Python code)
    await new Promise((resolve) => setTimeout(resolve, 2500));

    // Step 4: Resume the authorization flow
    let authorizationCode;
    try {
      const resumeUrl = resumePath.startsWith('http') ? resumePath : `https://identity.porsche.com${resumePath}`;
      const resumeResponse = await this.requestClient({
        method: 'get',
        url: resumeUrl,
        headers: headers,
        maxRedirects: 0,
        validateStatus: (status) => status === 302 || status === 200,
      });

      if (resumeResponse.status === 302) {
        const location = resumeResponse.headers.location;
        this.log.debug('Final redirect location: ' + location);

        if (location && location.includes('code=')) {
          const urlParams = new URL(location, 'http://dummy').searchParams;
          authorizationCode = urlParams.get('code');
        }
      }
    } catch (error) {
      if (error.response && error.response.status === 302) {
        const location = error.response.headers.location;
        this.log.debug('Final redirect location from error: ' + location);

        if (location && location.includes('code=')) {
          const urlParams = new URL(location, 'http://dummy').searchParams;
          authorizationCode = urlParams.get('code');
        }
      } else {
        this.log.error('Error in resume step: ' + error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
        return;
      }
    }

    if (!authorizationCode) {
      this.log.error('No authorization code found. Please check your credentials');
      return;
    }

    this.log.debug('Got authorization code: ' + authorizationCode);
    this.log.info('Exchanging authorization code for token...');
    await this.exchangeCodeForToken(authorizationCode, headers);
  }

  async exchangeCodeForToken(code, headers) {
    await this.requestClient({
      method: 'post',
      url: 'https://identity.porsche.com/oauth/token',
      headers: {
        ...headers,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: qs.stringify({
        client_id: this.clientId,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: this.redirectUri,
      }),
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.session = res.data;
        this.log.info('Login successful!');
        this.setState('info.connection', true, true);
      })
      .catch((error) => {
        this.log.error('Error exchanging code for token: ' + error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
      });
  }
  async getDeviceList() {
    await this.requestClient({
      method: 'get',
      url: 'https://api.ppa.porsche.com/app/connect/v1/vehicles',
      headers: {
        accept: '*/*',
        'x-client-id': this.xClientId,
        authorization: 'Bearer ' + this.session.access_token,
        'user-agent': this.userAgent,
        'accept-language': 'de',
      },
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));

        for (const device of res.data) {
          this.deviceArray.push(device.vin);
          let name = device.modelName;
          if (device.customName) {
            name += ' ' + device.customName;
          }
          await this.setObjectNotExistsAsync(device.vin, {
            type: 'device',
            common: {
              name: name,
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(device.vin + '.remote', {
            type: 'channel',
            common: {
              name: 'Remote Controls',
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(device.vin + '.general', {
            type: 'channel',
            common: {
              name: 'General Information',
            },
            native: {},
          });

          const remoteArray = [
            // Heating
            { command: 'REMOTE_HEATING_START', name: 'Start Heating', desc: 'Start auxiliary heating' },
            { command: 'REMOTE_HEATING_STOP', name: 'Stop Heating', desc: 'Stop auxiliary heating' },
            // Climatizer (A/C with temperature)
            { command: 'REMOTE_CLIMATIZER_START', name: 'Start Climatizer', desc: 'Start air conditioning with set temperature' },
            { command: 'REMOTE_CLIMATIZER_STOP', name: 'Stop Climatizer', desc: 'Stop air conditioning' },
            { command: 'REMOTE_CLIMATIZER-temperature', name: 'Climatizer Temperature', desc: 'Target temperature for climatizer (Celsius)', type: 'number', role: 'value' },
            // ACV - Auxiliary Climatizer Ventilation
            { command: 'REMOTE_ACV_START', name: 'Start Ventilation', desc: 'Start auxiliary ventilation (10 min, no A/C)' },
            { command: 'REMOTE_ACV_STOP', name: 'Stop Ventilation', desc: 'Stop auxiliary ventilation' },
            // Direct Charging
            { command: 'DIRECT_CHARGING_START', name: 'Start Direct Charging', desc: 'Start immediate charging (bypasses timer/profiles)' },
            { command: 'DIRECT_CHARGING_STOP', name: 'Stop Direct Charging', desc: 'Stop immediate charging' },
            // Charging Control
            { command: 'CHARGING_START', name: 'Start Charging', desc: 'Start charging session' },
            { command: 'CHARGING_STOP', name: 'Stop Charging', desc: 'Stop current charging session' },
            // Lock/Unlock
            { command: 'LOCK', name: 'Lock Vehicle', desc: 'Lock all doors' },
            { command: 'UNLOCK', name: 'Unlock Vehicle', desc: 'Unlock all doors' },
            // Honk & Flash
            { command: 'HONK_FLASH', name: 'Honk & Flash', desc: 'Honk horn and flash lights to locate vehicle' },
            { command: 'HONK_FLASH-mode', name: 'Honk & Flash Mode', desc: 'Mode: HONK, FLASH, or HONK_AND_FLASH', type: 'string', role: 'text', states: { HONK: 'HONK', FLASH: 'FLASH', HONK_AND_FLASH: 'HONK_AND_FLASH' } },
            // Timer Control
            { command: 'TIMERS_DISABLE', name: 'Disable Timers', desc: 'Disable all charging/climate timers' },
            // Refresh
            { command: 'Refresh', name: 'Refresh Data', desc: 'Refresh vehicle data from cloud' },
            { command: 'Force_Refresh', name: 'Force Refresh', desc: 'Force wake-up vehicle and refresh data' },
          ];
          for (const remote of remoteArray) {
            const common = {
              name: remote.name || '',
              desc: remote.desc || '',
              type: /** @type {ioBroker.CommonType} */ (remote.type || 'boolean'),
              role: remote.role || 'boolean',
              write: true,
              read: true,
            };
            if (remote.states) {
              common.states = remote.states;
            }
            await this.setObjectNotExistsAsync(device.vin + '.remote.' + remote.command, {
              type: 'state',
              common: common,
              native: {},
            });
          }
          this.json2iob.parse(device.vin + '.general', device);
          await this.requestClient({
            method: 'get',
            url: 'https://api.ppa.porsche.com/app/connect/v1/vehicles/' + device.vin + '/pictures',
            headers: {
              accept: '*/*',
              'x-client-id': this.xClientId,
              authorization: 'Bearer ' + this.session.access_token,
              'user-agent': this.userAgent,
              'accept-language': 'de',
            },
          })
            .then(async (res) => {
              this.log.debug(JSON.stringify(res.data));
              this.json2iob.parse(device.vin + '.pictures', res.data, { preferedArrayName: 'view' });
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

  async updateDevices(forceRefresh) {
    if (Date.now() - this.lastForceRefresh > 1000 * 60 * 60 * 3) {
      // force refresh every 3 hour
      forceRefresh = true;
    }

    this.lastForceRefresh = Date.now();
    // Measurements from official Porsche App (de.porsche.one APK) + legacy measurements
    // Each measurement has a description for better understanding
    const measurementsWithDesc = {
      ACV_STATE: 'Auxiliary Climatizer Ventilation state',
      ALARM_STATE: 'Vehicle alarm system state',
      BATTERY_CHARGING_STATE: 'High-voltage battery charging state',
      BATTERY_LEVEL: 'High-voltage battery charge level (%)',
      BATTERY_TYPE: 'Battery type information',
      BEM_LEVEL: 'Battery Energy Management level',
      BLEID_DDADATA: 'Bluetooth LE identification data',
      CAR_ALARMS_HISTORY: 'History of triggered alarms',
      CHARGING_PROFILES: 'Configured charging profiles/schedules',
      CHARGING_RATE: 'Current charging rate (kW)',
      CHARGING_SETTINGS: 'Charging configuration settings',
      CHARGING_SUMMARY: 'Charging session summary',
      CLIMATIZER_STATE: 'Air conditioning/climatizer state',
      DEPARTURES: 'Scheduled departure times for preconditioning',
      DESTINATIONS: 'Saved navigation destinations',
      DIRECT_CHARGING: 'Direct/immediate charging state',
      E_CONSUMPTION_DATA: 'Electric energy consumption data',
      E_RANGE: 'Electric driving range (km)',
      FUEL_LEVEL: 'Fuel tank level (%)',
      FUEL_RESERVE: 'Fuel reserve warning state',
      GLOBAL_PRIVACY_MODE: 'Privacy mode state (disables remote access)',
      GLOBAL_TIMESTAMP: 'Last data update timestamp',
      GPS_LOCATION: 'Current GPS position',
      GUIDANCE_SETTINGS: 'Navigation guidance settings',
      HEATING_STATE: 'Auxiliary heating state',
      HVAC_STATE: 'Heating/Ventilation/AC state',
      HVAC_SUMMARY: 'HVAC system summary',
      INTERMEDIATE_SERVICE_RANGE: 'Distance until intermediate service (km)',
      INTERMEDIATE_SERVICE_TIME: 'Time until intermediate service',
      LOCATION_ALARMS: 'Geofence/location alarm settings',
      LOCATION_ALARMS_HISTORY: 'History of location alarm triggers',
      LOCK_STATE_VEHICLE: 'Door lock state',
      MAIN_SERVICE_RANGE: 'Distance until main service (km)',
      MAIN_SERVICE_TIME: 'Time until main service',
      MDK_ACTIVATION_STATE: 'Mobile Device Key activation state',
      MDK_CARD_STATE: 'Mobile Device Key card state',
      MDK_PAIRING_PASSWORD: 'Mobile Device Key pairing password',
      MDK_PAIRING_STATE: 'Mobile Device Key pairing state',
      MILEAGE: 'Total mileage (km)',
      OIL_LEVEL_CURRENT: 'Current oil level',
      OIL_LEVEL_MAX: 'Maximum oil level',
      OIL_LEVEL_MIN_WARNING: 'Oil level minimum warning threshold',
      OIL_SERVICE_RANGE: 'Distance until oil service (km)',
      OIL_SERVICE_TIME: 'Time until oil service',
      OPEN_STATE_CHARGE_FLAP_LEFT: 'Left charging flap open state',
      OPEN_STATE_CHARGE_FLAP_RIGHT: 'Right charging flap open state',
      OPEN_STATE_DOOR_FRONT_LEFT: 'Front left door open state',
      OPEN_STATE_DOOR_FRONT_RIGHT: 'Front right door open state',
      OPEN_STATE_DOOR_REAR_LEFT: 'Rear left door open state',
      OPEN_STATE_DOOR_REAR_RIGHT: 'Rear right door open state',
      OPEN_STATE_LID_FRONT: 'Front lid/hood open state',
      OPEN_STATE_LID_REAR: 'Rear lid/trunk open state',
      OPEN_STATE_SERVICE_FLAP: 'Service flap open state',
      OPEN_STATE_SPOILER: 'Spoiler position state',
      OPEN_STATE_SUNROOF: 'Sunroof open state',
      OPEN_STATE_SUNROOF_REAR: 'Rear sunroof open state',
      OPEN_STATE_TOP: 'Convertible top state',
      OPEN_STATE_WINDOW_FRONT_LEFT: 'Front left window open state',
      OPEN_STATE_WINDOW_FRONT_RIGHT: 'Front right window open state',
      OPEN_STATE_WINDOW_REAR_LEFT: 'Rear left window open state',
      OPEN_STATE_WINDOW_REAR_RIGHT: 'Rear right window open state',
      OTA_CONSENT_STATUS: 'Over-the-air update consent status',
      OTA_UPDATE_DETAILS: 'Over-the-air update details',
      PAIRING_CODE: 'Vehicle pairing code',
      PARKING_BRAKE: 'Parking brake state',
      PARKING_LIGHT: 'Parking light state',
      RANGE: 'Total driving range (km)',
      REMOTE_ACCESS_AUTHORIZATION: 'Remote access authorization state',
      SERVICE_PREDICTIONS: 'Predicted service dates',
      SPEED_ALARMS: 'Speed alarm settings',
      SPEED_ALARMS_HISTORY: 'History of speed alarm triggers',
      THEFT_MODE: 'Theft protection mode',
      THEFT_STATE: 'Theft detection state',
      TIMERS: 'Charging/climate timer settings',
      TIMEZONE: 'Vehicle timezone setting',
      TIRE_PRESSURE: 'Tire pressure overview',
      TIRE_PRESSURE_FRONT_LEFT: 'Front left tire pressure (bar)',
      TIRE_PRESSURE_FRONT_RIGHT: 'Front right tire pressure (bar)',
      TIRE_PRESSURE_REAR_LEFT: 'Rear left tire pressure (bar)',
      TIRE_PRESSURE_REAR_RIGHT: 'Rear right tire pressure (bar)',
      TRIP_STATISTICS_CYCLIC: 'Cyclic trip statistics',
      TRIP_STATISTICS_CYCLIC_HISTORY: 'Cyclic trip statistics history',
      TRIP_STATISTICS_LONG_TERM: 'Long-term trip statistics',
      TRIP_STATISTICS_LONG_TERM_HISTORY: 'Long-term trip statistics history',
      TRIP_STATISTICS_MONTHLY_REPORT: 'Monthly trip report',
      TRIP_STATISTICS_SHORT_TERM: 'Short-term trip statistics',
      TRIP_STATISTICS_SHORT_TERM_HISTORY: 'Short-term trip statistics history',
      VALET_ALARM: 'Valet mode alarm settings',
      VALET_ALARM_HISTORY: 'Valet alarm history',
      VTS_MODES: 'Vehicle Tracking System modes',
      VTS_CERTIFICATE_LIST: 'VTS certificate list',
      VTS_CONFIGURATION: 'Vehicle Tracking System configuration',
    };
    const measurements = Object.keys(measurementsWithDesc);
    let url = 'https://api.ppa.porsche.com/app/connect/v1/vehicles/$vin?mf=' + measurements.join('&mf=');

    if (forceRefresh) {
      url += '&wakeUpJob=' + uuidv4();
    }
    const statusArray = [
      {
        path: 'status',
        url: url,
        desc: 'Status of the car',
      },
    ];

    const headers = {
      accept: '*/*',
      'x-client-id': this.xClientId,
      authorization: 'Bearer ' + this.session.access_token,
      'user-agent': this.userAgent,
      'accept-language': 'de',
    };
    for (const vin of this.deviceArray) {
      for (const element of statusArray) {
        const url = element.url.replace('$vin', vin);

        await this.requestClient({
          method: 'get',
          url: url,
          headers: headers,
        })
          .then(async (res) => {
            this.log.debug(JSON.stringify(res.data));
            if (!res.data) {
              return;
            }
            const data = res.data;

            const forceIndex = null;
            const preferedArrayName = null;

            this.json2iob.parse(vin + '.' + element.path, data, {
              forceIndex: forceIndex,
              preferedArrayName: preferedArrayName,
              channelName: element.desc,
              descriptions: measurementsWithDesc,
            });
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401) {
                error.response && this.log.debug(JSON.stringify(error.response.data));
                this.log.info(element.path + ' receive 401 error. Refresh Token in 60 seconds');
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
    if (!this.session || !this.session.refresh_token) {
      this.log.error('No session found relogin');
      await this.login();
      return;
    }
    await this.requestClient({
      method: 'post',
      url: 'https://identity.porsche.com/oauth/token',
      headers: {
        'User-Agent': this.userAgent,
        'X-Client-ID': this.xClientId,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: qs.stringify({
        client_id: this.clientId,
        grant_type: 'refresh_token',
        refresh_token: this.session.refresh_token,
      }),
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.session = res.data;
        this.setState('info.connection', true, true);
      })
      .catch((error) => {
        this.log.error('refresh token failed');
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
        // 403 means refresh token is invalid, need full relogin
        this.log.error('Start relogin in 1min');
        this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
        this.reLoginTimeout = setTimeout(() => {
          this.login();
        }, 1000 * 60 * 1);
      });
  }

  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  onUnload(callback) {
    try {
      this.setState('info.connection', false, true);
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
      callback();
    } catch (e) {
      this.log.error('Error during unload: ' + e);
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
        const deviceId = id.split('.')[2];
        const command = id.split('.')[4];
        if (id.split('.')[3] !== 'remote') {
          return;
        }
        if (command === 'REMOTE_CLIMATIZER-temperature') {
          return;
        }
        if (command === 'HONK_FLASH-mode') {
          return;
        }
        if (command === 'Refresh') {
          this.updateDevices();
        }
        if (command === 'Force_Refresh') {
          this.updateDevices(true);
        }

        const data = {
          payload: {},
          key: command,
        };
        if (command === 'REMOTE_CLIMATIZER_START') {
          const temperatureState = await this.getStateAsync(deviceId + '.remote.REMOTE_CLIMATIZER-temperature');
          if (temperatureState) {
            data.payload.temperature = temperatureState.val ? temperatureState.val : 22;
          } else {
            data.payload.temperature = 22;
          }
        }
        if (command === 'HONK_FLASH') {
          const modeState = await this.getStateAsync(deviceId + '.remote.HONK_FLASH-mode');
          data.payload.mode = modeState && modeState.val ? modeState.val : 'HONK_AND_FLASH';
        }

        this.log.debug(JSON.stringify(data));

        await this.requestClient({
          method: 'post',
          url: 'https://api.ppa.porsche.com/app/connect/v1/vehicles/' + deviceId + '/commands',
          headers: {
            accept: '*/*',
            'x-client-id': this.xClientId,
            'content-type': 'application/json',
            'accept-language': 'de',
            authorization: 'Bearer ' + this.session.access_token,
            'user-agent': this.userAgent,
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

  /**
   * Handle messages from admin interface
   * @param {ioBroker.Message} obj
   */
  onMessage(obj) {
    if (typeof obj === 'object') {
      // imageSendTo expects the full data URL string directly (e.g., "data:image/svg+xml;base64,...")
      if (obj.command === 'getCaptcha') {
        if (this.pendingCaptcha && this.pendingCaptcha.svg) {
          this.sendTo(obj.from, obj.command, this.pendingCaptcha.svg, obj.callback);
        } else {
          // Return visible placeholder when no captcha is pending
          // SVG says "No Captcha - Reload page if needed"
          const placeholder = 'data:image/svg+xml;base64,' + Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60"><rect width="200" height="60" fill="#f0f0f0" stroke="#ccc"/><text x="100" y="25" text-anchor="middle" fill="#666" font-family="sans-serif" font-size="14">No Captcha</text><text x="100" y="45" text-anchor="middle" fill="#999" font-family="sans-serif" font-size="11">Reload page if needed</text></svg>').toString('base64');
          this.sendTo(obj.from, obj.command, placeholder, obj.callback);
        }
      }
      // textSendTo expects the text string directly
      if (obj.command === 'getCaptchaText') {
        if (this.pendingCaptcha && this.pendingCaptcha.svg) {
          this.sendTo(obj.from, obj.command, 'Captcha is available! Please enter the code shown in the image above.', obj.callback);
        } else {
          this.sendTo(obj.from, obj.command, 'No captcha pending. Login may have succeeded or not been attempted yet.', obj.callback);
        }
      }
      if (obj.command === 'submitCaptcha') {
        const captchaCode = obj.message.captchaCode;
        if (captchaCode) {
          this.loginWithCaptcha(captchaCode);
          this.sendTo(obj.from, obj.command, {
            result: 'Captcha submitted, retrying login...',
          }, obj.callback);
        } else {
          this.sendTo(obj.from, obj.command, {
            error: 'No captcha code provided',
          }, obj.callback);
        }
      }
    }
  }

  /**
   * Retry login with captcha code
   * @param {string} captchaCode
   */
  async loginWithCaptcha(captchaCode) {
    if (!this.pendingCaptcha) {
      this.log.error('No pending captcha');
      return;
    }

    const state = this.pendingCaptcha.state;
    const headers = {
      'User-Agent': this.userAgent,
      'X-Client-ID': this.xClientId,
    };

    this.log.info('Retrying login with captcha code...');

    // Step 2: POST /u/login/identifier with captcha
    try {
      await this.requestClient({
        method: 'post',
        url: 'https://identity.porsche.com/u/login/identifier',
        params: { state: state },
        headers: {
          ...headers,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        data: qs.stringify({
          state: state,
          username: this.config.username,
          'js-available': 'true',
          'webauthn-available': 'false',
          'is-brave': 'false',
          'webauthn-platform-available': 'false',
          action: 'default',
          captcha: captchaCode,
        }),
        maxRedirects: 0,
        validateStatus: (status) => status === 302 || status === 200,
      });
      this.log.debug('Identifier step with captcha completed');
    } catch (error) {
      if (error.response && error.response.status === 401) {
        this.log.error('Wrong credentials');
        return;
      }
      if (error.response && error.response.status === 400) {
        this.log.error('Captcha invalid or expired - please try again');
        // Extract new captcha if available
        const html = error.response.data;
        const match = html.match(/<img[^>]+alt="captcha"[^>]+src="([^"]+)"/);
        if (match) {
          this.pendingCaptcha = {
            svg: match[1],
            state: state,
          };
          this.log.warn('New captcha required - please enter new captcha code in admin config');
        }
        return;
      }
      // 302 redirect is expected, continue
      if (!error.response || error.response.status !== 302) {
        this.log.error('Error in identifier step with captcha: ' + error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
        return;
      }
    }

    // Clear pending captcha
    this.pendingCaptcha = null;

    // Step 3: POST /u/login/password with password
    let resumePath;
    try {
      const passwordResponse = await this.requestClient({
        method: 'post',
        url: 'https://identity.porsche.com/u/login/password',
        params: { state: state },
        headers: {
          ...headers,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        data: qs.stringify({
          state: state,
          username: this.config.username,
          password: this.config.password,
          action: 'default',
        }),
        maxRedirects: 0,
        validateStatus: (status) => status === 302 || status === 200,
      });

      if (passwordResponse.status === 302) {
        resumePath = passwordResponse.headers.location;
        this.log.debug('Resume path: ' + resumePath);
      }
    } catch (error) {
      if (error.response && error.response.status === 302) {
        resumePath = error.response.headers.location;
        this.log.debug('Resume path from error: ' + resumePath);
      } else if (error.response && error.response.status === 400) {
        this.log.error('Invalid credentials');
        return;
      } else {
        this.log.error('Error in password step: ' + error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
        return;
      }
    }

    if (!resumePath) {
      this.log.error('No resume path found after password step');
      return;
    }

    // Wait a bit before resuming
    await new Promise((resolve) => setTimeout(resolve, 2500));

    // Step 4: Resume the authorization flow
    let authorizationCode;
    try {
      const resumeUrl = resumePath.startsWith('http') ? resumePath : `https://identity.porsche.com${resumePath}`;
      const resumeResponse = await this.requestClient({
        method: 'get',
        url: resumeUrl,
        headers: headers,
        maxRedirects: 0,
        validateStatus: (status) => status === 302 || status === 200,
      });

      if (resumeResponse.status === 302) {
        const location = resumeResponse.headers.location;
        this.log.debug('Final redirect location: ' + location);

        if (location && location.includes('code=')) {
          const urlParams = new URL(location, 'http://dummy').searchParams;
          authorizationCode = urlParams.get('code');
        }
      }
    } catch (error) {
      if (error.response && error.response.status === 302) {
        const location = error.response.headers.location;
        this.log.debug('Final redirect location from error: ' + location);

        if (location && location.includes('code=')) {
          const urlParams = new URL(location, 'http://dummy').searchParams;
          authorizationCode = urlParams.get('code');
        }
      } else {
        this.log.error('Error in resume step: ' + error);
        if (error.response) {
          this.log.error(JSON.stringify(error.response.data));
        }
        return;
      }
    }

    if (!authorizationCode) {
      this.log.error('No authorization code found after captcha login');
      return;
    }

    this.log.debug('Got authorization code: ' + authorizationCode);
    await this.exchangeCodeForToken(authorizationCode, headers);

    // If login was successful, start fetching data
    if (this.session.access_token) {
      this.log.info('Login with captcha successful!');
      await this.getDeviceList();
      await this.updateDevices(true);

      // Set up intervals if not already running
      if (!this.updateInterval) {
        this.updateInterval = setInterval(async () => {
          await this.updateDevices();
        }, this.config.interval * 60 * 1000);
      }
      if (!this.refreshTokenInterval) {
        this.refreshTokenInterval = setInterval(() => {
          this.refreshToken();
        }, this.session.expires_in * 1000);
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
