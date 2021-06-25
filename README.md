# dawn-ng
dawn-ng is a fork of [DAWN](https://github.com/berlin-open-wireless-lab/DAWN) Decentralized WiFi Controller. The code is refactored, some bugs are fixed, custom features added...

The controller provides 802.11 k/v features over OpenWRT.

## General

WIP...

If configuration reload is invoked, dawn-ng rereads `intervals`, `metric` and `behaviour` config sections. 

Next, to ensure that every dawn-ng instance is operating the same intervals, metric and behaviour, new configuration (except `ap_weight`) is spreaded over the other instances and written to the uci.

Although, if a new dawn-ng instance starts operating, no config consistance checkup is done and it can have whatever config it want.

## Installation

WIP

## Configuration

| Option | Description |
| --- | --- |
| general ||
| network_proto | Network communication protocol. 0 - broadcast UDP, 1 - multicast UDP, 2 - TCP. |
| network_ip | This option must be set to broadcast or multicast IP if network_proto is set to 0 or 1 respectively. This option may be set if network_proto is set to 2 and connection to specific server is required. |
| network_port | --- |
| use_encryption | If 1 is set, network messages will be encrypted. No encryption could be usefull for debugging purposes. |
| log_level | Numbers from 4 to 0 represents: debug, info, warning, error and none. |
| hostapd_dir | Path to hostapd socket directory. |
| operational_ssid | WIP. |
| crypto ||
| key | --- |
| init_vector | --- |
| intervals ||
| update_clients | Period of time between two hostapd get_clients requests. |
| discover_dawn_instances | If network_proto is set to 2, dawn-ng will try to find another dawn-ng instances via umdns. |
| update_chan_utilisation | --- |
| request_beacon_reports | --- |
| remove_old_probes | --- |
| remove_old_aps | --- |
| move_to_allow_list | If use_driver_recog is set to 1 and auth/assoc request is denied because there is a better AP to connect, the request is being stored. If STA was unable to connect within move_to_allow_list seconds, it is considered to be dumb and placed to allow list. STAs from allow list are capable to connect to any AP they want and never get kicked. |
| mteric ||
| --- | The value is added to the score... |
| ap_weight |  ... unconditionally for this AP. |
| ht_support | ... if both STA and AP support HT. |
| vht_support | ... if both STA and AP support VHT. |
| chan_util_val | --- |
| chan_util | ... if channel utilization is below chan_util_val. |
| max_chan_util_val | --- |
| max_chan_util | ... if channel utilization is above max_chan_util_val. |
| freq | ... if AP frequency is above 5000 Hz. |
| rssi_val | --- |
| rssi | ... if client RSSI is better than rssi_val. |
| low_rssi_val | --- |
| low_rssi | if client RSSI is worse than low_rssi_val. |
| behaviour ||
| kicking | Kick STA if better AP is available and STA's bandwidth is below bandwidth_threshold. |
| aggressive_kicking | Kick STA if better AP is available and the score is negative, nevermind the bandwidth. |
| bandwidth_threshold | --- |
| use_station_count | If set to 1 and the scores of client for two APs are equal, prefer *less busy* AP. |
| max_station_diff | An amount of STAs one AP must have over an other to consider the first one to be *less busy*. |
| min_probe_count | Minimal amount of probes STA must send before dawn-ng will make any decision about it. |
| eval_probe_req | If better AP is available for STA that sent probe, probe response will contain flag that AP is full and can not handle any new STA. |
| eval_auth_req | If better AP is available authentication will be denied with reason specified in deny_auth_reason. |
| eval_assoc_req | If better AP is available association will be denied with reason specified in deny_assoc_reason. |
| use_driver_recog | --- |
| chan_util_avg_period | Number of periods update_chan_utilisation seconds long within an average channel utilization value is calculated. |
| set_hostapd_nr | If set to 1, neighbor report of AP will be filled based on collected information. |
| op_class | --- |
| duration | --- |
| mode | --- |
| scan_channel | --- |

## Build options

`DAWN_MEMORY_AUDITING` Every *alloc memory operation is being recorded. Sending SIGUSR1 provides you an overview of allocated memory blocks, their size and where exactly in the code (file, line) the allocation was made.

`DAWN_LOG_TO_SYSLOG` Send logs to syslog. Otherwise, stderr will be used and log level will prepend the message in form of \<E\>, \<W\>, etc.

`DAWN_VERBOSE_LOGS` Prepend log message with message location in form of file:function:line.

`DAWN_NO_DEBUG_LOGS` WIP.

`DAWN_LOCK_FREE_DATASTORAGE` WIP.

## Signals

`SIGINT` or `SIGTERM` Shut down dawn-ng.

`SIGUSR1` Print memory audit listing.

`SIGUSR2` Print dawn-ng state info: list of TCP connections, list of probe requests, list of APs, list of clietns.

`SIGHUP` WIP.

## ubus interface

`get_network` provides an overview of all APs and connected clients.

    root@OpenWrt:~# ubus call dawn get_network
    {
	    "Free-Cookies": {
		    "00:27:19:XX:XX:XX": {
			    "78:02:F8:XX:XX:XX": {
				    "freq": 2452,
				    "ht": 1,
				    "vht": 0,
				    "collision_count": 4
			    }
		    },
		    "A4:2B:B0:XX:XX:XX": {
			    "48:27:EA:XX:XX:XX: {
				    "freq": 2412,
				    "ht": 1,
				    "vht": 0,
				    "collision_count": 4
			    },
		    }
	    },
	    "Free-Cookies_5G": {

	    }
    }
`get_hearing_map` provides you a list of STAs, each containing a list of APs that got probe from that STA.

    root@OpenWrt:~# ubus call dawn get_hearing_map
    {
	    "Free-Cookies": {
		    "0E:5B:DB:XX:XX:XX": {
			    "00:27:19:XX:XX:XX": {
				    "signal": -64,
				    "freq": 2452,
				    "ht_support": true,
				    "vht_support": false,
				    "channel_utilization": 12,
				    "num_sta": 1,
				    "ht": 1,
				    "vht": 0,
				    "score": 10
			    },
			    "A4:2B:B0:XX:XX:XX": {
				    "signal": -70,
				    "freq": 2412,
				    "ht_support": true,
				    "vht_support": false,
				    "channel_utilization": 71,
				    "num_sta": 3,
				    "ht": 1,
				    "vht": 0,
				    "score": 10
			    }
		    }
	    }
    }

