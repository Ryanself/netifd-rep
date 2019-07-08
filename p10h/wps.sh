#!/bin/sh
. /usr/share/led-button/wps_func.sh

status=0
wps_status=0

#flags
#@wps_start means enter wds.sh
#@wps_status means wpa_ci_event receive the event WPS-SUCCESS
check_status() {
	[ -f /tmp/wps_start ] && status=`cat /tmp/wps_start`
	[ -f /tmp/wps_status  ] && wps_status=`cat /tmp/wps_status`
	[ $status = 1 -o "$wps_status" != 0 ] && {
		exit 0
	}
}

wps_start() {
	#add sta iface conf file in wireless to up sif*.
	uci_add_station "sfi0"
	uci_add_station "sfi1"
}

mode=`uci -q get basic_setting.ap.enable`
#enable 0 means wds(repeater), 1 means ap(wps). default: ap.
if [ "$mode" == 0 ]; then
	check_status
	echo 1 > /tmp/wps_start
	wps_start
	uci commit
	output=`wifi reload`

	sleep 2
	cd /var/run/wpa_supplicant
	for socket in *; do
		[ -S "$socket"  ] || continue
		wpa_cli -i "$socket" wps_pbc
	done

	#wps_start  shall rm here.
	[ -f /tmp/wps_start ] && rm /tmp/wps_start
	exit 0
else
	cd /var/run/wpa_supplicant
	for socket in *; do
		[ -S "$socket" ] || continue
		wpa_cli -i "$socket" wps_pbc
	done
fi
