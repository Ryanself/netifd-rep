#!/bin/sh


#$1 ifname
uci_add_station() {
	local device
	local name
	local cnt=0
	#TODO  what if we have added too much station?
	until [ "$?" = 1 ]
	do
		name=`uci -q get wireless.@wifi-iface[$cnt].ifname`
		# if station is already exist, just return.
		[ "$name" = "$1" ] && return
		let "cnt++"
		uci -q get wireless.@wifi-iface[$cnt]
	done

	case "$1" in
		*0)
			device="radio0"
			;;
		*1)
			device="radio1"
			;;
	esac

	uci -q batch << EOF
add wireless wifi-iface
set wireless.@wifi-iface[$cnt].device='$device'
set wireless.@wifi-iface[$cnt].network='wwan'
set wireless.@wifi-iface[$cnt].ssid='errorssid'
set wireless.@wifi-iface[$cnt].ifname='$1'
set wireless.@wifi-iface[$cnt].mode='sta'
set wireless.@wifi-iface[$cnt].disabled='0'
EOF
}

uci_delete_wireless_iface() {
	local name
	local cnt=0
	until [ "$name" = "$1" -o $cnt -gt 9 ]
	do
		name=`uci -q get wireless.@wifi-iface[$cnt].ifname`
		let "cnt++"
	done
	let "cnt--"
	[ $cnt -gt 8  ] || uci -q delete wireless.@wifi-iface[$cnt]
}

#FIXME add or set and what if it already exist?
#uci set network wwan and stabridge.
uci_set_network() {
	uci -q batch <<EOF
set network.wwan=interface
set network.wwan.ifname='$1'
set network.wwan.proto='dhcp'
set network.stabridge=interface
set network.stabridge.proto='relay'
set network.stabridge.network='lan wwan'
set network.stabridge.disable_dhcp_parse='1'
EOF
}

#set wireless base ifname
uci_set_wireless_iface() {
	local cnt=0
	local ssid=$2
	local enc=$3
	local psk=$4
	until [ "$name" = "$1" -o $cnt -gt 9 ]
	do
		name=`uci -q get wireless.@wifi-iface[$cnt].ifname`
		let "cnt++"
	done
	let "cnt--"
	[ $cnt -gt 8 ] || {
	uci -q batch << EOF
set wireless.@wifi-iface[$cnt].ssid="$ssid"
set wireless.@wifi-iface[$cnt].encryption="$enc"
set wireless.@wifi-iface[$cnt].key="$psk"
EOF
}
}
