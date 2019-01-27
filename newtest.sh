#!/bin/sh

#set 2.4g or 5g to connect
prepare(){

	key="12345678"
	ssid="SiWiFi-306c-2.4G"
	ssid2="SiWiFi-3070"
	bssid="10:16:88:5A:30:6C"
	bssid2="10:16:88:5A:30:70"
	rai=
	local up_time=0
	sleep 2

	case $1 in
	0)
		uci set wireless.@wifi-iface[2].key="$key"
		uci set wireless.@wifi-iface[2].ssid="$ssid"
		uci set wireless.@wifi-iface[2].bssid="$bssid"
		uci set wireless.@wifi-iface[2].disabled='0'
		#uci set wireless.@wifi-iface[3].disabled='1'
		;;
	1)
		uci set wireless.@wifi-iface[3].key="$key"
		uci set wireless.@wifi-iface[3].ssid="$ssid2"
		uci set wireless.@wifi-iface[3].bssid="$bssid2"
		uci set wireless.@wifi-iface[3].disabled='0'
		#uci set wireless.@wifi-iface[2].disabled='1'
		;;
	esac

	sleep 2
	uci commit
	wifi reload
	sleep 2
	while [ -z "$rai" ]
	do
		let "up_time++"
		rai=`iwinfo | grep "rai"`
		rai=${rai%% *}
		[ $up_time -gt 15 ] && echo "sta set up failed: time out! >>>>>>>>>>>" > /dev/console
		sleep 2
	done
}

#wds connect
#rai can also get from band.
check_ip(){
	sleep 1
	local check
	local checktime=0

	#get iface num to set chan through uci
	case $rai in
	rai0)
		iface=0
		wan="lan wwan"
		rai_num=2
		;;
	rai1)
		iface=3
		wan="lan wwwan"
		rai_num=3
		;;
	esac

	while [ -n "$check" ]
	do
		sleep 2
		let "checktime++"
		check=`ifconfig $rai | grep "inet addr"`
		[ $checktime -gt 15 ] && echo "wds get ip failed: time out>>>>>>>>>>"
	done
	check=
}

#connect and set dns and relayd
setwds(){
	sleep 2
	uci set network.stabridge.disabled='0'
	uci set network.stabridge.network="$wan"
	uci set basic_setting.dnsmasq.down='1'

	/etc/init.d/dnsmasq restart
	/etc/init.d/relayd reload

	#get and set ap channel
	chan=`iwinfo $rai info | grep Chan|awk -F ' ' '{print $4}'`
	[ "$chan" = "unknown"  ] || {
		[ -n "$iface" ] && uci set wireless.@wifi-iface[$iface].channel="$chan"
		uci commit
	}
	wifi reload
}

#reset to reconnect
resetwds(){
	sleep 1
	uci set network.stabridge.disabled='1'
	uci set basic_setting.dnsmasq.down='0'
	uci set wireless.@wifi-iface[$rai_num].disabled='1'

	uci commit
	/etc/init.d/dnsmasq restart
	sleep 2
	/etc/init.d/network restart
	sleep 10
}

#check if success or fail
checkwds(){
	sleep 1
	local check_time=0
	local wds
	while [ $wds -gt 0 ]
	do
		let "check_time++"
		if ping -c1 -w1 192.168.1.10 &>/dev/null
		then
			wds=1
		fi
		[ $checktime -gt 15  ] && echo "rep ping server failed: time out!>>>>>>>>>>" > /dev/console
		sleep 2
	done
	wds=0

	sleep 2
}

testtime=0
band=0
echo ">>>>>>>>>>>>>>>>>>>>>repeater wds test start<<<<<<<<<<<<<<<<<<<<<<<" > /dev/console
while true
do
	let "testtime++"
	echo ">>>>>>>>>>>>>>>test time: $testtime <<<<<<<<<<<<<<<<" > /dev/console
	prepare $band
	check_ip
	setwds
	checkwds
	ret="$?"
	if [ "$ret" != 0 ];  then
		echo "check wds failed >>>>>>> please recheck!>>>>>>>" > /dev/console
		exit 0
	else
		resetwds
	fi
	if [ $band != 0 ];then
		band=0
	else
		band=1
	fi
done
