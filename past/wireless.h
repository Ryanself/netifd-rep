/*
 * netifd - network interface daemon
 * Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef __NETIFD_WIRELESS_H
#define __NETIFD_WIRELESS_H

#include <libubox/utils.h>
#include "interface.h"

struct vlist_tree wireless_devices;
struct avl_tree wireless_drivers;

struct wireless_driver {
	struct avl_node node;

	const char *name;
	const char *script;

	struct {
		char *buf;
		struct uci_blob_param_list *config;
	} device, interface;
};

/*
 *@wpa* control wpa_supplicant
 *@disabled control device, both hostap and wpas
 */
struct wireless_device {
	struct vlist_node node;

	struct wireless_driver *drv;
	struct vlist_tree interfaces;
	char *name;

	struct netifd_process script_task;
	struct uloop_timeout timeout;
	struct uloop_timeout poll;

	struct list_head script_proc;
	struct uloop_fd script_proc_fd;
	struct uloop_timeout script_check;

	struct ubus_request_data *kill_request;

	bool config_autostart;
	bool autostart;

	enum interface_state state;
	enum interface_config_state config_state;
	bool cancel;
	int retry;

	struct blob_attr *prev_config;
	struct blob_attr *config;
	struct blob_attr *data;
	bool disabled;

	struct netifd_process wpa_script_task;
	struct uloop_timeout wpa_timeout;
	struct uloop_timeout wpa_poll;

	struct list_head wpa_script_proc;
	struct uloop_fd wpa_script_proc_fd;
	struct uloop_timeout wpa_script_check;

	struct ubus_request_data *wpa_kill_request;

	bool wpa_config_autostart;
	bool wpa_autostart;

	enum interface_state wpa_state;
	enum interface_config_state wpa_config_state;
	bool wpa_cancel;
	int wpa_retry;

	int vif_idx;
	bool hostap_remove;
	bool wpas_remove;
};

struct wireless_interface {
	struct vlist_node node;
	const char *section;
	char *name;

	struct wireless_device *wdev;

	struct blob_attr *config;
	struct blob_attr *data;

	const char *ifname;
	struct blob_attr *network;
	bool isolate;
	bool ap_mode;
	unsigned int group;
	bool disable_input;
	bool netisolate;
};

struct wireless_process {
	struct list_head list;

	const char *exe;
	int pid;

	bool required;
	//bool mode;
};

/*
 * @wireless_config state to pass action to script
 */
enum wireless_config {
	WDEV_TEARDOWN,
	WDEV_SETUP,
	WDEV_RELOAD,
	WDEV_REPDOWN,
	WDEV_REPUP,
};

void wireless_device_create(struct wireless_driver *drv, const char *name, struct blob_attr *data);
void wireless_device_set_up(struct wireless_device *wdev);
void wireless_device_set_down(struct wireless_device *wdev);
void wireless_device_status(struct wireless_device *wdev, struct blob_buf *b);
void wireless_device_get_validate(struct wireless_device *wdev, struct blob_buf *b);
void wireless_interface_create(struct wireless_device *wdev, struct blob_attr *data, const char *section);
int wireless_device_notify(struct wireless_device *wdev, struct blob_attr *data,
			   struct ubus_request_data *req);

void wireless_start_pending(void);
void wireless_init(void);

#endif
