#!/usr/bin/env python
"""
https://github.com/jantman/prometheus-synology-api-exporter

MIT License

Copyright (c) 2023 Jason Antman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import sys
import os
import argparse
import logging
import socket
import time
from typing import Generator, List, Dict, Optional

from wsgiref.simple_server import make_server, WSGIServer
from prometheus_client.core import (
    REGISTRY, GaugeMetricFamily, InfoMetricFamily, StateSetMetricFamily, Metric
)
from prometheus_client.exposition import make_wsgi_app, _SilentHandler
from prometheus_client.samples import Sample
from synology_dsm import SynologyDSM

FORMAT = "[%(asctime)s %(levelname)s] %(message)s"
logging.basicConfig(level=logging.WARNING, format=FORMAT)
logger = logging.getLogger()


def enum_metric_family(
    name: str, documentation: str, states: List[str], value: str
):
    """Since the client library doesn't have this..."""
    if value not in states:
        logger.error(
            'Value of "%s" not listed in states %s for enum_metric_family %s',
            value, states, name
        )
        states.append(value)
    return StateSetMetricFamily(
        name, documentation,
        {
            x: x == value for x in states
        }
    )


class LabeledGaugeMetricFamily(Metric):
    """Not sure why the upstream one doesn't allow labels..."""

    def __init__(
        self,
        name: str,
        documentation: str,
        value: Optional[float] = None,
        labels: Dict[str, str] = None,
        unit: str = '',
    ):
        Metric.__init__(self, name, documentation, 'gauge', unit)
        if labels is None:
            labels = {}
        self._labels = labels
        if value is not None:
            self.add_metric(labels, value)

    def add_metric(self, labels: Dict[str, str], value: float) -> None:
        """Add a metric to the metric family.
        Args:
          labels: A dictionary of labels
          value: A float
        """
        self.samples.append(
            Sample(self.name, dict(labels | self._labels), value, None)
        )


class LabeledStateSetMetricFamily(Metric):
    """Not sure why upstream doesn't allow this..."""

    def __init__(
        self,
        name: str,
        documentation: str,
        labels: Optional[Dict[str, str]] = None,
    ):
        Metric.__init__(self, name, documentation, 'stateset')
        if labels is None:
            labels = {}
        self._labels = labels

    def add_metric(
        self, value: Dict[str, bool], labels: Optional[Dict[str, str]] = None
    ) -> None:
        if labels is None:
            labels = {}
        for state, enabled in sorted(value.items()):
            v = (1 if enabled else 0)
            self.samples.append(Sample(
                self.name,
                dict(self._labels | labels | {self.name: state}),
                v,
            ))


class SynologyApiCollector:

    def _env_or_err(self, name: str) -> str:
        s: str = os.environ.get(name)
        if not s:
            raise RuntimeError(
                f'ERROR: You must set the "{name}" environment variable.'
            )
        return s

    def __init__(self):
        logger.debug('Instantiating SynologyApiCollector')
        ip: str = self._env_or_err('DSM_IP')
        port: int = int(os.environ.get('DSM_PORT', '5000'))
        username: str = self._env_or_err('DSM_USER')
        passwd: str = self._env_or_err('DSM_PASS')
        use_https: bool = os.environ.get('DSM_USE_HTTPS') == 'true'
        verify_ssl: bool = os.environ.get('DSM_VERIFY_SSL') == 'true'
        timeout: int = int(os.environ.get('DSM_TIMEOUT_SEC', '30'))
        logger.info(
            'Connecting to DSM at %s:%s as user %s', ip, port, username
        )
        self.dsm: SynologyDSM = SynologyDSM(
            ip, port, username, passwd,
            use_https=use_https, verify_ssl=verify_ssl, timeout=timeout
        )
        self.dsm.login()
        logger.debug('Connected to DSM')
        self.query_time: float = 0.0

    def _get_dsm_data(self):
        """Update all data from the DSM API."""
        logger.debug('Updating DSM data')
        qstart = time.time()
        self.dsm.information.update()
        self.dsm.utilisation.update()
        self.dsm.storage.update()
        self.dsm.share.update()
        self.dsm.network.update()
        self.dsm.system.update()
        self.dsm.security.update()
        self.query_time = time.time() - qstart
        logger.debug('DSM data updated in %s', self.query_time)

    def collect(self) -> Generator[Metric, None, None]:
        logger.debug('Beginning collection')
        self._get_dsm_data()
        yield GaugeMetricFamily(
            'synology_query_time_seconds',
            'Time taken to collect data from DSM',
            value=self.query_time
        )
        for meth in [
            self._do_information,
            self._do_security,
            self._do_storage_disks,
            self._do_storage_pools,
            self._do_storage_volumes,
            self._do_utilization_cpu,
            self._do_utilization_disk,
            self._do_utilization_network,
            self._do_utilization_memory,
            self._do_utilization_nfs,
            self._do_utilization_space,
            self._do_system,
        ]:
            yield from meth()
        logger.debug('Finished collection')

    def _do_system(self) -> Generator[Metric, None, None]:
        data = self.dsm.system._data
        states = LabeledStateSetMetricFamily(
            'synology_system_state', 'Boolean state items for whole system'
        )
        states.add_metric(
            value={
                x: data[x] for x in [
                    "enabled_ntp", "sys_tempwarn", "systempwarn",
                    "temperature_warning"
                ]
            }
        )
        yield states
        yield GaugeMetricFamily(
            'synology_system_cpu_clock_speed', 'CPU clock speed MHz',
            unit='MHz', value=data['cpu_clock_speed']
        )
        yield GaugeMetricFamily(
            'synology_system_ram_size', 'System RAM size MB',
            unit='MB', value=data['ram_size']
        )
        yield GaugeMetricFamily(
            'synology_system_temp', 'System temperature',
            unit='celcius', value=data['sys_temp']
        )
        yield GaugeMetricFamily(
            'synology_system_num_usb_debices', 'Number of USB devices',
            value=len(data['usb_dev'])
        )
        yield GaugeMetricFamily(
            'synology_system_num_sata_debices', 'Number of SATA devices',
            value=len(data['sata_dev'])
        )
        info = InfoMetricFamily(
            'synology_system', 'Information on system',
        )
        info.add_metric(labels={}, value={
            x: data[x] for x in [
                "cpu_cores", "cpu_family", "cpu_series", "cpu_vendor",
                "firmware_date", "firmware_ver", "model", "ntp_server",
                "serial", "support_esata"
            ]
        })
        yield info

    def _do_utilization_nfs(self) -> Generator[Metric, None, None]:
        nfs = self.dsm.utilisation._data['nfs'][0]
        assert nfs['device'] == 'nfs'
        for x in ["read_OPS", "total_OPS", "write_OPS"]:
            yield GaugeMetricFamily(
                f'synology_utilization_nfs_{x}', f'NFS {x}',
                value=nfs[x]
            )
        for x in ["read_max_latency", "total_max_latency", "write_max_latency"]:
            yield GaugeMetricFamily(
                f'synology_utilization_nfs_{x}', f'NFS {x}',
                value=nfs[x] / 1000000.0, unit='seconds'
            )

    def _do_utilization_cpu(self) -> Generator[Metric, None, None]:
        cpu = self.dsm.utilisation.cpu
        yield GaugeMetricFamily(
            'synology_utilization_cpu_load1', '1-minute load average',
            value=cpu['1min_load']
        )
        yield GaugeMetricFamily(
            'synology_utilization_cpu_load5', '5-minute load average',
            value=cpu['5min_load']
        )
        yield GaugeMetricFamily(
            'synology_utilization_cpu_load15', '15-minute load average',
            value=cpu['15min_load']
        )
        yield GaugeMetricFamily(
            'synology_utilization_cpu_load_other', 'CPU load other',
            value=cpu['other_load']
        )
        yield GaugeMetricFamily(
            'synology_utilization_cpu_load_user', 'CPU load user',
            value=cpu['user_load']
        )
        yield GaugeMetricFamily(
            'synology_utilization_cpu_load_system', 'CPU load system',
            value=cpu['system_load']
        )

    def _do_utilization_disk(self) -> Generator[Metric, None, None]:
        diskutil = self.dsm.utilisation._data['disk']['disk']
        diskutil.append(self.dsm.utilisation._data['disk']['total'])
        util = LabeledGaugeMetricFamily(
            'synology_utilization_disk_utilization_percent', 'Disk utilization'
        )
        read_a = LabeledGaugeMetricFamily(
            'synology_utilization_disk_read_accesses',
            'Disk read access utilization'
        )
        write_a = LabeledGaugeMetricFamily(
            'synology_utilization_disk_write_accesses',
            'Disk write access utilization'
        )
        read_b = LabeledGaugeMetricFamily(
            'synology_utilization_disk_read', 'Disk read', unit='bytes'
        )
        write_b = LabeledGaugeMetricFamily(
            'synology_utilization_disk_write', 'Disk write', unit='bytes'
        )
        for disk in diskutil:
            labels = {'device': disk['device']}
            util.add_metric(labels=labels, value=disk['utilization'])
            read_a.add_metric(labels=labels, value=disk['read_access'])
            read_b.add_metric(labels=labels, value=disk['read_byte'])
            write_a.add_metric(labels=labels, value=disk['write_access'])
            write_b.add_metric(labels=labels, value=disk['write_byte'])
        yield from [util, read_a, write_a, read_b, write_b]

    def _do_utilization_space(self) -> Generator[Metric, None, None]:
        diskutil = self.dsm.utilisation._data['space']['volume']
        self.dsm.utilisation._data['space']['total']['display_name'] = 'total'
        diskutil.append(self.dsm.utilisation._data['space']['total'])
        util = LabeledGaugeMetricFamily(
            'synology_utilization_volume_utilization_percent',
            'Volume space utilization'
        )
        read_a = LabeledGaugeMetricFamily(
            'synology_utilization_volume_read_accesses',
            'Volume read access utilization'
        )
        write_a = LabeledGaugeMetricFamily(
            'synology_utilization_volume_write_accesses',
            'Volume write access utilization'
        )
        read_b = LabeledGaugeMetricFamily(
            'synology_utilization_volume_read', 'Volume read', unit='bytes'
        )
        write_b = LabeledGaugeMetricFamily(
            'synology_utilization_volume_write', 'Volume write', unit='bytes'
        )
        for disk in diskutil:
            labels = {
                'device': disk['device'], 'display_name': disk['display_name']
            }
            util.add_metric(labels=labels, value=disk['utilization'])
            read_a.add_metric(labels=labels, value=disk['read_access'])
            read_b.add_metric(labels=labels, value=disk['read_byte'])
            write_a.add_metric(labels=labels, value=disk['write_access'])
            write_b.add_metric(labels=labels, value=disk['write_byte'])
        yield from [util, read_a, write_a, read_b, write_b]

    def _do_utilization_network(self) -> Generator[Metric, None, None]:
        net_rx = LabeledGaugeMetricFamily(
            'synology_utilization_network_rx', 'Network RX'
        )
        net_tx = LabeledGaugeMetricFamily(
            'synology_utilization_network_tx', 'Network TX'
        )
        for dev in self.dsm.utilisation.network:
            net_rx.add_metric(
                labels={'device': dev['device']}, value=dev['rx']
            )
            net_tx.add_metric(
                labels={'device': dev['device']}, value=dev['tx']
            )
        yield from [net_rx, net_tx]

    def _do_utilization_memory(self) -> Generator[Metric, None, None]:
        mem: Dict = self.dsm.utilisation.memory
        mem.pop('device', None)
        yield GaugeMetricFamily(
            'synology_utilization_memory_swap_in', 'Swap In',
            value=mem['si_disk']
        )
        yield GaugeMetricFamily(
            'synology_utilization_memory_swap_out', 'Swap Out',
            value=mem['so_disk']
        )
        yield GaugeMetricFamily(
            'synology_utilization_memory_usage_percent',
            'Real memory usage percent',
            value=mem['real_usage']
        )
        yield GaugeMetricFamily(
            'synology_utilization_swap_usage_percent',
            'Swap memory usage percent',
            value=mem['swap_usage']
        )
        for x in [
            "avail_real", "avail_swap", "buffer", "cached", "memory_size",
            "total_real", "total_swap"
        ]:
            yield GaugeMetricFamily(
                f'synology_utilization_memory_{x}',
                f'Memory utilization - {x}',
                value=mem[x], unit='bytes'
            )

    def _do_storage_volumes(self) -> Generator[Metric, None, None]:
        states = LabeledStateSetMetricFamily(
            'synology_volume_state', 'Boolean state items for a Volume'
        )
        info = InfoMetricFamily(
            'synology_volume', 'Information on a volume',
        )
        suggestions = LabeledGaugeMetricFamily(
            'synology_volume_suggestions', 'Number of suggestions for volume'
        )
        expand = LabeledGaugeMetricFamily(
            'synology_volume_can_expand_by_disks',
            'Number of disks that the volume can be expanded by'
        )
        failure = LabeledGaugeMetricFamily(
            'synology_volume_disk_failure_number',
            'Number of failed disks'
        )
        missing = LabeledGaugeMetricFamily(
            'synology_volume_missing_drives',
            'Number of missing drives'
        )
        size_total = LabeledGaugeMetricFamily(
            'synology_volume_size_total', 'Total volume size', unit='bytes'
        )
        size_used = LabeledGaugeMetricFamily(
            'synology_volume_size_used', 'Used volume size', unit='bytes'
        )
        inode_total = LabeledGaugeMetricFamily(
            'synology_volume_inode_total', 'Total inodes'
        )
        inode_free = LabeledGaugeMetricFamily(
            'synology_volume_inode_free', 'Free inodes'
        )
        for vol in self.dsm.storage.volumes:
            labels = {
                x: vol[x] for x in ['id', 'desc', 'vol_path']
            }
            ss = vol['space_status']
            vol['space_status'] = ss['status']
            vol['space_status_summary'] = ss['summary_status']
            vol['space_status_detail'] = ss['detail']
            vol['space_status_attention'] = ss['show_attention']
            vol['space_status_danger'] = ss['show_danger']
            vol['can_do_disk_replace'] = vol['can_do'].get('disk_replace', False)
            vol['can_do_expand_by_disk'] = vol['can_do'].get('expand_by_disk', False)
            states.add_metric(
                labels=labels,
                value={
                    x: vol[x] for x in [
                        "can_assemble", 'space_status_attention',
                        'space_status_danger', 'can_do_disk_replace',
                        "is_acting", "is_actioning", "is_backgroundbuilding",
                        "is_inode_full", "is_scheduled", "is_writable"

                    ]
                }
            )
            info.add_metric(labels=labels, value={
                x: vol[x] for x in [
                    "container", "device_type", "fs_type", "pool_path",
                    "repair_action", "scrubbingStatus", "space_path",
                    "status", "summary_status", "vol_attribute",
                    'space_status', 'space_status_summary',
                    'space_status_detail'
                ]
            })
            suggestions.add_metric(labels=labels, value=len(vol['suggestions']))
            expand.add_metric(labels=labels, value=vol['can_do_expand_by_disk'])
            failure.add_metric(labels=labels, value=vol['disk_failure_number'])
            missing.add_metric(
                labels=labels, value=len(vol['missing_drives'])
            )
            size_total.add_metric(
                labels=labels, value=int(vol['size']['total'])
            )
            size_used.add_metric(
                labels=labels, value=int(vol['size']['used'])
            )
            inode_total.add_metric(
                labels=labels, value=int(vol['size']['total_inode'])
            )
            inode_free.add_metric(
                labels=labels, value=int(vol['size']['free_inode'])
            )
        yield from [
            states, info, suggestions, expand, failure, missing, size_total,
            size_used, inode_total, inode_free
        ]

    def _do_storage_pools(self) -> Generator[Metric, None, None]:
        states = LabeledStateSetMetricFamily(
            'synology_pool_disk_state', 'Boolean state items for a Storage Pool'
        )
        info = InfoMetricFamily(
            'synology_pool', 'Information on a storage pool',
        )
        fail_num = LabeledGaugeMetricFamily(
            'synology_pool_disk_failure_number', 'Number of failed disks'
        )
        num_disks = LabeledGaugeMetricFamily(
            'synology_pool_num_disks', 'Number of disks in pool'
        )
        missing_drives = LabeledGaugeMetricFamily(
            'synology_pool_missing_drives', 'Number of missing drives'
        )
        spares = LabeledGaugeMetricFamily(
            'synology_pool_num_spares', 'Number of spare drives'
        )
        size_total = LabeledGaugeMetricFamily(
            'synology_pool_size', 'Total size of pool', unit='bytes'
        )
        used = LabeledGaugeMetricFamily(
            'synology_pool_used', 'Used size of pool', unit='byes'
        )
        raid_designed = LabeledGaugeMetricFamily(
            'synology_pool_raid_designed_disk_count',
            'RAID designed disk count'
        )
        raid_num_devices = LabeledGaugeMetricFamily(
            'synology_pool_raid_num_devices',
            'RAID device/disk disk count'
        )
        raid_spares = LabeledGaugeMetricFamily(
            'synology_pool_raid_num_spares',
            'RAID spare disk count'
        )
        raid_crashed_reason = LabeledGaugeMetricFamily(
            'synology_pool_raid_crashed_reason',
            'Numeric crashed reason for RAID'
        )
        raid_status = LabeledGaugeMetricFamily(
            'synology_pool_raid_status', 'Numeric RAID status'
        )
        raid_has_parity = LabeledStateSetMetricFamily(
            'synology_pool_raid_has_parity', 'RAID has parity'
        )
        devices = InfoMetricFamily(
            'synology_pool_raid_device', 'RAID device info and status'
        )
        for pool in self.dsm.storage.storage_pools:
            labels = {
                "pool_path": pool["pool_path"],
                "desc": pool["desc"],
                "id": pool["id"]
            }
            pool['space_attention'] = pool['space_status']['show_attention']
            pool['space_danger'] = pool['space_status']['show_danger']
            states.add_metric(
                labels=labels,
                value={
                    x: pool[x] for x in [
                        "is_actioning", "is_backgroundbuilding", "is_scheduled",
                        "is_writable", 'space_attention', 'space_danger'
                    ]
                }
            )
            ss = pool['space_status']
            pool['space_status'] = ss['status']
            pool['space_status_detail'] = ss['detail']
            pool['space_status_summary'] = ss['summary_status']
            pool['drive_type'] = str(pool['drive_type'])
            info.add_metric(labels=labels, value={
                x: pool[x] for x in [
                    "cacheStatus", "device_type", "repair_action",
                    "scrubbingStatus", "status", "summary_status",
                    'space_status_detail', 'space_status',
                    'space_status_summary', 'drive_type'
                ]
            })
            fail_num.add_metric(
                labels=labels, value=pool['disk_failure_number']
            )
            num_disks.add_metric(
                labels=labels, value=len(pool['disks'])
            )
            missing_drives.add_metric(
                labels=labels, value=len(pool['missing_drives'])
            )
            spares.add_metric(
                labels=labels, value=len(pool['spares'])
            )
            size_total.add_metric(
                labels=labels, value=int(pool['size']['total'])
            )
            used.add_metric(
                labels=labels, value=int(pool['size']['used'])
            )
            for raid in pool['raids']:
                rlabels = dict(labels | {'raidPath': raid['raidPath']})
                raid_designed.add_metric(
                    labels=rlabels, value=raid['designedDiskCount']
                )
                raid_num_devices.add_metric(
                    labels=rlabels, value=len(raid['devices'])
                )
                raid_spares.add_metric(
                    labels=rlabels, value=len(raid['spares'])
                )
                raid_crashed_reason.add_metric(
                    labels=rlabels, value=raid['raidCrashedReason']
                )
                raid_status.add_metric(
                    labels=rlabels, value=raid['raidStatus']
                )
                raid_has_parity.add_metric(
                    labels=rlabels, value={'hasParity': raid['hasParity']}
                )
                for dev in raid['devices']:
                    devices.add_metric(
                        labels=rlabels,
                        value={x: str(y) for x, y in dev.items()}
                    )
        yield from [
            states, info, fail_num, num_disks, missing_drives, spares,
            size_total, used, raid_designed, raid_num_devices, raid_spares,
            raid_crashed_reason, raid_status, raid_has_parity, devices
        ]

    def _do_storage_disks(self) -> Generator[Metric, None, None]:
        info = InfoMetricFamily(
            'synology_disk', 'Information on an individual disk',
        )
        states = LabeledStateSetMetricFamily(
            'synology_disk_state', 'Boolean state items for a single disk'
        )
        size = LabeledGaugeMetricFamily(
            'synology_disk_size', 'Size of physical disk', unit='bytes'
        )
        remain = LabeledGaugeMetricFamily(
            'synology_disk_remain_life', 'Disk life remaining'
        )
        sbdays = LabeledGaugeMetricFamily(
            'synology_disk_sb_days_left', 'SB Days Left'
        )
        temp = LabeledGaugeMetricFamily(
            'synology_disk_temp', 'Disk temperature', unit='celcius'
        )
        unc = LabeledGaugeMetricFamily('synology_disk_unc', 'Disk UNC')
        for disk in self.dsm.storage.disks:
            labels = {
                'id': disk['id'], 'name': disk['name'],
                'device': disk['device'], 'serial': disk['serial']
            }
            disk['container_order'] = disk['container']['order']
            disk['container_str'] = disk['container']['str']
            disk['container_type'] = disk['container']['type']
            info.add_metric(labels=labels, value={
                x: str(disk[x]) for x in [
                    'container_order', 'container_str', 'container_type',
                    "device", "diskType", "disk_code", "disk_location",
                    "firm", "firmware_status", "id", "longName", "model",
                    "name", "overview_status", "portType", "serial",
                    "smart_progress", "smart_status", "status",
                    "summary_status_category", "summary_status_key",
                    "testing_progress", "testing_type", "ui_serial",
                    "used_by", "vendor"
                ]
            })
            disk['slot_id'] = str(disk['slot_id'])
            states.add_metric(
                labels=labels,
                value={
                    x: disk[x] for x in [
                        "below_remain_life_mail_notify_thr",
                        "below_remain_life_show_thr", "below_remain_life_thr",
                        "has_system", "ihm_testing", "is4Kn", "isSsd",
                        "isSynoDrive", "isSynoPartition", "is_bundle_ssd",
                        "is_erasing", "perf_testing", "remain_life_danger",
                        "sb_days_left_critical", "sb_days_left_warning",
                        "smart_test_support", "smart_testing",
                        "wcache_force_off", "wcache_force_on", "wdda_support",
                        'slot_id'
                    ]
                }
            )
            size.add_metric(labels=labels, value=int(disk['size_total']))
            if isinstance(disk['remain_life'], type(-1)):
                remain.add_metric(labels=labels, value=disk['remain_life'])
            else:
                # DSM 7.2
                remain.add_metric(
                    labels=labels, value=disk['remain_life']['value']
                )
            sbdays.add_metric(labels=labels, value=disk['sb_days_left'])
            temp.add_metric(labels=labels, value=disk['temp'])
            unc.add_metric(labels=labels, value=disk['unc'])
        yield from [info, states, size, remain, sbdays, temp, unc]
        yield StateSetMetricFamily(
            'synology_storage_env',
            'Storage environment status information',
            value={
                'fs_acting': self.dsm.storage.env['fs_acting'],
                'is_space_actioning': self.dsm.storage.env['is_space_actioning'],
                'system_crashed': self.dsm.storage.env['status'][
                    'system_crashed'],
                'system_need_repair': self.dsm.storage.env['status'][
                    'system_need_repair'],
                'system_rebuilding': self.dsm.storage.env['status'][
                    'system_rebuilding'],
            }
        )

    def _do_security(self) -> Generator[Metric, None, None]:
        yield StateSetMetricFamily(
            'synology_security_success',
            'Security scan success (boolean)',
            value={'success': self.dsm.security.success}
        )
        yield GaugeMetricFamily(
            'synology_security_progress_pct',
            'Security scan progress (percent)',
            unit='percent',
            value=self.dsm.security.progress
        )
        yield enum_metric_family(
            'synology_security_status',
            'Security status string',
            ['safe', 'danger', 'info', 'outOfDate', 'risk', 'warning'],
            value=self.dsm.security.status
        )
        yield GaugeMetricFamily(
            'synology_security_time_since_last_scan',
            'Number of seconds since the last scan started',
            unit='seconds',
            value=time.time() - int(self.dsm.security.last_scan_time)
        )
        failures = LabeledGaugeMetricFamily(
            'synology_security_check_failure_count',
            'Count of security check failures',
        )
        total_checks = LabeledGaugeMetricFamily(
            'synology_security_total_checks',
            'Count of total checks in any status, per category'
        )
        progress = LabeledGaugeMetricFamily(
            'synology_security_check_progress_percent',
            'Percent progress of checks per category',
            unit='percent'
        )
        fail_severity = InfoMetricFamily(
            'synology_security_fail_severity',
            'Failure severity, per category'
        )
        for item in self.dsm.security.checks.values():
            total_checks.add_metric(
                {'category': item['category']},
                item['total']
            )
            progress.add_metric(
                {'category': item['category']},
                item['progress']
            )
            fail_severity.add_metric(
                {'category': item['category']},
                {'severity': item['failSeverity'], 'category': item['category']}
            )
            for _type, count in item['fail'].items():
                failures.add_metric(
                    {
                        'category': item['category'],
                        'fail_type': _type
                    },
                    count
                )
        yield from [failures, total_checks, progress, fail_severity]

    def _do_information(self) -> Generator[Metric, None, None]:
        yield GaugeMetricFamily(
            'synology_info_uptime_seconds',
            'Uptime in seconds',
            unit='seconds',
            value=self.dsm.information.uptime
        )
        yield GaugeMetricFamily(
            'synology_info_system_temperature',
            'System temperature °C',
            unit='celsius',
            value=self.dsm.information.temperature
        )
        yield GaugeMetricFamily(
            'synology_info_ram',
            'System RAM in MB',
            unit='MB',
            value=self.dsm.information.ram
        )
        yield StateSetMetricFamily(
            'synology_info_system_temperature_warning',
            'System temperature warning or not (boolean)',
            value={'warning': self.dsm.information.temperature_warn}
        )
        yield InfoMetricFamily(
            'synology_information',
            'System-level information',
            value={
                x: getattr(self.dsm.information, x)
                for x in [
                    'model', 'serial', 'version', 'version_string'
                ]
            }
        )


def _get_best_family(address, port):
    """
    Automatically select address family depending on address
    copied from prometheus_client.exposition.start_http_server
    """
    # HTTPServer defaults to AF_INET, which will not start properly if
    # binding an ipv6 address is requested.
    # This function is based on what upstream python did for http.server
    # in https://github.com/python/cpython/pull/11767
    infos = socket.getaddrinfo(address, port)
    family, _, _, _, sockaddr = next(iter(infos))
    return family, sockaddr[0]


def serve_exporter(port: int, addr: str = '0.0.0.0'):
    """
    Copied from prometheus_client.exposition.start_http_server, but doesn't run
    in a thread because we're just a proxy.
    """

    class TmpServer(WSGIServer):
        """Copy of WSGIServer to update address_family locally"""

    TmpServer.address_family, addr = _get_best_family(addr, port)
    app = make_wsgi_app(REGISTRY)
    httpd = make_server(
        addr, port, app, TmpServer, handler_class=_SilentHandler
    )
    httpd.serve_forever()


def parse_args(argv):
    p = argparse.ArgumentParser(description='Prometheus Synology API exporter')
    p.add_argument(
        '-v', '--verbose', dest='verbose', action='count', default=0,
        help='verbose output. specify twice for debug-level output.'
    )
    PORT_DEF = int(os.environ.get('PORT', '8080'))
    p.add_argument(
        '-p', '--port', dest='port', action='store', type=int,
        default=PORT_DEF, help=f'Port to listen on (default: {PORT_DEF})'
    )
    args = p.parse_args(argv)
    return args


def set_log_info():
    set_log_level_format(
        logging.INFO, '%(asctime)s %(levelname)s:%(name)s:%(message)s'
    )


def set_log_debug():
    set_log_level_format(
        logging.DEBUG,
        "%(asctime)s [%(levelname)s %(filename)s:%(lineno)s - "
        "%(name)s.%(funcName)s() ] %(message)s"
    )


def set_log_level_format(level: int, format: str):
    """
    Set logger level and format.

    :param level: logging level; see the :py:mod:`logging` constants.
    :type level: int
    :param format: logging formatter format string
    :type format: str
    """
    formatter = logging.Formatter(fmt=format)
    logger.handlers[0].setFormatter(formatter)
    logger.setLevel(level)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    if args.verbose > 1:
        set_log_debug()
    elif args.verbose == 1:
        set_log_info()
    logger.debug('Registering collector...')
    REGISTRY.register(SynologyApiCollector())
    logger.info('Starting HTTP server on port %d', args.port)
    serve_exporter(args.port)
