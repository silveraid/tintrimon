#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#  Copyright (c) 2016 Frank Felhoffer
#
#  Permission is hereby granted, free of charge, to any person obtaining a
#  copy of this software and associated documentation files (the "Software"),
#  to deal in the Software without restriction, including without limitation
#  the rights to use, copy, modify, merge, publish, distribute, sublicense,
#  and/or sell copies of the Software, and to permit persons to whom the
#  Software is furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included
#  in all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
#  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
#  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Python program to monitor Tintri Storage Appliances
"""

from __future__ import print_function

import argparse
import atexit
import json
import tintri_1_1 as tintri


# Version information
build_ver = 'v1.01'
build_date = '2016-07-21'


def parse_args():

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-s', '--host', required=True, action='store',
                        help='The IP address or the hostname of the datastore')
    parser.add_argument('-u', '--user', required=True, action='store',
                        help='Username with read-only access')
    parser.add_argument('-p', '--password', required=True, action='store',
                        help='Password belongs to the user')
    parser.add_argument('-w', '--warning', required=True, action='store', type=int,
                        help='Nagios warning threshold in GB (free raw space)')
    parser.add_argument('-e', '--error', required=True, action='store', type=int,
                        help='Nagios error threshold in GB (free raw space)')
    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='')
    args = parser.parse_args()
    return args


def print_with_prefix(prefix, out):
    print(prefix + out)
    return


def print_verbose(out):
    if verbose:
        print_with_prefix("[VERBOSE]: ", out)
    return


def print_info(out):
    print_with_prefix("[INFO]: ", out)
    return


def print_error(out):
    print_with_prefix("[ERROR]: ", out)
    return


def get_json(host, session_id, url):
    try:
        r = tintri.api_get(host, url, session_id)
        print_verbose("Response: " + r.text)

        # If the status_code != 200 a TintriApiException is raised,
        # there is no need to do any checks regarding

    except tintri.TintriRequestsException as tre:
        print_error(tre.__str__())
        tintri.api_logout(host, session_id)
        exit(NAGIOS_CRITICAL)

    except tintri.TintriApiException as tae:
        print_error(tae.__str__())
        tintri.api_logout(host, session_id)
        exit(NAGIOS_CRITICAL)

    return r.text


def get_alert_count(host, session_id):

    url = "/v310/appliance/default/alertCounts"
    json_res = get_json(host, session_id, url)
    res = json.loads(json_res)

    # The number of inbox alerts since appliance installed.
    numInboxAlerts = res['numInboxAlerts']

    # The number of inbox notices since appliance installed.
    numInboxNotices = res['numInboxNotices']

    # The number of archived alerts since appliance installed.
    numArchivedAlerts = res['numArchivedAlerts']

    # The number of archived notices since appliance installed.
    numArchivedNotices = res['numArchivedNotices']

    # The number of unread alerts since appliance installed.
    numUnreadAlerts = res['numUnreadAlerts']

    # Read alerts => WARNING
    if (numInboxAlerts > 0):
        set_nagios_state(NAGIOS_WARNING, "Read Inbox Alerts Present")

    # Unread alerts => CRITICAL
    if (numUnreadAlerts > 0):
        set_nagios_state(NAGIOS_CRITICAL, "Unread Inbox Alerts Present")


# TODO: Have to go on-site to test this, potential get a list of the components
def get_failed_components(host, session_id):

    url = "/v310/appliance/default/failedComponents"
    json_res = get_json(host, session_id, url)
    res = json.loads(json_res)

    # The list of failed components.
    failedComponents = res['failedComponents']

    # Failed Components => CRITICAL
    if (len(failedComponents)):
        set_nagios_state(NAGIOS_CRITICAL, "Failed Components Present")


def get_maintenance_mode(host, session_id):

    url = "/v310/appliance/default/maintenanceMode"
    json_res = get_json(host, session_id, url)
    res = json.loads(json_res)

    # 'True' indicates that maintenance mode is enabled.
    # 'False' indicates normal mode.
    isEnabled = res['isEnabled']

    if (isEnabled == False) or (isEnabled == True):
        return isEnabled
    else:
        print("Unexpected response (get_maintenance_mode)!")
        exit(NAGIOS_CRITICAL)


def get_operational_status(host, session_id):

    url = "/v310/appliance/default/operationalStatus"
    json_res = get_json(host, session_id, url)
    res = json.loads(json_res)

    # Number of days, hours and minutes the appliance is up and running
    # since last update or boot. The format is "%d days %d hours %d minutes".
    uptime = res['uptime']

    # The unread alerts count.
    alertsUnreadCount = res['alertsUnreadCount']

    # 'True' indicates that the file system is up. 'False' indicates
    # that the file system is down.
    isFilesystemUp = res['isFilesystemUp']

    # List of actions required for the Appliance when settings are changed
    criticalActionPrompts = res['criticalActionPrompts']

    # Urgent message for the datastore
    urgentMessage = res['urgentMessage']

    if (alertsUnreadCount > 0):
        set_nagios_state(NAGIOS_CRITICAL, "Unread Alerts Present")

    if (isFilesystemUp == False):
        set_nagios_state(NAGIOS_CRITICAL, "File System Down")

    if (len(criticalActionPrompts)):
        set_nagios_state(NAGIOS_CRITICAL, "Critical Action Prompts")

    if (urgentMessage != ""):
        set_nagios_state(NAGIOS_CRITICAL, "Urgent Message: " + urgentMessage)


def get_datastore_stats(host, session_id, space_warning, space_error):

    url = "/v310/datastore"
    json_res = get_json(host, session_id, url)
    res = json.loads(json_res)

    # This is an array, not sure why yet
    x = res[0]

    # Measure of the space saved due to deduplication from Tintri clones.
    # This is computed as a ratio of the logical footprint and the logical
    # bytes written, before block deduplication (if applicable). A value
    # of 1.0 means no savings due to clone deduplication. Higher values mean
    # greater space savings. This field is being deprecated at the VM and
    # vDisk levels. We recommend using the spaceSavingsFactor at the VM and
    # vDisk levels instead.
    cloneDedupeFactor = x['stat']['cloneDedupeFactor']

    # At the datastore level, this is a measure of the space saved due to
    # compression, and is computed as a ratio of the logical bytes stored
    # and the physical space used. At the VM and vDisk levels, this is a
    # measure of the compressibility of the data written to the VM or vDisk,
    # and is computed as a ratio of the logical written size and the
    # compressed space used. A value of 1.0 means no savings due to
    # compression. Higher values mean greater space savings.
    compressionFactor = x['stat']['compressionFactor']

    # Measure of the space saved due to block and clone deduplication. This
    # is computed as a ratio of the logical footprint and the logical bytes
    # stored, after deduplication has filtered out duplicate data. This
    # attribute is only returned at the Datastore level. A value of 1.0
    # means no savings due to deduplication. Higher values mean
    # greater space savings.
    dedupeFactor = x['stat']['dedupeFactor']

    # Total number of disks of all virtual machines provisioned
    # on this datastore.
    disksCount = x['stat']['disksCount']

    # The percentage of all reads and writes that are satisfied
    # by flash storage.
    flashHitPercent = x['stat']['flashHitPercent']

    # The interval between datapoints in seconds
    intervalSeconds = x['stat']['intervalSeconds']

    # The portion of overall latency contributed by QoS contention
    latencyContentionMs = x['stat']['latencyContentionMs']

    # The portion of overall latency contributed by the hard
    # disks in milliseconds.
    latencyDiskMs = x['stat']['latencyDiskMs']

    # The portion of overall latency contributed by QoS flash
    latencyFlashMs = x['stat']['latencyFlashMs']

    # The portion of overall latency contributed by from ESX
    # hosts down to disks in milliseconds.
    latencyHostMs = x['stat']['latencyHostMs']

    # The percentage of total latency due to host and network latency.
    latencyIopsPercent = x['stat']['latencyIopsPercent']

    # The portion of overall latency contributed by from the network
    # down to disks in milliseconds.
    latencyNetworkMs = x['stat']['latencyNetworkMs']

    # The portion of overall latency contributed by the Tintri storage
    # in milliseconds. It includes latency of disks.
    latencyStorageMs = x['stat']['latencyStorageMs']

    # The portion of overall latency contributed by QoS throttling
    latencyThrottleMs = x['stat']['latencyThrottleMs']

    # The maximum host and network latency in milliseconds.
    latencyTotalMs = x['stat']['latencyTotalMs']

    # Logical unique space used by all of the VMs.
    logicalUniqueSpaceUsedGiB = x['stat']['logicalUniqueSpaceUsedGiB']

    # Normalized Read and Write IOPS total
    normalizedTotalIops = x['stat']['normalizedTotalIops']

    # The maximum IOPS in the last week.
    operationsInWeekMaximumIops = x['stat']['operationsInWeekMaximumIops']

    # The minimum IOPS in the last week.
    operationsInWeekMinimumIops = x['stat']['operationsInWeekMinimumIops']

    # Read operations per second.
    operationsReadIops = x['stat']['operationsReadIops']

    # Total IOPS on the datastore.
    operationsTotalIops = x['stat']['operationsTotalIops']

    # Write operations per second.
    operationsWriteIops = x['stat']['operationsWriteIops']

    # Performance reserve percentage for a disk or VM.
    performanceReserveAutoAllocated = x['stat']['performanceReserveAutoAllocated']

    # Performance reserves for a disk or VM.
    performanceReservePinned = x['stat']['performanceReservePinned']

    # The percentage of performance reserves remaining.
    # (100 - performanceReserveUsed)
    performanceReserveRemaining = x['stat']['performanceReserveRemaining']

    # The percentage of performance reserves used.
    # (autoAllocatedPerfReservePercentage + pinnedPerfReservePercentage)
    performanceReserveUsed = x['stat']['performanceReserveUsed']

    # Logical space allocated on the datastore in GiB.
    spaceProvisionedGiB = x['stat']['spaceProvisionedGiB']

    # Datastore provisioned space percentage.
    spaceProvisionedPercent = x['stat']['spaceProvisionedPercent']

    # The estimated number of days until the datastore is full based
    # on recent usage.
    spaceRemainingDays = x['stat']['spaceRemainingDays']

    # Total physical available minus physical used.
    spaceRemainingPhysicalGiB = int(round(x['stat']['spaceRemainingPhysicalGiB']))

    # Measures the space saved due to all space savings techniques supported,
    # excluding thin provisioning. At the VM and vDisk level, the space
    # savings factor applies to the data written to the VM or vDisk. At the
    # Datastore level, the space savings applies to the logical footprint of
    # the datastore, which includes the data written to the datastore as well
    # as the additional data accessible to clones due to clone deduplication.
    spaceSavingsFactor = x['stat']['spaceSavingsFactor']

    # The total space capacity of the datastore in GiB.
    spaceTotalGiB = x['stat']['spaceTotalGiB']

    # The amount of logical space used on the datastore in GiB.
    spaceUsedGiB = x['stat']['spaceUsedGiB']

    # Logical space used for live VM data and hypervisor snapshots in GiB
    # (does not include snapshot-only space).
    # Includes vDisk files and swap files.
    spaceUsedLiveGiB = x['stat']['spaceUsedLiveGiB']

    # Physical (actual) space used by live VM data and hypervisor snapshots,
    # after all space savings techniques are applied.
    spaceUsedLivePhysicalGiB = x['stat']['spaceUsedLivePhysicalGiB']

    # Logical footprint of the datastore. This is the logical size of all
    # data accessible on the datastore, before any space savings techniques
    # are applied.
    spaceUsedMappedGiB = x['stat']['spaceUsedMappedGiB']

    # The logical spaced used by other files.
    spaceUsedOtherGiB = x['stat']['spaceUsedOtherGiB']

    # The physical space used by other files in GiB.
    spaceUsedOtherPhysicalGiB = x['stat']['spaceUsedOtherPhysicalGiB']

    # The amount of physical space used on the datastore in GiB.
    spaceUsedPhysicalGiB = int(round(x['stat']['spaceUsedPhysicalGiB']))

    # Logical space used for hypervisor snapshots in GiB.
    spaceUsedSnapshotsHypervisorGiB = x['stat']['spaceUsedSnapshotsHypervisorGiB']

    # Physical space used for hypervisor snapshots in GiB.
    spaceUsedSnapshotsHypervisorPhysicalGiB = x['stat']['spaceUsedSnapshotsHypervisorPhysicalGiB']

    # Space used for Tintri Snapshots in GiB.
    spaceUsedSnapshotsTintriGiB = x['stat']['spaceUsedSnapshotsTintriGiB']

    # Actual space consumed by Tintri snapshots in GiB.
    spaceUsedSnapshotsTintriPhysicalGiB = x['stat']['spaceUsedSnapshotsTintriPhysicalGiB']

    # Total thick space used on the system This is an indicator of how much
    # space can user efficiently save, by converting the thick space
    # used VMs to thin.
    thickSpaceUsedGiB = x['stat']['thickSpaceUsedGiB']

    # Datastore thick space used percentage. This value represents the
    # percentage of the total physical space used in the system by
    # Thick-provisioned VMs.
    thickSpaceUsedPercent = x['stat']['thickSpaceUsedPercent']

    # The cache read throughput that is satisfied by flash storage.
    throughputCacheReadMBps = x['stat']['throughputCacheReadMBps']

    # System wide flash miss rate based on throughput in MBps.
    # (The amount of read traffic that goes to disk)
    throughputFlashMissMBps = x['stat']['throughputFlashMissMBps']

    # The maximum throughput in the last week.
    throughputInWeekMaximumMBps = x['stat']['throughputInWeekMaximumMBps']

    # The minimum throughput in the last week in MBps.
    throughputInWeekMinimumMBps = x['stat']['throughputInWeekMinimumMBps']

    # Bandwidth in MB per second for read operations.
    throughputReadMBps = x['stat']['throughputReadMBps']

    # Total throughput on the datastore in MBps.
    throughputTotalMBps = x['stat']['throughputTotalMBps']

    # Bandwidth in MB per second for write operations.
    throughputWriteMBps = x['stat']['throughputWriteMBps']

    # Measures the space saved due to all space savings techniques supported
    # including Thin Provisioning. The formula is [ spaceProvisionedGiB -
    # (spaceUsedLiveGiB + spaceUsedOtherGiB ) + spaceUsedMappedGiB] /
    # [spaceUsedLivePhysicalGiB + spaceUsedOtherPhysicalGiB +
    # spaceUsedSnapshotsTintriPhysicalGiB]
    totalSpaceSavingsIncludingThinProvisioningFactor = x['stat']['totalSpaceSavingsIncludingThinProvisioningFactor']

    # Number of virtual machines provisioned on this datastore.
    vmsCount = x['stat']['vmsCount']

    # Logical amount of aggregated data(MB) yet to be replicated over for
    # that VM, for all applicable ongoing replications.
    replicationOutgoing_bytesRemainingMB = x['stat']['replicationOutgoing']['bytesRemainingMB']

    if (spaceRemainingPhysicalGiB < space_error):
        nagios_state = NAGIOS_CRITICAL
    elif (spaceRemainingPhysicalGiB < space_warning):
        nagios_state = NAGIOS_WARNING
    else:
        nagios_state = NAGIOS_OK

    set_nagios_state(nagios_state, "VMS: {0}, USED: {1} GB, FREE: {2} GB".
                     format(vmsCount, spaceUsedPhysicalGiB, spaceRemainingPhysicalGiB))


def tintri_logout(host, session_id):
    print_verbose("Logout ({0})".format(host))
    tintri.api_logout(host, session_id)


def set_nagios_state(new_state, msg):

    global NAGIOS_STATE, NAGIOS_MESSAGE

    if (NAGIOS_STATE < new_state):
        NAGIOS_STATE = new_state

    if (len(msg)):
        if (len(NAGIOS_MESSAGE)):
            NAGIOS_MESSAGE += ", "

        NAGIOS_MESSAGE += msg


def main():

    global NAGIOS_OK, NAGIOS_WARNING, NAGIOS_CRITICAL, NAGIOS_UNKNOWN, NAGIOS_MESSAGE, NAGIOS_STATE
    global verbose

    # Nagios Plugin Return Codes
    NAGIOS_OK = 0
    NAGIOS_WARNING = 1
    NAGIOS_CRITICAL = 2
    NAGIOS_UNKNOWN = 3

    # The Nagios Message
    NAGIOS_MESSAGE = ""

    # Everything is fine by default
    NAGIOS_STATE = NAGIOS_OK

    args = parse_args()

    if args.verbose:
        verbose = True
    else:
        verbose = False

    # Get the product name
    try:
        r = tintri.api_version(args.host)
        json_info = r.json()
        product_name = json_info['productName']

        # The expected product name is "Tintri VMstore"
        if (product_name != "Tintri VMstore"):
            print("Incompatible VMstore has been detected!")
            exit(NAGIOS_CRITICAL)

        # Login to Tintri VMStore
        session_id = tintri.api_login(args.host, args.user, args.password)
        atexit.register(tintri_logout, args.host, session_id)

    except tintri.TintriRequestsException as tre:
        print_error(tre.__str__())
        exit(NAGIOS_CRITICAL)

    except tintri.TintriApiException as tae:
        print_error(tae.__str__())
        exit(NAGIOS_CRITICAL)


    if (get_maintenance_mode(args.host, session_id)):
        print("Maintenance mode active!")
        exit(NAGIOS_WARNING)

    # Checking free space and such
    get_datastore_stats(args.host, session_id, args.warning, args.error)

    # Checking alerts in the Inbox
    get_alert_count(args.host, session_id)

    # Checking if there are any failed components
    # Note: It takes a lot of time to collect this information
    get_failed_components(args.host, session_id)

    # Checking generic status values
    get_operational_status(args.host, session_id)

    # Exiting with the calculated state
    print("{0} ({1})".format(NAGIOS_MESSAGE, NAGIOS_STATE))
    exit(NAGIOS_STATE)


# Start program
if __name__ == "__main__":
    main()