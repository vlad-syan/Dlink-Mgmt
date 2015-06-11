#!/usr/bin/perl

#  Mgmt.pm
#  
#  Copyright 2015 Vladimir Sarkisyan <vlad.syan@gmail.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

# Tab indent size = 4
# Some dark magic ahead.

#	Documentation TODO:
#	
#	* internal functions with description:
#	- _snmpget
#	- _telnet_cmd
#	- _snmpwalk
#	- _snmpgetnext
#	- _snmpset
#
#	* hardcoded functions:
#	- save
#	- reboot
#
#



use strict;
use Net::SNMP;
use Net::Telnet;
use POSIX;

require Crypt::DES;
require Digest::HMAC;

package DLink::Mgmt;

=pod

=begin man

.TH DLink::SNMP 1

=end man

=head1 NAME

=begin html

<style>
p { 
	text-align: justify; 
}
p.code { 
	margin-left: 40px;
	margin-right: 40px;
	background: #eaeaea; 
	border: 1px solid black; 
	padding: 15px;
	font-family: monospace;
}
p.list {
	margin-left: 40px;
	margin-right: 40px;
	padding: 15px;
	background: #dedeff;
}
.tab {
	margin-left: 2em;
}
.code {
	font-family: monospace;
	font-style: normal;
}
.code-comment {
	font-family: monospace;
	font-style: italic;
	font-color: #454545;
	margin-left: 3em;
}
</style>

DLink::Mgmt - интерфейс для управления коммутаторами D-Link

=end html

=begin man

DLink::Mgmt - D-Link network switch management API

=end man

=head1 SYNOPSIS

=begin html

Модуль DLink::Mgmt дает возможность представить коммутатор в качестве объекта.
Для управления используются протоколы SNMP и Telnet. На данный момент поддерживаются 
следующие модели:

<p class="list">
DES-3526<br>
DES-3528<br>
DES-3028<br>
DES-1228/ME/B1A<br>
DES-3200/A1 Series<br>
DES-3200/C1 Series<br>
DGS-3120-24SC/A1<br>
DGS-3100-24TG<br>
</p>

Также поддерживается ограниченное чтение настроек на коммутаторах:
<p class="list">
DGS-3627G<br>
DGS-3620-28SC<br>
</p>

=end html

=begin man

This module represents D-Link network switch class and gives ability to configure
it in object-oriented way. It reads and writes configuration options using SNMP
and Telnet protocols. This version of module supports next models:

=over 1

=item - DES-3526

=item - DES-3528

=item - DES-3028

=item - DES-1228/ME/B1A

=item - DES-3200/A1 Series

=item - DES-3200/C1 Series

=item - DGS-3120-24SC/A1

=item - DGS-3100-24TG

=item

=back

Also, there is a limited support (ReadOnly) for next models:

=over 1

=item - DGS-3620-28SC

=item - DGS-3627G

=back

=end man

=cut

#
#	SNMP std.	
#
my $OID_description = '1.3.6.1.2.1.1.1.0';
my $OID_model = '1.3.6.1.2.1.1.2.0';
my $OID_802dot1q_name = '1.3.6.1.2.1.17.7.1.4.3.1.1';
my $OID_802dot1q_egress = '1.3.6.1.2.1.17.7.1.4.3.1.2';
my $OID_802dot1q_forbidden = '1.3.6.1.2.1.17.7.1.4.3.1.3';
my $OID_802dot1q_untag = '1.3.6.1.2.1.17.7.1.4.3.1.4';
my $OID_802dot1q_status = '1.3.6.1.2.1.17.7.1.4.3.1.5';
my $dlink_private = '1.3.6.1.4.1.171.11';
my $dlink_common = '1.3.6.1.4.1.171.12';
my $OID_FCSErrors = '1.3.6.1.2.1.10.7.11.1.2';
my $OID_Collisions = '1.3.6.1.2.1.10.7.2.1.5';
my $OID_SymbolErrs = '1.3.6.1.2.1.10.7.11.1.6';
my $OID_Oversize = '1.3.6.1.2.1.10.7.11.1.4';
my $OID_RxUcast = '1.3.6.1.2.1.31.1.1.1.7';
my $OID_RxMcast = '1.3.6.1.2.1.31.1.1.1.8';
my $OID_RxBcast = '1.3.6.1.2.1.31.1.1.1.9';
my $OID_RxOctet = '1.3.6.1.2.1.31.1.1.1.6';
my $OID_TxOctet = '1.3.6.1.2.1.31.1.1.1.10';
my $OID_Uptime = '1.3.6.1.2.1.1.3.0';
my $OID_PortDescription = '1.3.6.1.2.1.31.1.1.1.18';
#
#	D-Link common mgmt.
#
my $OID_FDB_port = '1.3.6.1.2.1.17.4.3.1.2';
my $OID_DLink_FW = '1.3.6.1.4.1.171.12.1.2.7.1.2';
my $OID_DLink_CurrentTime = '1.3.6.1.4.1.171.12.10.10.1.0';
my $OID_CPU_5sec = '1.3.6.1.4.1.171.12.1.1.6.1.0';
my $OID_CPU_1min = '1.3.6.1.4.1.171.12.1.1.6.2.0';
my $OID_CPU_5min = '1.3.6.1.4.1.171.12.1.1.6.3.0';
my $OID_DLink_TFTP_Addr = '1.3.6.1.4.1.171.12.1.2.1.1.3';
my $OID_DLink_Filename = '1.3.6.1.4.1.171.12.1.2.1.1.5';
my $OID_DLink_Filectrl = '1.3.6.1.4.1.171.12.1.2.1.1.8';
my $OID_DLink_FileID = '1.3.6.1.4.1.171.12.1.2.1.1.10';
my $OID_DLink_FileLoad = '1.3.6.1.4.1.171.12.1.2.1.1.7';
my $OID_DLink_Increment = '1.3.6.1.4.1.171.12.1.2.1.1.9';
my $OID_DLink_FileType = '1.3.6.1.4.1.171.12.1.2.1.1.6';
#
#	strings
#

=head1 DESCRIPTION

=head2 Constants

=begin html

В модуле используются следующие строковые константы:

<p class="code">
enabled, disabled, partially, other, unknown, auto, 10-half, 10-full, 
100-half, 100-full, 1000-full, 10000-full, link-pass, link-fail, none, 
empty, lbd, ddm, storm, local0, local1, local2, local3, local4, local5, 
local6, local7, all, warn, info, emergency, alert, critical, error, notice, 
debug, strict, loose, drop, shutdown, normal, error, loop, permit, deny
</p>

=end html

=begin man

There are such string constants in module as:
enabled, disabled, partially, other, unknown, auto, 10-half, 10-full, 
100-half, 100-full, 1000-full, 10000-full, link-pass, link-fail, none, 
empty, lbd, ddm, storm, local0, local1, local2, local3, local4, local5, 
local6, local7, all, warn, info, emergency, alert, critical, error, notice, 
debug, strict, loose, drop, shutdown, normal, error, loop, permit, deny

=end man

=cut

my $enabled = 'enabled';
my $disabled = 'disabled';
my $partially = 'partially';
my $other = 'other';
my $unknown = 'unknown';
my $nway_auto = 'auto';
my $nway_10half = '10-half';
my $nway_10full = '10-full';
my $nway_100half = '100-half';
my $nway_100full = '100-full';
my $nway_1G = '1000-full';
my $nway_10G = '10000-full';
my $link_pass = 'link-pass';
my $link_fail = 'link-fail';
my $none = 'none';
my $empty = 'empty';
my $lbd = 'lbd';
my $ddm = 'ddm';
my $storm = 'storm';
my $local0 = 'local0';
my $local1 = 'local1';
my $local2 = 'local2';
my $local3 = 'local3';
my $local4 = 'local4';
my $local5 = 'local5';
my $local6 = 'local6';
my $local7 = 'local7';
my $all = 'all';
my $warn = 'warn';
my $info = 'info';
my $emergency = 'emergency';
my $alert = 'alert';
my $critical = 'critical';
my $error = 'error';
my $notice = 'notice';
my $debug = 'debug';
my $strict = 'strict';
my $loose = 'loose';
my $copper;
my $fiber;
my $drop = 'drop';
my $shutdown = 'shutdown';
my $normal = 'normal';
my $error = 'error';
my $loop = 'loop';
my $permit = 'permit';
my $deny = 'deny';
my $default_gw = '00-25-90-91-32-9B';
#
#	Constants
#

=pod

=begin html

Также по умолчанию приняты следующие соглашения:
<p class="list">ISM VLAN tag - <span class="code">24</span><br>
SNMP version для readonly доступа - <span class="code">2c</span><br>
SNMP community для readonly доступа - <span class="code">dlread</span><br>
Telnet login - <span class="code">admin</span><br>
Telnet password - <span class="code">Masterok</span>
</p>

=end html

=begin man

Here are some more default values:

=over 1

=item IGMP Snooping Multicast VLAN Tag - 24

=item SNMP version for ReadOnly access - 2c

=item SNMP community - dlread

=item Telnet login - admin

=item Telnet password - Masterok

=back

=end man

=cut

my $const_mvr_tag = 24;
my $const_snmp_community = 'dlread';
my $const_snmp_version = 2;
my $t_string = Net::SNMP::OCTET_STRING;
my $t_integer = Net::SNMP::INTEGER;
my $t_octet = Net::SNMP::OCTET_STRING;
my $t_ipaddr = Net::SNMP::IPADDRESS;
my $createAndGo = 4;
my $destroy = 6;
my $telnet_login = 'admin';
my $telnet_pass = 'Masterok';
#
#	Mcast groups
#
my $OID_McastRange_ID;
my $OID_McastRange_Name;
my $OID_McastRange_From;
my $OID_McastRange_To;
my $OID_Mcast_PortAccess;
my $OID_Mcast_PortState;
my $OID_Mcast_PortRangeID;
my @str_Mcast_PortAccess;
my @str_Mcast_PortState;

=head2 Functions

=head3 new

=begin html

Создает экземпляр класса DLink::Mgmt.
<p class=code>my $dlink = DLink::Mgmt->new(<br>
	<span class="tab"></span>host => 172.16.131.115,<br>
	<span class="tab"></span>version => '2c',<br>
	<span class="tab"></span>community => 'dlread',<br>
	<span class="tab"></span>mvr => 24,<br>
	<span class="tab"></span>gw => '00-25-90-91-32-9B'<br>
	);
</p>
<p class="list">
<span class="code">host</span> - адрес коммутатора, обязательный параметр.<br>
<span class="code">version</span> - версия SNMP для ReadOnly доступа.<br>
<span class="code">community</span> - SNMP community для ReadOnly доступа.<br>
<span class="code">mvr</span> - IGMP Snooping Multicast VLAN Tag.<br>
<span class="code">gw</span> - MAC-адрес шлюза сети управления.<br>
</p>


При вызове функции <span class="code">new</span> экземпляр класса <b>DLink::Mgmt</b> 
получает свойство-объект <span class="code">snmp</span>, которое является экземпляром 
класса <b>Net::SNMP</b> и используется для <i>ReadOnly</i> вызовов. Также, если 
устройство не является L3-коммутатором, создается свойство-объект <span class="code">
snmpv3</span>, являющееся экземпляром класса <b>Net::SNMP</b> и использующееся
для <i>Write</i> вызовов. Параметры для установления SNMPv3-соединения описываются в
конце функции и могут различаться в зависимости от устройства. Подробнее это будет
описано в разделе <b>"Добавление новых устройств"</b>.

=end html

=begin man

=over 1

=item my $dlink = DLink::Mgmt->new(

=over 2

=item host => 172.16.131.115, 

=item version => '2c', 

=item community => 'dlread', 

=item mvr => 24, 

=item gw => '00-25-90-91-32-9B'

=back

=item );

=back

When new \fBsub\fR is called, it creates DLink::Mgmt object with \fBsnmp\fR property, 
which is a Net::SNMP object and is used for read-only requests. Also, if the switch 
is not a L3-switch, \fBsnmpv3\fR property is created. Parameters for SNMPv3-session
are different for each device and are set in the end of the sub.

=end man

=cut

sub new {
	my ($class, %args) = @_;
	my $self = bless({}, $class);
	
	my $version = exists $args{version} ? $args{version} : $const_snmp_version;
	my $community = exists $args{community} ? $args{community} : $const_snmp_community;
	$self->{mvr} = exists $args{mvr} ? $args{mvr} : $const_mvr_tag;
	$self->{gw} = exists $args{gateway_mac} ? $args{gateway_mac} : $default_gw;
	$self->{cache_igmp_ttl} = 5;
	$self->{cache_acl_ttl} = 60;
	
	my $host = $args{host};
	$self->{ip} = $host;
	
	my $snmp = Net::SNMP->session(-hostname => $host, -version => $version, -community => $community, -timeout => 30);
	$self->{snmp_session} = $snmp;
	my $result = $snmp->get_request(-varbindlist => [$OID_model]);
	$self->{model} = $result->{$OID_model};
	
	my $model = $self->{model};
	$model =~ s/1.3.6.1.4.1.171.10.//;
	my $prefix = $dlink_private . '.' . $model;
	
	$self->{default_medium} = 'copper';
	$self->{type} = 'L2';

	################
	#
	# DES-3526
	#
	################
	if ($model eq '64.1') {
		$self->{name} = 'DES-3526';
		# Ports
		$self->{OID_PortAdminNway} = $prefix . '.2.4.5.1.5';
		$self->{OID_PortAdminState} = $prefix . '.2.4.5.1.4';
		$self->{OID_PortErrDisabled} = $prefix . '.2.4.4.1.8';
		$self->{OID_PortOperNway} = $prefix . '.2.4.4.1.6';
		$self->{OID_PortOperState} = $prefix . '.2.4.4.1.5';
		$self->{str_PortAdminState} = ([0, $other, $disabled, $enabled]);
		$self->{str_PortAdminNway} = ([0, $other, $nway_auto, $nway_10half, $nway_10full, $nway_100half, $nway_100full, '1000-half', $nway_1G, '1000-full-master', '1000-full-slave']);
		$self->{str_PortErrDisabled} = ([$none, $storm, $lbd, $ddm, $unknown]);
		$self->{str_PortOperNway} = ([$other, $empty, $link_fail, $nway_10half, $nway_10full, $nway_100half, $nway_100full, '1000-half', $nway_1G, $nway_10G]);
		$self->{str_PortOperState} = ([0, $other, $link_pass, $link_fail]);
		$self->{copper} = 1;
		$self->{fiber} = 2;
		$self->{max_ports} = 26;
		$self->{ErrDisabledCheckStatus} = 0;
		# ISM VLAN
		my $ISM_prefix = $prefix . '.2.10.6.1';
		$self->{OID_ISM_VLAN_Name} = $ISM_prefix . '.2.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Source} = $ISM_prefix . '.3.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Member} = $ISM_prefix . '.4.' . $self->{mvr};
		$self->{OID_ISM_VLAN_RowStatus} = $ISM_prefix . '.5.' . $self->{mvr};
		$self->{OID_ISM_VLAN_ReplaceSrcIP} = $ISM_prefix . '.6.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Remap} = $ISM_prefix . '.8.' . $self->{mvr};
		$self->{OID_ISM_VLAN_State} = $prefix . '.2.10.3.1.11.' . $self->{mvr};
		$self->{str_ISM_VLAN_State} = ([0, $other, $disabled, $enabled]);
		$self->{ISM_full_creation} = 1;
		# IGMP
		$self->{OID_IGMP_RouterDynamic} = $prefix . '.2.10.7.1.3.' . $self->{mvr};
		$self->{OID_IGMP_AA_PortState} = $prefix . '.2.10.8.1.2';
		$self->{OID_IGMP_Snooping} = $prefix . '.2.1.2.2.0';
		$self->{OID_IGMP_Info} = $prefix . '.2.10.5.1.4';
		$self->{str_IGMP_AA_PortState} = ([0, $disabled, $enabled]);
		$self->{str_IGMP_Snooping} = ([0, $other, $disabled, $enabled]);
		$self->{IGMPMcastVLANgroupsEqualMcastFilterProfiles} = 1;
		$self->{IGMPInfoIndex} = 'grponly';
		# DHCP Relay
		$self->{OID_DHCPLocalRelay_State} = $prefix . '.2.24.1.0';
		$self->{OID_DHCPRelay_State} = $dlink_common . '.42.1.1.0';
		$self->{str_DHCPLocalRelay_State} = ([0, $other, $disabled, $enabled]);
		$self->{str_DHCPRelay_State} = ([0, $enabled, $disabled]);
		# Syslog
		$self->{OID_Syslog_HostIP} = $dlink_common . '.12.2.1.2';
		$self->{OID_Syslog_Facility} = $dlink_common . '.12.2.1.3';
		$self->{OID_Syslog_Severity} = $dlink_common . '.12.2.1.4';
		$self->{OID_Syslog_ServerState} = $dlink_common . '.12.2.1.6';
		$self->{OID_Syslog_RowStatus} = $dlink_common . '.12.2.1.7';
		$self->{OID_Syslog_State} = $dlink_common . '12.1.0';
		$self->{str_Syslog_Facility} = ([$local0, $local1, $local2, $local3, $local4, $local5, $local6, $local7]);
		$self->{str_Syslog_Severity} = ([0, $all, $warn, $info]);
		$self->{str_Syslog_ServerState} = ([0, $other, $disabled, $enabled]);
		$self->{str_Syslog_State} = ([0, $other, $disabled, $enabled]);
		# RADIUS
		$self->{OID_RADIUS_Index} = $dlink_common . '.3.2.4.1.1';
		$self->{OID_RADIUS_IP} = $dlink_common . '.3.2.4.1.2';
		$self->{OID_RADIUS_AuthPort} = $dlink_common . '.3.2.4.1.4';
		$self->{OID_RADIUS_AcctPort} = $dlink_common . '.3.2.4.1.5';
		$self->{OID_RADIUS_Timeout} = $dlink_common . '.3.2.2.0';
		$self->{OID_RADIUS_Retransmit} = $dlink_common . '.3.2.3.0';
		# IMPB
		$self->{OID_IMPB_DHCPSnooping} = $prefix . '.2.7.7.0';
		$self->{OID_IMPB_PortState} = $prefix . '.2.7.1.1.2';
		$self->{OID_IMPB_ZeroIP} = $prefix . '.2.7.1.1.3';
		$self->{OID_IMPB_ForwardDHCPPkt} = $prefix . '.2.7.1.1.4';
		$self->{OID_IMPB_Port} = $prefix . '.2.7.2.1.4';
		$self->{OID_IMPB_MAC} = $prefix . '.2.7.2.1.2';
		$self->{OID_IMPB_IP} = $prefix . '.2.7.2.1.1';
		$self->{OID_IMPB_RowStatus} = $prefix . '.2.7.2.1.3';
		$self->{OID_IMPB_BlockVID} = $prefix . '.2.7.3.1.1';
		$self->{OID_IMPB_BlockMac} = $prefix . '.2.7.3.1.2';
		$self->{OID_IMPB_BlockPort} = $prefix . '.2.7.3.1.4';
		$self->{OID_IMPB_BlockRowStatus} = $prefix . '.2.7.3.1.5';
		$self->{str_IMPB_DHCPSnooping} = ([0, $enabled, $disabled]);
		$self->{str_IMPB_PortState} = ([0, $other, $strict, $disabled, $loose]);
		$self->{str_IMPB_ZeroIP} = ([0, $other, $enabled, $disabled]);
		$self->{str_IMPB_ForwardDHCPPkt} = ([0, $enabled, $disabled]);
		$self->{IMPBBlockDelete} = 3;
		# TrafCtrl
		$self->{OID_TrafCtrl_BroadcastStatus} = $dlink_common . '.25.3.1.1.3';
		$self->{OID_TrafCtrl_MulticastStatus} = $dlink_common . '.25.3.1.1.4';
		$self->{OID_TrafCtrl_UnicastStatus} = $dlink_common . '.25.3.1.1.5';
		$self->{OID_TrafCtrl_ActionStatus} = $dlink_common . '.25.3.1.1.6';
		$self->{OID_TrafCtrl_Countdown} = $dlink_common . '.25.3.1.1.7';
		$self->{OID_TrafCtrl_Interval} = $dlink_common . '.25.3.1.1.8';
		$self->{OID_TrafCtrl_BroadcastThreshold} = $dlink_common . '.25.3.1.1.10';
		$self->{OID_TrafCtrl_MulticastThreshold} = $dlink_common . '.25.3.1.1.11';
		$self->{OID_TrafCtrl_UnicastThreshold} = $dlink_common . '.25.3.1.1.12';
		$self->{str_TrafCtrl_BroadcastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_MulticastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_UnicastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_ActionStatus} = ([0, $shutdown, $drop]);
		# TrafSegmentation
		$self->{OID_TrafficSegForwardPorts} = $prefix . '.2.13.1.1.2';
		# SNTP
		$self->{OID_SNTP_State} = $dlink_common . '.10.11.1.0';
		$self->{OID_SNTP_PrimaryIP} = $dlink_common . '.10.11.3.0';
		$self->{OID_SNTP_SecondaryIP} = $dlink_common . '.10.11.4.0';
		$self->{OID_SNTP_PollInterval} = $dlink_common . '.10.11.5.0';
		$self->{str_SNTP_State} = ([0, $other, $disabled, $enabled]);
		# DHCP/Netbios filter
		$self->{OID_Filter_DHCP_PortState} = $dlink_common . '.37.1.2.1.2';
		$self->{OID_Filter_Netbios_PortState} = $dlink_common . '.37.2.1.1.2';
		$self->{OID_Filter_ExtNetbios_PortState} = $dlink_common . '.37.3.1.1.2';
		$self->{str_Filter_DHCP_PortState} = ([0, $enabled, $disabled]);
		$self->{str_Filter_Netbios_PortState} = ([0, $enabled, $disabled]);
		$self->{str_Filter_ExtNetbios_PortState} = ([0, $enabled, $disabled]);
		$self->{FilterNetbiosTroughPCF} = 0;
		# LBD
		$self->{OID_LBD_State} = $prefix . '.2.12.1.1.0';
		$self->{OID_LBD_PortState} = $prefix . '.2.12.2.1.1.2';
		$self->{OID_LBD_PortLoopStatus} = $prefix . '.2.12.2.1.1.4';
		$self->{str_LBD_State} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortState} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortLoopStatus} = ([0, $normal, $loop, $error]);
		# Mcast filtering
		$self->{OID_McastRange_Name} = $prefix . '.2.5.1.1.1';
		$self->{OID_McastRange_From} = $prefix . '.2.5.1.1.2';
		$self->{OID_McastRange_To} = $prefix . '.2.5.1.1.3';
		$self->{OID_McastRange_RowStatus} = $prefix . '.2.5.1.1.4';
		$self->{OID_Mcast_PortAccess} = $prefix . '.2.5.2.1.1.2';
		$self->{OID_Mcast_PortState} = $prefix . '.2.5.2.1.1.3';
		$self->{OID_Mcast_PortRangeID} = $prefix . '.2.5.2.2.1.1';
		$self->{OID_Mcast_PortRangeName} = $prefix . '.2.5.2.2.1.2';
		$self->{OID_Mcast_PortRange_RowStatus} = $prefix . '.2.5.2.2.1.5';
		$self->{str_Mcast_PortAccess} = ([0, $none, $permit, $deny]);
		$self->{str_Mcast_PortState} = ([0, $other, $disabled, $enabled]);
		$self->{McastFilterSNMPNameIndex} = 1;
		# Other
		$self->{OID_WebState} = $prefix . '.2.1.2.17.1.0';
		$self->{OID_WebPort} = $prefix . '.2.1.2.17.2.0';
		$self->{OID_TelnetState} = $prefix . '.2.1.2.15.1.0';
		$self->{OID_TelnetPort} = $prefix . '.2.1.2.15.2.0';
		$self->{str_WebState} = ([0, $other, $disabled, $enabled]);
		$self->{str_TelnetState} = ([0, $other, $disabled, $enabled]);
		my $OID = $prefix . '.2.1.2.14.0';
		$result = $snmp->get_request(-varbindlist => [$OID]);
		$self->{mgmtVLAN} = $result->{$OID};
		$self->{mask_size} = 8;
		$self->{archaic_802dot1q} = 1;
		# ACL
		$self->{OID_EtherACL_Profile} = $dlink_common . '.9.1.1.1.1';
		$self->{OID_EtherACL_UseEtype} = $dlink_common . '.9.1.1.1.7';
		$self->{OID_EtherACL_UseMAC} = $dlink_common . '.9.1.1.1.3';
		$self->{OID_EtherACL_Profile_SrcMACMask} = $dlink_common . '.9.1.1.1.4';
		$self->{OID_EtherACL_Profile_RowStatus} = $dlink_common . '.9.1.1.1.8';
		$self->{OID_EtherACL_Etype} = $dlink_common . '.9.2.1.1.7';
		$self->{OID_EtherACL_RuleID} = $dlink_common . '.9.2.1.1.2';
		$self->{OID_EtherACL_Permit} = $dlink_common . '.9.2.1.1.13';
		$self->{OID_EtherACL_SrcMAC} = $dlink_common . '.9.2.1.1.4';
		$self->{OID_EtherACL_DstMAC} = $dlink_common . '.9.2.1.1.5';
		$self->{OID_EtherACL_Port} = $dlink_common . '.9.2.1.1.14';
		$self->{OID_EtherACL_Rule_RowStatus} = $dlink_common . '.9.2.1.1.15';
		$self->{str_EtherACL_Permit} = ([0, $deny, $permit]);
		$self->{str_EtherACL_UseEtype} = ([0, $enabled, $disabled]);
		$self->{str_EtherACL_UseMAC} = ([0, $none, 'dst', 'src', 'srcdst']);
		$self->{ACL_rule_per_port} = 1;
		# Safeguard
		$self->{OID_SafeguardGlobalState} = $dlink_common . '.19.1.1.0';
		$self->{OID_SafeguardRisingThreshold} = $dlink_common . '.19.2.1.0';
		$self->{OID_SafeguardFallingThreshold} = $dlink_common . '.19.2.2.0';
		$self->{OID_SafeguardMode} = $dlink_common . '.19.2.3.0';
		$self->{OID_SafeguardTrap} = $dlink_common . '.19.2.4.0';
		$self->{OID_SafeguardStatus} = $dlink_common . '.19.2.5.0';
		$self->{str_SafeguardGlobalState} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardMode} = ([0, 'strict', 'fuzzy']);
		$self->{str_SafeguardTrap} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardStatus} = ([0, 'normal', 'exhausted']);
	} elsif ($model eq '105.1') {
	#################
	#
	#	DES-3528
	#
	#################
		$self->{name} = 'DES-3528';
		# Ports
		$self->{OID_PortAdminNway} = $prefix . '.2.3.2.1.5';
		$self->{OID_PortAdminState} = $prefix . '.2.3.2.1.4';
		$self->{OID_PortErrDisabled} = $prefix . '.2.3.1.1.8';
		$self->{OID_PortOperNway} = $prefix . '.2.3.1.1.6';
		$self->{OID_PortOperState} = $prefix . '.2.3.1.1.5';
		$self->{str_PortAdminState} = ([0, $other, $disabled, $enabled]);
		$self->{str_PortAdminNway} = ([0, $other, $nway_auto, $nway_10half, $nway_10full, $nway_100half, $nway_100full, '1000-half', $nway_1G, '1000-full-master', '1000-full-slave']);
		$self->{str_PortErrDisabled} = ([$none, $storm, $unknown, $unknown, $lbd]);
		$self->{str_PortOperNway} = ([$link_fail, '10-full-8023x', $nway_10full, '10-half-backup', $nway_10half, '100-full-8023x', $nway_100full, '100-half-backup', $nway_100half, '1000-full-8023x', $nway_1G, '1000-half-backup', '1000-half', '10000-full-8023x', $nway_10G, '10000-half-8023x', '10000-half', $empty]);
		$self->{str_PortOperState} = ([0, $other, $link_pass, $link_fail]);
		$self->{copper} = 1;
		$self->{fiber} = 2;
		$self->{max_ports} = 28;
		$self->{ErrDisabledCheckStatus} = 0;
		# ISM VLAN
		my $ISM_prefix = $dlink_common . '.64.3.1.1';
		$self->{OID_ISM_VLAN_Name} = $ISM_prefix . '.2.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Source} = $ISM_prefix . '.3.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Member} = $ISM_prefix . '.4.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Tagged} = $ISM_prefix . '.5.' . $self->{mvr};
		$self->{OID_ISM_VLAN_State} = $ISM_prefix . '.7.' . $self->{mvr};
		$self->{OID_ISM_VLAN_ReplaceSrcIPType} = $ISM_prefix . '.8.' . $self->{mvr};
		$self->{OID_ISM_VLAN_ReplaceSrcIP} = $ISM_prefix . '.9.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Remap} = $ISM_prefix . '.10.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Replace} = $ISM_prefix . '.11.' . $self->{mvr};
		$self->{OID_ISM_VLAN_RowStatus} = $ISM_prefix . '.13.' . $self->{mvr};
		$self->{str_ISM_VLAN_State} = ([0, $enabled, $disabled]);
		$self->{str_ISM_VLAN_Replace} = ([0, $enabled, $disabled]);
		# IGMP
		my $IGMP_prefix = $dlink_common . '.73.3.1';
		$self->{OID_IGMP_Querier_Version} = $IGMP_prefix . '.1.1.60.' . $self->{mvr};
		$self->{OID_IGMP_DataDriven} = $IGMP_prefix . '.1.1.65.' . $self->{mvr};
		$self->{OID_IGMP_DataDriven_AgedOut} = $IGMP_prefix . '.1.1.70.' . $self->{mvr};
		$self->{OID_IGMP_FastLeave} = $IGMP_prefix . '.1.1.50.' . $self->{mvr};
		$self->{OID_IGMP_ReportSuppression} = $IGMP_prefix . '.1.1.55.' . $self->{mvr};
		$self->{OID_IGMP_AA_PortState} = $prefix . '.2.11.13.1.2';
		$self->{OID_IGMP_Snooping} = $dlink_common . '.73.1.1.0';
		$self->{OID_IGMP_Info} = $dlink_common . '.73.2.1.2.1.4';
		$self->{str_IGMP_AA_PortState} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_Snooping} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_DataDriven} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_DataDriven_AgedOut} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_FastLeave} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_ReportSuppression} = ([0, $enabled, $disabled]);
		$self->{OID_IGMP_McastVLANgroups} = $dlink_common . '.64.3.1.1.12.' . $self->{mvr};
		$self->{OID_IGMP_McastVLANgroupName_Index} = $dlink_common . '.64.3.2.1.2';
		$self->{OID_IGMP_McastVLANgroupName_RowStatus} = $dlink_common . '.64.3.2.1.3';
		$self->{OID_IGMP_McastVLANgroupStart} = $dlink_common . '.64.3.3.1.2';
		$self->{OID_IGMP_McastVLANgroupEnd} = $dlink_common . '.64.3.3.1.3';
		$self->{OID_IGMP_McastVLANgroup_RowStatus} = $dlink_common . '.64.3.3.1.4';
		$self->{IGMPInfoIndex} = 'src255grp';
		# DHCP Relay
		$self->{OID_DHCPLocalRelay_State} = $prefix . '.2.24.1.0';
		$self->{OID_DHCPRelay_State} = $dlink_common . '.42.1.1.0';
		$self->{str_DHCPLocalRelay_State} = ([0, $other, $disabled, $enabled]);
		$self->{str_DHCPRelay_State} = ([0, $enabled, $disabled]);
		# Syslog
		$self->{OID_Syslog_HostIP} = $dlink_common . '.12.2.1.9';
		$self->{OID_Syslog_AddrType} = $dlink_common . '.12.2.1.8';
		$self->{OID_Syslog_Facility} = $dlink_common . '.12.2.1.3';
		$self->{OID_Syslog_Severity} = $dlink_common . '.12.2.1.4';
		$self->{OID_Syslog_ServerState} = $dlink_common . '.12.2.1.6';
		$self->{OID_Syslog_RowStatus} = $dlink_common . '.12.2.1.7';
		$self->{OID_Syslog_State} = $dlink_common . '12.1.0';
		$self->{str_Syslog_Facility} = ([$local0, $local1, $local2, $local3, $local4, $local5, $local6, $local7]);
		$self->{str_Syslog_Severity} = ([0, $all, $warn, $info, $emergency, $alert, $critical, $error, $notice, $debug]);
		$self->{str_Syslog_ServerState} = ([0, $other, $disabled, $enabled]);
		$self->{str_Syslog_State} = ([0, $other, $disabled, $enabled]);
		# RADIUS
		$self->{OID_RADIUS_Index} = $dlink_common . '.3.2.4.1.1';
		$self->{OID_RADIUS_IP} = $dlink_common . '.3.2.4.1.10';
		$self->{OID_RADIUS_AuthPort} = $dlink_common . '.3.2.4.1.4';
		$self->{OID_RADIUS_AcctPort} = $dlink_common . '.3.2.4.1.5';
		$self->{OID_RADIUS_Timeout} = $dlink_common . '.3.2.4.1.7';
		$self->{OID_RADIUS_Retransmit} = $dlink_common . '.3.2.4.1.8';
		$self->{RADIUS_separate_params} = 1;
		# IMPB
		$self->{OID_IMPB_DHCPSnooping} = $dlink_common . '.23.1.4.0';
		$self->{OID_IMPB_PortState} = $dlink_common . '.23.3.2.1.2';
		$self->{OID_IMPB_ZeroIP} = $dlink_common . '.23.3.2.1.3';
		$self->{OID_IMPB_ForwardDHCPPkt} = $dlink_common . '.23.3.2.1.4';
		$self->{OID_IMPB_Port} = $dlink_common . '.23.4.1.1.4';
		$self->{OID_IMPB_MAC} = $dlink_common . '.23.4.1.1.2';
		$self->{OID_IMPB_IP} = $dlink_common . '.23.4.1.1.1';
		$self->{OID_IMPB_RowStatus} = $dlink_common . '.23.4.1.1.3';
		$self->{OID_IMPB_BlockVID} = $dlink_common . '.23.4.2.1.1';
		$self->{OID_IMPB_BlockMac} = $dlink_common . '.23.4.2.1.2';
		$self->{OID_IMPB_BlockPort} = $dlink_common . '.23.4.2.1.4';
		$self->{str_IMPB_DHCPSnooping} = ([0, $enabled, $disabled]);
		$self->{str_IMPB_PortState} = ([0, $other, $strict, $disabled, $loose]);
		$self->{str_IMPB_ZeroIP} = ([0, $enabled, $disabled]);
		$self->{str_IMPB_ForwardDHCPPkt} = ([0, $enabled, $disabled]);
		# TrafCtrl
		$self->{OID_TrafCtrl_BroadcastStatus} = $dlink_common . '.25.3.1.1.3';
		$self->{OID_TrafCtrl_MulticastStatus} = $dlink_common . '.25.3.1.1.4';
		$self->{OID_TrafCtrl_UnicastStatus} = $dlink_common . '.25.3.1.1.5';
		$self->{OID_TrafCtrl_ActionStatus} = $dlink_common . '.25.3.1.1.6';
		$self->{OID_TrafCtrl_Countdown} = $dlink_common . '.25.3.1.1.7';
		$self->{OID_TrafCtrl_Interval} = $dlink_common . '.25.3.1.1.8';
		$self->{OID_TrafCtrl_BroadcastThreshold} = $dlink_common . '.25.3.1.1.10';
		$self->{OID_TrafCtrl_MulticastThreshold} = $dlink_common . '.25.3.1.1.11';
		$self->{OID_TrafCtrl_UnicastThreshold} = $dlink_common . '.25.3.1.1.12';
		$self->{str_TrafCtrl_BroadcastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_MulticastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_UnicastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_ActionStatus} = ([0, $shutdown, $drop]);
		# TrafSegmentation
		$self->{OID_TrafficSegForwardPorts} = $prefix . '.2.14.1.1.2';
		# SNTP
		$self->{OID_SNTP_State} = $dlink_common . '.10.11.1.0';
		$self->{OID_SNTP_PrimaryIP} = $dlink_common . '.10.11.3.0';
		$self->{OID_SNTP_SecondaryIP} = $dlink_common . '.10.11.4.0';
		$self->{OID_SNTP_PollInterval} = $dlink_common . '.10.11.5.0';
		$self->{str_SNTP_State} = ([0, $other, $disabled, $enabled]);
		# DHCP/Netbios filter
		$self->{OID_Filter_DHCP_PortState} = $dlink_common . '.37.1.2.1.2';
		$self->{OID_Filter_Netbios_PortState} = $dlink_common . '.37.2.1.1.2';
		$self->{OID_Filter_ExtNetbios_PortState} = $dlink_common . '.37.3.1.1.2';
		$self->{str_Filter_DHCP_PortState} = ([0, $enabled, $disabled]);
		$self->{str_Filter_Netbios_PortState} = ([0, $enabled, $disabled]);
		$self->{str_Filter_ExtNetbios_PortState} = ([0, $enabled, $disabled]);
		$self->{FilterNetbiosTroughPCF} = 0;
		# LBD
		$self->{OID_LBD_State} = $dlink_common . '.41.1.1.0';
		$self->{OID_LBD_PortState} = $dlink_common . '.41.3.1.1.2';
		$self->{OID_LBD_PortLoopStatus} = $dlink_common . '.41.3.1.1.4';
		$self->{str_LBD_State} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortState} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortLoopStatus} = ([0, $normal, $loop, $error]);
		# Mcast filtering
		my $Mcast_prefix = $dlink_common . '.53';
		$self->{OID_McastRange_ID} = $Mcast_prefix . '.1.1.1';
		$self->{OID_McastRange_Name} = $Mcast_prefix . '.1.1.2';
		$self->{OID_McastRange_RowStatus} = $Mcast_prefix . '.1.1.3';
		$self->{OID_McastRangeAddress_RowStatus} = $Mcast_prefix . '.2.1.4';
		$self->{OID_McastRange_From} = $Mcast_prefix . '.2.1.2';
		$self->{OID_McastRange_To} = $Mcast_prefix . '.2.1.3';
		$self->{OID_Mcast_PortAccess} = $Mcast_prefix . '.4.1.2';
		$self->{OID_Mcast_PortRangeID} = $Mcast_prefix . '.3.1.2';
		$self->{OID_Mcast_Port_RowStatus} = $Mcast_prefix . '.3.1.3';
		$self->{str_Mcast_PortAccess} = ([0, $permit, $deny]);
		$self->{McastFilterSNMPTrailingAddr} = 1;
		# Other
		$self->{OID_WebState} = $prefix . '.2.1.2.17.1.0';
		$self->{OID_WebPort} = $prefix . '.2.1.2.17.2.0';
		$self->{OID_TelnetState} = $prefix . '.2.1.2.14.1.0';
		$self->{OID_TelnetPort} = $prefix . '.2.1.2.14.2.0';
		$self->{str_WebState} = ([0, $enabled, $disabled]);
		$self->{str_TelnetState} = ([0, $other, $disabled, $enabled]);
		my $OID = $prefix . '.2.1.2.16.0';
		$result = $snmp->get_request(-varbindlist => [$OID]);
		$self->{mgmtVLAN} = $result->{$OID};
		# ACL
		$self->{OID_EtherACL_Profile} = $dlink_common . '.9.2.1.1.1';
		$self->{OID_EtherACL_UseEtype} = $dlink_common . '.9.2.1.1.7';
		$self->{OID_EtherACL_UseMAC} = $dlink_common . '.9.2.1.1.3';
		$self->{OID_EtherACL_Profile_SrcMACMask} = $dlink_common . '.9.2.1.1.4';
		$self->{OID_EtherACL_Profile_RowStatus} = $dlink_common . '.9.2.1.1.8';
		$self->{OID_EtherACL_ProfileName} = $dlink_common . '.9.2.1.1.11';
		$self->{OID_EtherACL_RuleID} = $dlink_common . '.9.3.1.1.2';
		$self->{OID_EtherACL_Etype} = $dlink_common . '.9.3.1.1.7';
		$self->{OID_EtherACL_Permit} = $dlink_common . '.9.3.1.1.13';
		$self->{OID_EtherACL_SrcMAC} = $dlink_common . '.9.3.1.1.4';
		$self->{OID_EtherACL_SrcMACMask} = $dlink_common . '.9.3.1.1.23';
		$self->{OID_EtherACL_Port} = $dlink_common . '.9.3.1.1.14';
		$self->{OID_EtherACL_Rule_RowStatus} = $dlink_common . '.9.3.1.1.15';
		$self->{str_EtherACL_UseEtype} = ([0, $enabled, $disabled]);
		$self->{str_EtherACL_Permit} = ([0, $deny, $permit]);
		$self->{str_EtherACL_UseMAC} = ([0, $none, 'dst', 'src', 'srcdst']);
		$self->{ACLProfileHasName} = 1;
		# Safeguard
		$self->{OID_SafeguardGlobalState} = $dlink_common . '.19.1.1.0';
		$self->{OID_SafeguardRisingThreshold} = $dlink_common . '.19.2.1.0';
		$self->{OID_SafeguardFallingThreshold} = $dlink_common . '.19.2.2.0';
		$self->{OID_SafeguardMode} = $dlink_common . '.19.2.3.0';
		$self->{OID_SafeguardTrap} = $dlink_common . '.19.2.4.0';
		$self->{OID_SafeguardStatus} = $dlink_common . '.19.2.5.0';
		$self->{str_SafeguardGlobalState} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardMode} = ([0, 'strict', 'fuzzy']);
		$self->{str_SafeguardTrap} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardStatus} = ([0, 'normal', 'exhausted']);
	} elsif ($model =~ '113.[36].1') {
	##############################
	#
	#	DES-3200 rev. C1 series
	#
	##############################
		# Ports
		$self->{OID_PortAdminNway} = $prefix . '.2.3.2.1.5';
		$self->{OID_PortAdminState} = $prefix . '.2.3.2.1.4';
		$self->{OID_PortErrDisabled} = $prefix . '.2.3.1.1.8';
		$self->{OID_PortOperNway} = $prefix . '.2.3.1.1.6';
		$self->{OID_PortOperState} = $prefix . '.2.3.1.1.5';
		$self->{str_PortAdminState} = ([0, $other, $disabled, $enabled]);
		$self->{str_PortAdminNway} = ([0, $other, $nway_auto, $nway_10half, $nway_10full, $nway_100half, $nway_100full, '1000-half', $nway_1G, '1000-full-master', '1000-full-slave']);
		$self->{str_PortErrDisabled} = ([$none, $storm, $lbd, $unknown]);
		$self->{str_PortOperNway} = ([$other, $empty, $link_fail, $nway_10half, $nway_10full, $nway_100half, $nway_100full, '1000-half', $nway_1G, $nway_10G]);
		$self->{str_PortOperState} = ([0, $other, $link_pass, $link_fail]);
		$self->{copper} = 1;
		$self->{fiber} = 2;
		$self->{default_medium} = 'fiber';
		$self->{ErrDisabledCheckStatus} = 0;
		
		if ($model eq '113.6.1') {
			$self->{name} = 'DES-3200-28F/C1';
			$self->{max_ports} = 28;
		} elsif ($model eq '113.3.1') {
			$self->{name} = 'DES-3200-18/C1';
			$self->{max_ports} = 18;
		}
		
		# ISM VLAN
		my $ISM_prefix = $dlink_common . '.64.3.1.1';
		$self->{OID_ISM_VLAN_Name} = $ISM_prefix . '.2.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Source} = $ISM_prefix . '.3.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Member} = $ISM_prefix . '.4.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Tagged} = $ISM_prefix . '.5.' . $self->{mvr};
		$self->{OID_ISM_VLAN_State} = $ISM_prefix . '.7.' . $self->{mvr};
		$self->{OID_ISM_VLAN_ReplaceSrcIPType} = $ISM_prefix . '.8.' . $self->{mvr};
		$self->{OID_ISM_VLAN_ReplaceSrcIP} = $ISM_prefix . '.9.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Remap} = $ISM_prefix . '.10.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Replace} = $ISM_prefix . '.11.' . $self->{mvr};
		$self->{OID_ISM_VLAN_RowStatus} = $ISM_prefix . '.13.' . $self->{mvr};
		$self->{str_ISM_VLAN_State} = ([0, $enabled, $disabled]);
		$self->{str_ISM_VLAN_Replace} = ([0, $enabled, $disabled]);
		# IGMP
		my $IGMP_prefix = $dlink_common . '.73.3.1';
		$self->{OID_IGMP_Querier_Version} = $IGMP_prefix . '.1.1.60.' . $self->{mvr};
		$self->{OID_IGMP_DataDriven} = $IGMP_prefix . '.1.1.65.' . $self->{mvr};
		$self->{OID_IGMP_DataDriven_AgedOut} = $IGMP_prefix . '.1.1.70.' . $self->{mvr};
		$self->{OID_IGMP_FastLeave} = $IGMP_prefix . '.1.1.50.' . $self->{mvr};
		$self->{OID_IGMP_ReportSuppression} = $IGMP_prefix . '.1.1.55.' . $self->{mvr};
		$self->{OID_IGMP_AA_PortState} = $prefix . '.2.11.13.1.2';
		$self->{OID_IGMP_Snooping} = $dlink_common . '.73.1.1.0';
		$self->{OID_IGMP_Info} = $dlink_common . '.73.2.1.2.1.4';
		$self->{str_IGMP_AA_PortState} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_Snooping} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_DataDriven} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_DataDriven_AgedOut} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_FastLeave} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_ReportSuppression} = ([0, $enabled, $disabled]);
		$self->{OID_IGMP_McastVLANgroups} = $dlink_common . '.64.3.1.1.12.' . $self->{mvr};
		$self->{OID_IGMP_McastVLANgroupName_Index} = $dlink_common . '.64.3.2.1.2';
		$self->{OID_IGMP_McastVLANgroupName_RowStatus} = $dlink_common . '.64.3.2.1.3';
		$self->{OID_IGMP_McastVLANgroupStart} = $dlink_common . '.64.3.3.1.2';
		$self->{OID_IGMP_McastVLANgroupEnd} = $dlink_common . '.64.3.3.1.3';
		$self->{OID_IGMP_McastVLANgroup_RowStatus} = $dlink_common . '.64.3.3.1.4';
		$self->{IGMPInfoIndex} = 'src255grp';
		# DHCP Relay
		$self->{OID_DHCPLocalRelay_State} = $prefix . '.2.24.1.0';
		$self->{OID_DHCPRelay_State} = $dlink_common . '.42.1.1.0';
		$self->{str_DHCPLocalRelay_State} = ([0, $other, $disabled, $enabled]);
		$self->{str_DHCPRelay_State} = ([0, $enabled, $disabled]);
		# Syslog
		$self->{OID_Syslog_HostIP} = $dlink_common . '.12.2.1.9';
		$self->{OID_Syslog_AddrType} = $dlink_common . '.12.2.1.8';
		$self->{OID_Syslog_Facility} = $dlink_common . '.12.2.1.3';
		$self->{OID_Syslog_Severity} = $dlink_common . '.12.2.1.4';
		$self->{OID_Syslog_ServerState} = $dlink_common . '.12.2.1.6';
		$self->{OID_Syslog_RowStatus} = $dlink_common . '.12.2.1.7';
		$self->{OID_Syslog_State} = $dlink_common . '12.1.0';
		$self->{str_Syslog_Facility} = ([$local0, $local1, $local2, $local3, $local4, $local5, $local6, $local7]);
		$self->{str_Syslog_Severity} = ([0, $all, $warn, $info, $emergency, $alert, $critical, $error, $notice, $debug]);
		$self->{str_Syslog_ServerState} = ([0, $other, $disabled, $enabled]);
		$self->{str_Syslog_State} = ([0, $other, $disabled, $enabled]);
		# RADIUS
		$self->{OID_RADIUS_Index} = $dlink_common . '.3.2.4.1.1';
		$self->{OID_RADIUS_IP} = $dlink_common . '.3.2.4.1.10';
		$self->{OID_RADIUS_AuthPort} = $dlink_common . '.3.2.4.1.4';
		$self->{OID_RADIUS_AcctPort} = $dlink_common . '.3.2.4.1.5';
		$self->{OID_RADIUS_Timeout} = $dlink_common . '.3.2.4.1.7';
		$self->{OID_RADIUS_Retransmit} = $dlink_common . '.3.2.4.1.8';
		$self->{RADIUS_separate_params} = 1;
		# IMPB
		$self->{OID_IMPB_DHCPSnooping} = $dlink_common . '.23.1.4.0';
		$self->{OID_IMPB_PortState} = $dlink_common . '.23.3.2.1.16';
		$self->{OID_IMPB_ZeroIP} = $dlink_common . '.23.3.2.1.3';
		$self->{OID_IMPB_ForwardDHCPPkt} = $dlink_common . '.23.3.2.1.4';
		$self->{OID_IMPB_Port} = $dlink_common . '.23.4.1.1.4';
		$self->{OID_IMPB_MAC} = $dlink_common . '.23.4.1.1.2';
		$self->{OID_IMPB_IP} = $dlink_common . '.23.4.1.1.1';
		$self->{OID_IMPB_RowStatus} = $dlink_common . '.23.4.1.1.3';
		$self->{OID_IMPB_BlockVID} = $dlink_common . '.23.4.2.1.1';
		$self->{OID_IMPB_BlockMac} = $dlink_common . '.23.4.2.1.2';
		$self->{OID_IMPB_BlockPort} = $dlink_common . '.23.4.2.1.4';
		$self->{str_IMPB_DHCPSnooping} = ([0, $enabled, $disabled]);
		$self->{str_IMPB_PortState} = ([0, $disabled, $strict, $loose]);
		$self->{str_IMPB_ZeroIP} = ([0, $enabled, $disabled]);
		$self->{str_IMPB_ForwardDHCPPkt} = ([0, $enabled, $disabled]);
		# TrafCtrl
		$self->{OID_TrafCtrl_BroadcastStatus} = $dlink_common . '.25.3.1.1.3';
		$self->{OID_TrafCtrl_MulticastStatus} = $dlink_common . '.25.3.1.1.4';
		$self->{OID_TrafCtrl_UnicastStatus} = $dlink_common . '.25.3.1.1.5';
		$self->{OID_TrafCtrl_ActionStatus} = $dlink_common . '.25.3.1.1.6';
		$self->{OID_TrafCtrl_Countdown} = $dlink_common . '.25.3.1.1.7';
		$self->{OID_TrafCtrl_Interval} = $dlink_common . '.25.3.1.1.8';
		$self->{OID_TrafCtrl_BroadcastThreshold} = $dlink_common . '.25.3.1.1.10';
		$self->{OID_TrafCtrl_MulticastThreshold} = $dlink_common . '.25.3.1.1.11';
		$self->{OID_TrafCtrl_UnicastThreshold} = $dlink_common . '.25.3.1.1.12';
		$self->{str_TrafCtrl_BroadcastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_MulticastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_UnicastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_ActionStatus} = ([0, $shutdown, $drop]);
		# TrafSegmentation
		$self->{OID_TrafficSegForwardPorts} = $prefix . '.2.14.1.1.2';
		# SNTP
		$self->{OID_SNTP_State} = $dlink_common . '.10.11.1.0';
		$self->{OID_SNTP_PrimaryIP} = $dlink_common . '.10.11.3.0';
		$self->{OID_SNTP_SecondaryIP} = $dlink_common . '.10.11.4.0';
		$self->{OID_SNTP_PollInterval} = $dlink_common . '.10.11.5.0';
		$self->{str_SNTP_State} = ([0, $other, $disabled, $enabled]);
		# DHCP/Netbios filter
		$self->{OID_Filter_DHCP_PortState} = $dlink_common . '.37.1.2.1.2';
		$self->{OID_Filter_Netbios_PortState} = $dlink_common . '.37.2.1.1.2';
		$self->{OID_Filter_ExtNetbios_PortState} = $dlink_common . '.37.3.1.1.2';
		$self->{str_Filter_DHCP_PortState} = ([0, $enabled, $disabled]);
		$self->{str_Filter_Netbios_PortState} = ([0, $enabled, $disabled]);
		$self->{str_Filter_ExtNetbios_PortState} = ([0, $enabled, $disabled]);
		$self->{FilterNetbiosTroughPCF} = 0;
		# LBD
		$self->{OID_LBD_State} = $dlink_common . '.41.1.1.0';
		$self->{OID_LBD_PortState} = $dlink_common . '.41.3.1.1.2';
		$self->{OID_LBD_PortLoopStatus} = $dlink_common . '.41.3.1.1.4';
		$self->{str_LBD_State} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortState} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortLoopStatus} = ([0, $normal, $loop, $error]);
		# Mcast filtering
		my $Mcast_prefix = $dlink_common . '.53';
		$self->{OID_McastRange_ID} = $Mcast_prefix . '.1.1.1';
		$self->{OID_McastRange_Name} = $Mcast_prefix . '.1.1.2';
		$self->{OID_McastRange_RowStatus} = $Mcast_prefix . '.1.1.3';
		$self->{OID_McastRangeAddress_RowStatus} = $Mcast_prefix . '.2.1.4';
		$self->{OID_McastRange_From} = $Mcast_prefix . '.2.1.2';
		$self->{OID_McastRange_To} = $Mcast_prefix . '.2.1.3';
		$self->{OID_Mcast_PortAccess} = $Mcast_prefix . '.4.1.2';
		$self->{OID_Mcast_PortRangeID} = $Mcast_prefix . '.3.1.2';
		$self->{OID_Mcast_Port_RowStatus} = $Mcast_prefix . '.3.1.3';
		$self->{str_Mcast_PortAccess} = ([0, $permit, $deny]);
		$self->{McastFilterSNMPTrailingAddr} = 1;
		# Other
		$self->{OID_WebState} = $prefix . '.2.1.2.17.1.0';
		$self->{OID_WebPort} = $prefix . '.2.1.2.17.2.0';
		$self->{OID_TelnetState} = $prefix . '.2.1.2.14.1.0';
		$self->{OID_TelnetPort} = $prefix . '.2.1.2.14.2.0';
		$self->{str_WebState} = ([0, $enabled, $disabled]);
		$self->{str_TelnetState} = ([0, $other, $disabled, $enabled]);
		my $OID = $prefix . '.2.1.2.16.0';
		$result = $snmp->get_request(-varbindlist => [$OID]);
		$self->{mgmtVLAN} = $result->{$OID};
		# ACL
		$self->{OID_EtherACL_Profile} = $dlink_common . '.9.2.1.1.1';
		$self->{OID_EtherACL_UseEtype} = $dlink_common . '.9.2.1.1.7';
		$self->{OID_EtherACL_UseMAC} = $dlink_common . '.9.2.1.1.3';
		$self->{OID_EtherACL_Profile_SrcMACMask} = $dlink_common . '.9.2.1.1.4';
		$self->{OID_EtherACL_Profile_RowStatus} = $dlink_common . '.9.2.1.1.8';
		$self->{OID_EtherACL_ProfileName} = $dlink_common . '.9.2.1.1.11';
		$self->{OID_EtherACL_RuleID} = $dlink_common . '.9.3.1.1.2';
		$self->{OID_EtherACL_Etype} = $dlink_common . '.9.3.1.1.7';
		$self->{OID_EtherACL_Permit} = $dlink_common . '.9.3.1.1.13';
		$self->{OID_EtherACL_SrcMAC} = $dlink_common . '.9.3.1.1.4';
		$self->{OID_EtherACL_SrcMACMask} = $dlink_common . '.9.3.1.1.23';
		$self->{OID_EtherACL_Port} = $dlink_common . '.9.3.1.1.14';
		$self->{OID_EtherACL_Rule_RowStatus} = $dlink_common . '.9.3.1.1.15';
		$self->{str_EtherACL_UseEtype} = ([0, $enabled, $disabled]);
		$self->{str_EtherACL_Permit} = ([0, $deny, $permit]);
		$self->{str_EtherACL_UseMAC} = ([0, $none, 'dst', 'src', 'srcdst']);
		$self->{ACLProfileHasName} = 1;
		# Safeguard
		$self->{OID_SafeguardGlobalState} = $dlink_common . '.19.1.1.0';
		$self->{OID_SafeguardRisingThreshold} = $dlink_common . '.19.2.1.0';
		$self->{OID_SafeguardFallingThreshold} = $dlink_common . '.19.2.2.0';
		$self->{OID_SafeguardMode} = $dlink_common . '.19.2.3.0';
		$self->{OID_SafeguardTrap} = $dlink_common . '.19.2.4.0';
		$self->{OID_SafeguardStatus} = $dlink_common . '.19.2.5.0';
		$self->{str_SafeguardGlobalState} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardMode} = ([0, 'strict', 'fuzzy']);
		$self->{str_SafeguardTrap} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardStatus} = ([0, 'normal', 'exhausted']);
	} elsif (($model =~ '113.1.[12345]') or ($model eq '116.2')) {
	##############################
	#
	#	DES-3200 rev. A1 series + DES-1228/ME
	#
	##############################
		# Ports
		$self->{OID_PortAdminNway} = $prefix . '.2.2.2.1.4';
		$self->{OID_PortAdminState} = $prefix . '.2.2.2.1.3';
		$self->{OID_PortOperNway} = $prefix . '.2.2.1.1.5';
		$self->{OID_PortOperState} = $prefix . '.2.2.1.1.4';
		$self->{str_PortAdminState} = ([0, $other, $disabled, $enabled]);
		$self->{str_PortAdminNway} = ([0, $nway_auto, $nway_10half, $nway_10full, $nway_100half, $nway_100full, $other, $nway_1G, '1000-full-master', '1000-full-slave']);
		$self->{str_PortOperNway} = ([0, $link_fail, $nway_10half, $nway_10full, $nway_100half, $nway_100full, $other, $nway_1G]);
		$self->{str_PortOperState} = ([0, $other, $link_pass, $link_fail]);
		$self->{copper} = 100;
		$self->{fiber} = 101;
		$self->{ErrDisabledCheckStatus} = 1;
		
		if ($model eq '113.1.1') {
			$self->{name} = 'DES-3200-10/A1';
			$self->{max_ports} = 10;
		} elsif ($model eq '113.1.2') {
			$self->{name} = 'DES-3200-18/A1';
			$self->{max_ports} = 18;
		} elsif ($model =~ '113.1.5') {
			$self->{name} = 'DES-3200-26/A1';
			$self->{max_ports} = 26;
		} else {
			$self->{max_ports} = 28;
		}
		
		if ($model eq '113.1.4') {
			$self->{name} = 'DES-3200-28F/A1';
			$self->{default_medium} = 'fiber';
		}
		
		if ($model eq '113.1.3') {
			$self->{name} = 'DES-3200-28/A1';
		}
		
		if ($model eq '116.2') {
			$self->{name} = 'DES-1228/ME/B1A';
		}
		
		# ISM VLAN
		my $ISM_prefix = $prefix . '.2.7.8.1';
		$self->{OID_ISM_VLAN_Name} = $ISM_prefix . '.2.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Source} = $ISM_prefix . '.3.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Member} = $ISM_prefix . '.4.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Tagged} = $ISM_prefix . '.5.' . $self->{mvr};
		$self->{OID_ISM_VLAN_State} = $ISM_prefix . '.6.' . $self->{mvr};
		$self->{OID_ISM_VLAN_ReplaceSrcIP} = $ISM_prefix . '.7.' . $self->{mvr};
		$self->{OID_ISM_VLAN_RowStatus} = $ISM_prefix . '.8.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Remap} = $ISM_prefix . '.10.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Replace} = $ISM_prefix . '.11.' . $self->{mvr};
		$self->{str_ISM_VLAN_State} = ([0, $enabled, $disabled]);
		$self->{str_ISM_VLAN_Replace} = ([0, $enabled, $disabled]);
		# IGMP
		my $IGMP_prefix = $dlink_common . '.73.3.1';
		$self->{OID_IGMP_Querier_Version} = $IGMP_prefix . '.1.1.60.' . $self->{mvr};
		$self->{OID_IGMP_DataDriven_AgedOut} = $IGMP_prefix . '.1.1.70.' . $self->{mvr};
		$self->{OID_IGMP_FastLeave} = $IGMP_prefix . '.1.1.50.' . $self->{mvr};
		$self->{OID_IGMP_AA_PortState} = $prefix . '.2.7.7.1.2';
		$self->{OID_IGMP_Snooping} = $dlink_common . '.73.1.1.0';
		$self->{OID_IGMP_Info} = $dlink_common . '.73.2.1.2.1.4';
		$self->{str_IGMP_AA_PortState} = ([0, $disabled, $enabled]);
		$self->{str_IGMP_Snooping} = ([0, $disabled, $enabled]);
		$self->{str_IGMP_DataDriven_AgedOut} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_FastLeave} = ([0, $enabled, $disabled]);
		$self->{OID_IGMP_McastVLANgroupStart} = $prefix . '.2.7.9.1.2';
		$self->{OID_IGMP_McastVLANgroupEnd} = $prefix . '.2.7.9.1.3';
		$self->{OID_IGMP_McastVLANgroup_RowStatus} = $prefix . '.2.7.9.1.4.' . $self->{mvr};
		$self->{IGMPInfoIndex} = 'src0grp';
		# DHCP Relay
		$self->{OID_DHCPLocalRelay_State} = $prefix . '.2.24.1.0';
		$self->{OID_DHCPRelay_State} = $dlink_common . '.42.1.1.0';
		$self->{str_DHCPLocalRelay_State} = ([0, $other, $disabled, $enabled]);
		$self->{str_DHCPRelay_State} = ([0, $enabled, $disabled]);
		# Syslog
		$self->{OID_Syslog_HostIP} = $dlink_common . '.12.2.1.2';
		$self->{OID_Syslog_Facility} = $dlink_common . '.12.2.1.3';
		$self->{OID_Syslog_Severity} = $dlink_common . '.12.2.1.4';
		$self->{OID_Syslog_ServerState} = $dlink_common . '.12.2.1.6';
		$self->{OID_Syslog_RowStatus} = $dlink_common . '.12.2.1.7';
		$self->{OID_Syslog_State} = $dlink_common . '12.1.0';
		$self->{str_Syslog_Facility} = ([$local0, $local1, $local2, $local3, $local4, $local5, $local6, $local7]);
		$self->{str_Syslog_Severity} = ([0, $all, $warn, $info]);
		$self->{str_Syslog_ServerState} = ([0, $other, $disabled, $enabled]);
		$self->{str_Syslog_State} = ([0, $other, $disabled, $enabled]);
		# RADIUS
		$self->{OID_RADIUS_Index} = $dlink_common . '.3.2.4.1.1';
		$self->{OID_RADIUS_IP} = $dlink_common . '.3.2.4.1.2';
		$self->{OID_RADIUS_AuthPort} = $dlink_common . '.3.2.4.1.4';
		$self->{OID_RADIUS_AcctPort} = $dlink_common . '.3.2.4.1.5';
		$self->{OID_RADIUS_Timeout} = $dlink_common . '.3.2.2.0';
		$self->{OID_RADIUS_Retransmit} = $dlink_common . '.3.2.3.0';
		# IMPB
		$self->{OID_IMPB_DHCPSnooping} = $dlink_common . '.23.1.4.0';
		$self->{OID_IMPB_PortState} = $dlink_common . '.23.3.2.1.2';
		$self->{OID_IMPB_ZeroIP} = $dlink_common . '.23.3.2.1.3';
		$self->{OID_IMPB_ForwardDHCPPkt} = $dlink_common . '.23.3.2.1.4';
		$self->{OID_IMPB_Port} = $dlink_common . '.23.4.1.1.4';
		$self->{OID_IMPB_MAC} = $dlink_common . '.23.4.1.1.2';
		$self->{OID_IMPB_IP} = $dlink_common . '.23.4.1.1.1';
		$self->{OID_IMPB_RowStatus} = $dlink_common . '.23.4.1.1.3';
		$self->{OID_IMPB_BlockVID} = $dlink_common . '.23.4.2.1.1';
		$self->{OID_IMPB_BlockMac} = $dlink_common . '.23.4.2.1.2';
		$self->{OID_IMPB_BlockPort} = $dlink_common . '.23.4.2.1.4';
		$self->{str_IMPB_DHCPSnooping} = ([0, $enabled, $disabled]);
		$self->{str_IMPB_PortState} = ([0, $other, $strict, $disabled, $loose]);
		$self->{str_IMPB_ZeroIP} = ([0, $enabled, $disabled]);
		$self->{str_IMPB_ForwardDHCPPkt} = ([0, $enabled, $disabled]);
		# TrafCtrl
		$self->{OID_TrafCtrl_BroadcastStatus} = $dlink_common . '.25.3.1.1.3';
		$self->{OID_TrafCtrl_MulticastStatus} = $dlink_common . '.25.3.1.1.4';
		$self->{OID_TrafCtrl_UnicastStatus} = $dlink_common . '.25.3.1.1.5';
		$self->{OID_TrafCtrl_ActionStatus} = $dlink_common . '.25.3.1.1.6';
		$self->{OID_TrafCtrl_Countdown} = $dlink_common . '.25.3.1.1.7';
		$self->{OID_TrafCtrl_Interval} = $dlink_common . '.25.3.1.1.8';
		$self->{OID_TrafCtrl_BroadcastThreshold} = $dlink_common . '.25.3.1.1.2';
		$self->{OID_TrafCtrl_MulticastThreshold} = $dlink_common . '.25.3.1.1.2';
		$self->{OID_TrafCtrl_UnicastThreshold} = $dlink_common . '.25.3.1.1.2';
		$self->{str_TrafCtrl_BroadcastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_MulticastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_UnicastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_ActionStatus} = ([0, $shutdown, $drop]);
		# TrafSegmentation
		$self->{OID_TrafficSegForwardPorts} = $prefix . '.2.12.1.1.2';
		# SNTP
		$self->{OID_SNTP_State} = $dlink_common . '.10.11.1.0';
		$self->{OID_SNTP_PrimaryIP} = $dlink_common . '.10.11.3.0';
		$self->{OID_SNTP_SecondaryIP} = $dlink_common . '.10.11.4.0';
		$self->{OID_SNTP_PollInterval} = $dlink_common . '.10.11.5.0';
		$self->{str_SNTP_State} = ([0, $other, $disabled, $enabled]);
		# DHCP/Netbios filter
		$self->{OID_Filter_DHCP_PortState} = $dlink_common . '.37.1.2.1.2';
		$self->{str_Filter_DHCP_PortState} = ([0, $enabled, $disabled]);
		$self->{FilterNetbiosTroughPCF} = 1;
		# LBD
		$self->{OID_LBD_State} = $prefix . '.2.21.1.1.0';
		$self->{OID_LBD_PortState} = $prefix . '.2.21.2.1.1.2';
		$self->{OID_LBD_PortLoopStatus} = $prefix . '.2.21.2.1.1.4';
		$self->{str_LBD_State} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortState} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortLoopStatus} = ([0, $normal, $loop, $error, $none]);
		# Mcast filtering
		$self->{McastFilterAddrInterval} = 1;
		$self->{OID_McastRange_ID} = $prefix . '.2.22.2.1.1';
		$self->{OID_McastRange_Name} = $prefix . '.2.22.2.1.2';
		$self->{OID_McastRange_Action} = $prefix . '.2.22.2.1.3';
		$self->{OID_McastRange_RowStatus} = $prefix . '.2.22.2.1.5';
		$self->{OID_McastRange_Addr} = $prefix . '.2.22.2.1.4';
		$self->{OID_Mcast_setPortProfileAction} = $prefix . '.2.22.3.1.2';
		$self->{OID_Mcast_setPortProfileID} = $prefix . '.2.22.3.1.3';
		$self->{OID_Mcast_setPortAccess} = $prefix . '.2.22.3.1.4';
		$self->{OID_Mcast_PortAccess} = $prefix . '.2.22.5.1.3';
		$self->{OID_Mcast_PortRangeID} = $prefix . '.2.22.5.1.2';
		$self->{str_Mcast_PortAccess} = ([0, $permit, $deny]);
		# Other
		$self->{OID_WebState} = $prefix . '.2.1.2.30.1.0';
		$self->{str_WebState} = ([0, $other, $disabled, $enabled]);
		my $OID = $prefix . '.2.1.2.5.0';
		$result = $snmp->get_request(-varbindlist => [$OID]);
		$self->{mgmtVLAN} = $result->{$OID};
		# ACL
		$self->{OID_EtherACL_Profile} = $dlink_common . '.9.2.1.1.1';
		$self->{OID_EtherACL_UseEtype} = $dlink_common . '.9.2.1.1.7';
		$self->{OID_EtherACL_UseMAC} = $dlink_common . '.9.2.1.1.3';
		$self->{OID_EtherACL_Profile_SrcMACMask} = $dlink_common . '.9.2.1.1.4';
		$self->{OID_EtherACL_Profile_RowStatus} = $dlink_common . '.9.2.1.1.8';
		$self->{OID_EtherACL_ProfileName} = $dlink_common . '.9.2.1.1.11';
		$self->{OID_EtherACL_RuleID} = $dlink_common . '.9.3.1.1.2';
		$self->{OID_EtherACL_Etype} = $dlink_common . '.9.3.1.1.7';
		$self->{OID_EtherACL_Permit} = $dlink_common . '.9.3.1.1.13';
		$self->{OID_EtherACL_SrcMAC} = $dlink_common . '.9.3.1.1.4';
		$self->{OID_EtherACL_SrcMACMask} = $dlink_common . '.9.3.1.1.23';
		$self->{OID_EtherACL_Port} = $dlink_common . '.9.3.1.1.14';
		$self->{OID_EtherACL_Rule_RowStatus} = $dlink_common . '.9.3.1.1.15';
		$self->{str_EtherACL_UseEtype} = ([0, $enabled, $disabled]);
		$self->{str_EtherACL_Permit} = ([0, $deny, $permit]);
		$self->{str_EtherACL_UseMAC} = ([0, $none, 'dst', 'src', 'srcdst']);
		$self->{OID_PCF_Profile} = $dlink_common . '.9.2.10.1.1.1';
		$self->{OID_PCF_Profile_RowStatus} = $dlink_common . '.9.2.10.1.1.9';
		$self->{OID_PCF_Offset_Bytes} = $dlink_common . '.9.2.10.2.1.4';
		$self->{OID_PCF_Offset_Mask} = $dlink_common . '.9.2.10.2.1.5';
		$self->{OID_PCF_Offset_RowStatus} = $dlink_common . '.9.2.10.2.1.6';
		$self->{OID_PCF_RuleID} = $dlink_common . '.9.3.10.1.1.2';
		$self->{OID_PCF_Port} = $dlink_common . '.9.3.10.1.1.13';
		$self->{OID_PCF_Permit} = $dlink_common . '.9.3.10.1.1.12';
		$self->{OID_PCF_Payload} = $dlink_common . '.9.3.10.2.1.4';
		$self->{OID_PCF_PayloadMask} = $dlink_common . '.9.3.10.2.1.6';
		$self->{OID_PCF_RuleOffset_RowStatus} = $dlink_common . '.9.3.10.2.1.5';
		$self->{OID_PCF_Rule_RowStatus} = $dlink_common . '.9.3.10.1.1.21';
		$self->{str_PCF_Permit} = ([0, $deny, $permit]);
		# Safeguard
		$self->{OID_SafeguardGlobalState} = $dlink_common . '.19.1.1.0';
		$self->{OID_SafeguardRisingThreshold} = $dlink_common . '.19.2.1.0';
		$self->{OID_SafeguardFallingThreshold} = $dlink_common . '.19.2.2.0';
		$self->{OID_SafeguardMode} = $dlink_common . '.19.2.3.0';
		$self->{OID_SafeguardTrap} = $dlink_common . '.19.2.4.0';
		$self->{OID_SafeguardStatus} = $dlink_common . '.19.2.5.0';
		$self->{str_SafeguardGlobalState} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardMode} = ([0, 'strict', 'fuzzy']);
		$self->{str_SafeguardTrap} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardStatus} = ([0, 'normal', 'exhausted']);
	} elsif ($model eq '63.6') {
	######################
	#
	# DES-3028
	#
	######################
		$self->{name} = 'DES-3028';
		# Ports
		$self->{OID_PortAdminNway} = $prefix . '.2.2.2.1.4';
		$self->{OID_PortAdminState} = $prefix . '.2.2.2.1.3';
		$self->{OID_PortErrDisabled} = 0;
		$self->{OID_PortOperNway} = $prefix . '.2.2.1.1.5';
		$self->{OID_PortOperState} = $prefix . '.2.2.1.1.4';
		$self->{str_PortAdminState} = ([0, $other, $disabled, $enabled]);
		$self->{str_PortAdminNway} = ([0, $nway_auto, $nway_10half, $nway_10full, $nway_100half, $nway_100full, $other, $nway_1G, '1000-full-master', '1000-full-slave']);
		$self->{str_PortErrDisabled} = ([0]);
		$self->{str_PortOperNway} = ([0, $link_fail, $nway_10half, $nway_10full, $nway_100half, $nway_100full, $other, $nway_1G]);
		$self->{str_PortOperState} = ([0, $other, $link_pass, $link_fail]);
		$self->{copper} = 100;
		$self->{fiber} = 101;
		$self->{max_ports} = 28;
		$self->{ErrDisabledCheckStatus} = 1;
		# ISM VLAN
		my $ISM_prefix = $prefix . '.2.7.8.1';
		$self->{OID_ISM_VLAN_Name} = $ISM_prefix . '.2.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Source} = $ISM_prefix . '.3.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Member} = $ISM_prefix . '.4.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Tagged} = $ISM_prefix . '.5.' . $self->{mvr};
		$self->{OID_ISM_VLAN_State} = $ISM_prefix . '.6.' . $self->{mvr};
		$self->{OID_ISM_VLAN_ReplaceSrcIP} = $ISM_prefix . '.7.' . $self->{mvr};
		$self->{OID_ISM_VLAN_RowStatus} = $ISM_prefix . '.8.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Remap} = $ISM_prefix . '.11.' . $self->{mvr};
		$self->{str_ISM_VLAN_State} = ([0, $enabled, $disabled]);
		# IGMP
		$self->{OID_IGMP_FastLeave} = $prefix . '.2.7.3.1.12.' . $self->{mvr};
		$self->{OID_IGMP_AA_PortState} = $prefix . '.2.7.7.1.2';
		$self->{OID_IGMP_Snooping} = $prefix . '.2.1.2.7.0';
		$self->{OID_IGMP_Info} = $prefix . '.2.7.5.1.4';
		$self->{str_IGMP_AA_PortState} = ([0, $disabled, $enabled]);
		$self->{str_IGMP_Snooping} = ([0, $other, $disabled, $enabled]);
		$self->{str_IGMP_FastLeave} = ([0, $other, $disabled, $enabled]);
		$self->{OID_IGMP_McastVLANgroupStart} = $prefix . '.2.7.9.1.2';
		$self->{OID_IGMP_McastVLANgroupEnd} = $prefix . '.2.7.9.1.3';
		$self->{OID_IGMP_McastVLANgroup_RowStatus} = $prefix . '.2.7.9.1.4.' . $self->{mvr};
		$self->{IGMPInfoIndex} = 'grponly';
		# DHCP Relay
		$self->{OID_DHCPLocalRelay_State} = $prefix . '.2.24.1.0';
		$self->{OID_DHCPRelay_State} = $dlink_common . '.42.1.1.0';
		$self->{str_DHCPLocalRelay_State} = ([0, $other, $disabled, $enabled]);
		$self->{str_DHCPRelay_State} = ([0, $enabled, $disabled]);
		# Syslog
		$self->{OID_Syslog_HostIP} = $dlink_common . '.12.2.1.2';
		$self->{OID_Syslog_Facility} = $dlink_common . '.12.2.1.3';
		$self->{OID_Syslog_Severity} = $dlink_common . '.12.2.1.4';
		$self->{OID_Syslog_ServerState} = $dlink_common . '.12.2.1.6';
		$self->{OID_Syslog_RowStatus} = $dlink_common . '.12.2.1.7';
		$self->{OID_Syslog_State} = $dlink_common . '12.1.0';
		$self->{str_Syslog_Facility} = ([$local0, $local1, $local2, $local3, $local4, $local5, $local6, $local7]);
		$self->{str_Syslog_Severity} = ([0, $all, $warn, $info]);
		$self->{str_Syslog_ServerState} = ([0, $other, $disabled, $enabled]);
		$self->{str_Syslog_State} = ([0, $other, $disabled, $enabled]);
		# RADIUS
		$self->{OID_RADIUS_Index} = $dlink_common . '.3.2.4.1.1';
		$self->{OID_RADIUS_IP} = $dlink_common . '.3.2.4.1.2';
		$self->{OID_RADIUS_AuthPort} = $dlink_common . '.3.2.4.1.4';
		$self->{OID_RADIUS_AcctPort} = $dlink_common . '.3.2.4.1.5';
		$self->{OID_RADIUS_Timeout} = $dlink_common . '.3.2.2.0';
		$self->{OID_RADIUS_Retransmit} = $dlink_common . '.3.2.3.0';
		# IMPB
		$self->{OID_IMPB_DHCPSnooping} = $dlink_common . '.23.1.4.0';
		$self->{OID_IMPB_PortState} = $dlink_common . '.23.3.2.1.2';
		$self->{OID_IMPB_ZeroIP} = $dlink_common . '.23.3.2.1.3';
		$self->{OID_IMPB_ForwardDHCPPkt} = $dlink_common . '.23.3.2.1.4';
		$self->{OID_IMPB_Port} = $dlink_common . '.23.4.1.1.4';
		$self->{OID_IMPB_MAC} = $dlink_common . '.23.4.1.1.2';
		$self->{OID_IMPB_IP} = $dlink_common . '.23.4.1.1.1';
		$self->{OID_IMPB_RowStatus} = $dlink_common . '.23.4.1.1.3';
		$self->{OID_IMPB_BlockVID} = $dlink_common . '.23.4.2.1.1';
		$self->{OID_IMPB_BlockMac} = $dlink_common . '.23.4.2.1.2';
		$self->{OID_IMPB_BlockPort} = $dlink_common . '.23.4.2.1.4';
		$self->{str_IMPB_DHCPSnooping} = ([0, $enabled, $disabled]);
		$self->{str_IMPB_PortState} = ([0, $other, $strict, $disabled, $loose]);
		$self->{str_IMPB_ZeroIP} = ([0, $enabled, $disabled]);
		$self->{str_IMPB_ForwardDHCPPkt} = ([0, $enabled, $disabled]);
		# TrafCtrl
		$self->{OID_TrafCtrl_BroadcastStatus} = $dlink_common . '.25.3.1.1.3';
		$self->{OID_TrafCtrl_MulticastStatus} = $dlink_common . '.25.3.1.1.4';
		$self->{OID_TrafCtrl_UnicastStatus} = $dlink_common . '.25.3.1.1.5';
		$self->{OID_TrafCtrl_ActionStatus} = $dlink_common . '.25.3.1.1.6';
		$self->{OID_TrafCtrl_Countdown} = $dlink_common . '.25.3.1.1.7';
		$self->{OID_TrafCtrl_Interval} = $dlink_common . '.25.3.1.1.8';
		$self->{OID_TrafCtrl_BroadcastThreshold} = $dlink_common . '.25.3.1.1.2';
		$self->{OID_TrafCtrl_MulticastThreshold} = $dlink_common . '.25.3.1.1.2';
		$self->{OID_TrafCtrl_UnicastThreshold} = $dlink_common . '.25.3.1.1.2';
		$self->{str_TrafCtrl_BroadcastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_MulticastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_UnicastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_ActionStatus} = ([0, $shutdown, $drop]);
		# TrafSegmentation
		$self->{OID_TrafficSegForwardPorts} = $prefix . '.2.12.1.1.2';
		# SNTP
		$self->{OID_SNTP_State} = $dlink_common . '.10.11.1.0';
		$self->{OID_SNTP_PrimaryIP} = $dlink_common . '.10.11.3.0';
		$self->{OID_SNTP_SecondaryIP} = $dlink_common . '.10.11.4.0';
		$self->{OID_SNTP_PollInterval} = $dlink_common . '.10.11.5.0';
		$self->{str_SNTP_State} = ([0, $other, $disabled, $enabled]);
		# DHCP/Netbios filter
		$self->{FilterNetbiosTroughPCF} = 1;
		# LBD
		$self->{OID_LBD_State} = $prefix . '.2.21.1.1.0';
		$self->{OID_LBD_PortState} = $prefix . '.2.21.2.1.1.2';
		$self->{OID_LBD_PortLoopStatus} = $prefix . '.2.21.2.1.1.4';
		$self->{str_LBD_State} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortState} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortLoopStatus} = ([0, $normal, $loop, $error]);
		# Mcast filtering
		$self->{McastFilterAddrInterval} = 1;
		$self->{OID_McastRange_ID} = $prefix . '.2.22.2.1.1';
		$self->{OID_McastRange_Name} = $prefix . '.2.22.2.1.2';
		$self->{OID_McastRange_Action} = $prefix . '.2.22.2.1.3';
		$self->{OID_McastRange_RowStatus} = $prefix . '.2.22.2.1.5';
		$self->{OID_McastRange_Addr} = $prefix . '.2.22.2.1.4';
		$self->{OID_Mcast_setPortProfileAction} = $prefix . '.2.22.3.1.2';
		$self->{OID_Mcast_setPortProfileID} = $prefix . '.2.22.3.1.3';
		$self->{OID_Mcast_PortRangeID} = $prefix . '.2.22.5.1.2';
		# Other
		my $OID = $prefix . '.2.1.2.5.0';
		$result = $snmp->get_request(-varbindlist => [$OID]);
		$self->{mgmtVLAN} = $result->{$OID};
		$self->{snmp_key} = '0x16f43ac04d543ea68a7696b099b66526';
		# ACL
		$self->{OID_EtherACL_Profile} = $dlink_common . '.9.2.1.1.1';
		$self->{OID_EtherACL_UseEtype} = $dlink_common . '.9.2.1.1.7';
		$self->{OID_EtherACL_UseMAC} = $dlink_common . '.9.2.1.1.3';
		$self->{OID_EtherACL_Profile_SrcMACMask} = $dlink_common . '.9.2.1.1.4';
		$self->{OID_EtherACL_Profile_RowStatus} = $dlink_common . '.9.2.1.1.8';
		$self->{OID_EtherACL_ProfileName} = $dlink_common . '.9.2.1.1.11';
		$self->{OID_EtherACL_RuleID} = $dlink_common . '.9.3.1.1.2';
		$self->{OID_EtherACL_Etype} = $dlink_common . '.9.3.1.1.7';
		$self->{OID_EtherACL_Permit} = $dlink_common . '.9.3.1.1.13';
		$self->{OID_EtherACL_SrcMAC} = $dlink_common . '.9.3.1.1.4';
		$self->{OID_EtherACL_Port} = $dlink_common . '.9.3.1.1.14';
		$self->{OID_EtherACL_Rule_RowStatus} = $dlink_common . '.9.3.1.1.15';
		$self->{str_EtherACL_UseEtype} = ([0, $enabled, $disabled]);
		$self->{str_EtherACL_Permit} = ([0, $deny, $permit]);
		$self->{str_EtherACL_UseMAC} = ([0, $none, 'dst', 'src', 'srcdst']);
		$self->{OID_PCF_Profile} = $dlink_common . '.9.2.3.1.1';
		$self->{OID_PCF_Profile_RowStatus} = $dlink_common . '.9.2.3.1.7';
		$self->{OID_PCF_ProfileOffset} = $dlink_common . '.9.2.3.1.4';
		$self->{OID_PCF_RuleID} = $dlink_common . '.9.3.9.1.2';
		$self->{OID_PCF_Port} = $dlink_common . '.9.3.9.1.30';
		$self->{OID_PCF_Permit} = $dlink_common . '.9.3.9.1.29';
		$self->{OID_PCF_Offset1} = $dlink_common . '.9.3.9.1.8';
		$self->{OID_PCF_Offset1Mask} = $dlink_common . '.9.3.9.1.9';
		$self->{OID_PCF_Payload} = $dlink_common . '.9.3.9.1.10';
		$self->{OID_PCF_Rule_RowStatus} = $dlink_common . '.9.3.9.1.33';
		$self->{str_PCF_Permit} = ([0, $deny, $permit]);
		$self->{PCF_Netbios_Mask} = '0'x16 . 'F'x4 . '0'x12;
		# Safeguard
		$self->{OID_SafeguardGlobalState} = $dlink_common . '.19.1.1.0';
		$self->{OID_SafeguardRisingThreshold} = $dlink_common . '.19.2.1.0';
		$self->{OID_SafeguardFallingThreshold} = $dlink_common . '.19.2.2.0';
		$self->{OID_SafeguardMode} = $dlink_common . '.19.2.3.0';
		$self->{OID_SafeguardTrap} = $dlink_common . '.19.2.4.0';
		$self->{OID_SafeguardStatus} = $dlink_common . '.19.2.5.0';
		$self->{str_SafeguardGlobalState} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardMode} = ([0, 'strict', 'fuzzy']);
		$self->{str_SafeguardTrap} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardStatus} = ([0, 'normal', 'exhausted']);
	} elsif ($model eq '94.5') {
	#####################
	#
	#	DGS-3100-24TG
	#
	#####################
		$self->{name} = 'DGS-3100-24TG';
		$prefix = '1.3.6.1.4.1.171.10.94.89.89';
		$self->{stackable} = 1;
		$self->{unit_ports} = 24;
		$self->{unit_bitmask} = 48;
		$self->{unit_portcount} = 50;
		# Ports - custom functions
		$self->{OID_PortAdminDuplex} = $prefix . '.43.1.1.3';
		$self->{OID_PortOperDuplex} = $prefix . '.43.1.1.4';
		$self->{OID_PortAdminSpeed} = $prefix . '.43.1.1.15';
		$self->{OID_PortAutoNegotiate} = $prefix . '.43.1.1.16';
		$self->{OID_PortOperSpeed} = '1.3.6.1.2.1.2.2.1.5';
		$self->{OID_PortAdminState} = '1.3.6.1.2.1.2.2.1.7';
		$self->{OID_PortOperState} = '1.3.6.1.2.1.2.2.1.8';
		$self->{custom_port_functions} = 1;
		#
		# ISM VLAN - not supported
		#
		# IGMP
		$self->{OID_IGMP_Querier_Version} = $prefix . '.55.2.7.1.8.' . $self->{mvr};
		$self->{OID_IGMP_Snooping} = $prefix . '.55.2.2.0';
		$self->{OID_IGMP_Info} = $prefix . '.55.2.11.1.4';
		$self->{str_IGMP_Snooping} = ([0, $enabled, $disabled]);
		$self->{IGMPInfoIndex} = 'grpsrc0';
		# DHCP Relay - not used
		#
		# Syslog
		$self->{OID_Syslog_State} = $prefix . '.82.2.1.0';
		$self->{OID_Syslog_HostIP} = $prefix . '.82.1.2.4.1.4';
		$self->{OID_Syslog_Facility} = $prefix . '.82.1.2.4.1.6';
		$self->{OID_Syslog_Severity} = $prefix . '.82.1.2.4.1.7';
		$self->{str_Syslog_State} = ([0, $enabled, $disabled]);
		$self->{str_Syslog_Facility} = ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
										$local0, $local1, $local2, $local3, $local4, $local5, $local6, $local7]);
		$self->{str_Syslog_Severity} = ([$emergency, $alert, $critical, $error, $warn, $notice, $info, $debug]);
		# RADIUS - not used
		#
		# IMPB - not used
		#
		# TrafCtl - not used
		#
		# TrafSegmentation - custom functions
		#
		# SNTP
		$self->{OID_SNTP_PrimaryIP} = $prefix . '.92.2.1.16.1.3.1';
		$self->{OID_SNTP_SecondaryIP} = $prefix . '.92.2.1.16.1.3.2';
		$self->{OID_SNTP_PollInterval} = $prefix . '.92.2.1.4';
		$self->{OID_SNTP_State} = $prefix . '.92.1.5.0';
		$self->{str_SNTP_State} = ([0, $disabled, $enabled, $enabled]);
		# Other
		$self->{mgmtVLAN} = 1; 		# Fix later!!!
		$self->{OID_CPU5sec} = '1.3.6.1.4.1.171.10.94.89.89.1.7.0';
		$self->{OID_CPU1min} = '1.3.6.1.4.1.171.10.94.89.89.1.8.0';
		$self->{OID_CPU5min} = '1.3.6.1.4.1.171.10.94.89.89.1.9.0';
	} elsif ($model eq '117.1.3') {
	#####################
	#
	#	DGS-3120-24SC
	#
	#####################
		$self->{name} = 'DGS-3120-24SC/A1';
		# Ports
		$self->{OID_PortAdminNway} = $prefix . '.2.3.2.1.5';
		$self->{OID_PortAdminState} = $prefix . '.2.3.2.1.4';
		$self->{OID_PortErrDisabled} = $prefix . '.2.3.1.1.8';
		$self->{OID_PortOperNway} = $prefix . '.2.3.1.1.6';
		$self->{OID_PortOperState} = $prefix . '.2.3.1.1.5';
		$self->{str_PortAdminState} = ([0, $other, $disabled, $enabled]);
		$self->{str_PortAdminNway} = ([0, $other, $nway_auto, $nway_10half, $nway_10full, $nway_100half, $nway_100full, '1000-half', $nway_1G, '1000-full-master', '1000-full-slave']);
		$self->{str_PortErrDisabled} = ([$none, $storm, $lbd, $lbd, $ddm, 'bpdu', $unknown, 'power-saving']);
		$self->{str_PortOperNway} = ([$link_fail, '10-full-8023x', $nway_10full, '10-half-backup', $nway_10half, '100-full-8023x', $nway_100full, '100-half-backup', $nway_100half, '1000-full-8023x', $nway_1G, '1000-half-backup', '1000-half', '10000-full-8023x', $nway_10G, '10000-half-8023x', '10000-half', $empty]);
		$self->{str_PortOperState} = ([0, $other, $link_pass, $link_fail]);
		$self->{copper} = 1;
		$self->{fiber} = 2;
		$self->{default_medium} = 'fiber';
		$self->{ErrDisabledCheckStatus} = 0;
		$self->{max_ports} = 24;
		# ISM VLAN
		my $ISM_prefix = $dlink_common . '.64.3.1.1';
		$self->{OID_ISM_VLAN_Name} = $ISM_prefix . '.2.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Source} = $ISM_prefix . '.3.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Member} = $ISM_prefix . '.4.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Tagged} = $ISM_prefix . '.5.' . $self->{mvr};
		$self->{OID_ISM_VLAN_ReplaceSrcIP} = $ISM_prefix . '.9.' . $self->{mvr};
		$self->{OID_ISM_VLAN_Remap} = $ISM_prefix . '.10.' . $self->{mvr};
		# IGMP
		my $IGMP_prefix = $dlink_common . '.73.3.1';
		$self->{OID_IGMP_Querier_Version} = $IGMP_prefix . '.1.1.60.' . $self->{mvr};
		$self->{OID_IGMP_DataDriven} = $IGMP_prefix . '.1.1.65.' . $self->{mvr};
		$self->{OID_IGMP_DataDriven_AgedOut} = $IGMP_prefix . '.1.1.70.' . $self->{mvr};
		$self->{OID_IGMP_FastLeave} = $IGMP_prefix . '.1.1.50.' . $self->{mvr};
		$self->{OID_IGMP_ReportSuppression} = $IGMP_prefix . '.1.1.55.' . $self->{mvr};
		$self->{OID_IGMP_AA_PortState} = $prefix . '.2.11.13.1.2';
		$self->{OID_IGMP_Snooping} = $dlink_common . '.73.1.1.0';
		$self->{OID_IGMP_Info} = $dlink_common . '.73.2.1.2.1.4';
		$self->{str_IGMP_AA_PortState} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_Snooping} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_DataDriven} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_DataDriven_AgedOut} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_FastLeave} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_ReportSuppression} = ([0, $enabled, $disabled]);
		$self->{OID_IGMP_McastVLANgroupStart} = $dlink_common . '.64.3.3.1.2';
		$self->{OID_IGMP_McastVLANgroupEnd} = $dlink_common . '.64.3.3.1.3';
		$self->{IGMPInfoIndex} = 'src255grp';
		# DHCP Relay
		$self->{OID_DHCPLocalRelay_State} = $prefix . '.2.24.1.0';
		$self->{OID_DHCPRelay_State} = $dlink_common . '.42.1.1.0';
		$self->{str_DHCPLocalRelay_State} = ([0, $other, $disabled, $enabled]);
		$self->{str_DHCPRelay_State} = ([0, $enabled, $disabled]);
		# Syslog
		$self->{OID_Syslog_HostIP} = $dlink_common . '.12.2.1.9';
		$self->{OID_Syslog_AddrType} = $dlink_common . '.12.2.1.8';
		$self->{OID_Syslog_Facility} = $dlink_common . '.12.2.1.3';
		$self->{OID_Syslog_Severity} = $dlink_common . '.12.2.1.4';
		$self->{OID_Syslog_ServerState} = $dlink_common . '.12.2.1.6';
		$self->{OID_Syslog_RowStatus} = $dlink_common . '.12.2.1.7';
		$self->{OID_Syslog_State} = $dlink_common . '12.1.0';
		$self->{str_Syslog_Facility} = ([$local0, $local1, $local2, $local3, $local4, $local5, $local6, $local7]);
		$self->{str_Syslog_Severity} = ([0, $all, $warn, $info, $emergency, $alert, $critical, $error, $notice, $debug]);
		$self->{str_Syslog_ServerState} = ([0, $other, $disabled, $enabled]);
		$self->{str_Syslog_State} = ([0, $other, $disabled, $enabled]);
		# RADIUS
		$self->{OID_RADIUS_Index} = $dlink_common . '.3.2.4.1.1';
		$self->{OID_RADIUS_IP} = $dlink_common . '.3.2.4.1.10';
		$self->{OID_RADIUS_AuthPort} = $dlink_common . '.3.2.4.1.4';
		$self->{OID_RADIUS_AcctPort} = $dlink_common . '.3.2.4.1.5';
		$self->{OID_RADIUS_Timeout} = $dlink_common . '.3.2.2.0';
		$self->{OID_RADIUS_Retransmit} = $dlink_common . '.3.2.3.0';
		# IMPB
		$self->{OID_IMPB_DHCPSnooping} = $dlink_common . '.23.1.4.0';
		$self->{OID_IMPB_PortState} = $dlink_common . '.23.3.2.1.16';
		$self->{OID_IMPB_ZeroIP} = $dlink_common . '.23.3.2.1.3';
		$self->{OID_IMPB_ForwardDHCPPkt} = $dlink_common . '.23.3.2.1.4';
		$self->{OID_IMPB_Port} = $dlink_common . '.23.4.1.1.4';
		$self->{OID_IMPB_MAC} = $dlink_common . '.23.4.1.1.2';
		$self->{OID_IMPB_IP} = $dlink_common . '.23.4.1.1.1';
		$self->{OID_IMPB_RowStatus} = $dlink_common . '.23.4.1.1.3';
		$self->{OID_IMPB_BlockVID} = $dlink_common . '.23.4.2.1.1';
		$self->{OID_IMPB_BlockMac} = $dlink_common . '.23.4.2.1.2';
		$self->{OID_IMPB_BlockPort} = $dlink_common . '.23.4.2.1.4';
		$self->{str_IMPB_DHCPSnooping} = ([0, $enabled, $disabled]);
		$self->{str_IMPB_PortState} = ([0, $disabled, $strict, $loose]);
		$self->{str_IMPB_ZeroIP} = ([0, $enabled, $disabled]);
		$self->{str_IMPB_ForwardDHCPPkt} = ([0, $enabled, $disabled]);
		# TrafCtrl
		$self->{OID_TrafCtrl_BroadcastStatus} = $dlink_common . '.25.3.1.1.3';
		$self->{OID_TrafCtrl_MulticastStatus} = $dlink_common . '.25.3.1.1.4';
		$self->{OID_TrafCtrl_UnicastStatus} = $dlink_common . '.25.3.1.1.5';
		$self->{OID_TrafCtrl_ActionStatus} = $dlink_common . '.25.3.1.1.6';
		$self->{OID_TrafCtrl_Countdown} = $dlink_common . '.25.3.1.1.7';
		$self->{OID_TrafCtrl_Interval} = $dlink_common . '.25.3.1.1.8';
		$self->{OID_TrafCtrl_BroadcastThreshold} = $dlink_common . '.25.3.1.1.10';
		$self->{OID_TrafCtrl_MulticastThreshold} = $dlink_common . '.25.3.1.1.11';
		$self->{OID_TrafCtrl_UnicastThreshold} = $dlink_common . '.25.3.1.1.12';
		$self->{str_TrafCtrl_BroadcastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_MulticastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_UnicastStatus} = ([0, $disabled, $enabled]);
		$self->{str_TrafCtrl_ActionStatus} = ([0, $shutdown, $drop]);
		# TrafSegmentation
		$self->{OID_TrafficSegForwardPorts} = $prefix . '.2.14.1.1.2';
		# SNTP
		$self->{OID_SNTP_State} = $dlink_common . '.10.11.1.0';
		$self->{OID_SNTP_PrimaryIP} = $dlink_common . '.10.11.3.0';
		$self->{OID_SNTP_SecondaryIP} = $dlink_common . '.10.11.4.0';
		$self->{OID_SNTP_PollInterval} = $dlink_common . '.10.11.5.0';
		$self->{str_SNTP_State} = ([0, $other, $disabled, $enabled]);
		# DHCP/Netbios filter
		$self->{OID_Filter_DHCP_PortState} = $dlink_common . '.37.1.2.1.2';
		$self->{OID_Filter_Netbios_PortState} = $dlink_common . '.37.2.1.1.2';
		$self->{OID_Filter_ExtNetbios_PortState} = $dlink_common . '.37.3.1.1.2';
		$self->{str_Filter_DHCP_PortState} = ([0, $enabled, $disabled]);
		$self->{str_Filter_Netbios_PortState} = ([0, $enabled, $disabled]);
		$self->{str_Filter_ExtNetbios_PortState} = ([0, $enabled, $disabled]);
		$self->{FilterNetbiosTroughPCF} = 0;
		# LBD
		$self->{OID_LBD_State} = $dlink_common . '.41.1.1.0';
		$self->{OID_LBD_PortState} = $dlink_common . '.41.3.1.1.2';
		$self->{OID_LBD_PortLoopStatus} = $dlink_common . '.41.3.1.1.4';
		$self->{str_LBD_State} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortState} = ([0, $enabled, $disabled]);
		$self->{str_LBD_PortLoopStatus} = ([0, $normal, $loop, $error]);
		# Mcast filtering
		my $Mcast_prefix = $dlink_common . '.53';
		$self->{OID_McastRange_ID} = $Mcast_prefix . '.1.1.1';
		$self->{OID_McastRange_Name} = $Mcast_prefix . '.1.1.2';
		$self->{OID_McastRange_From} = $Mcast_prefix . '.2.1.2';
		$self->{OID_McastRange_To} = $Mcast_prefix . '.2.1.3';
		$self->{OID_Mcast_PortAccess} = $Mcast_prefix . '.4.1.2';
		$self->{OID_Mcast_PortRangeID} = $Mcast_prefix . '.3.1.2';
		$self->{str_Mcast_PortAccess} = ([0, $permit, $deny]);
		$self->{McastFilterSNMPTrailingAddr} = 1;
		# Other
		$self->{OID_WebState} = $prefix . '.2.1.2.17.1.0';
		$self->{OID_WebPort} = $prefix . '.2.1.2.17.2.0';
		$self->{OID_TelnetState} = $prefix . '.2.1.2.14.1.0';
		$self->{OID_TelnetPort} = $prefix . '.2.1.2.14.2.0';
		$self->{str_WebState} = ([0, $enabled, $disabled]);
		$self->{str_TelnetState} = ([0, $other, $disabled, $enabled]);
		my $OID = $prefix . '.2.1.2.16.0';
		$result = $snmp->get_request(-varbindlist => [$OID]);
		$self->{mgmtVLAN} = $result->{$OID};
		# ACL
		$self->{OID_EtherACL_Profile} = $dlink_common . '.9.2.1.1.1';
		$self->{OID_EtherACL_UseEtype} = $dlink_common . '.9.2.1.1.7';
		$self->{OID_EtherACL_UseMAC} = $dlink_common . '.9.2.1.1.3';
		$self->{OID_EtherACL_Profile_SrcMACMask} = $dlink_common . '.9.2.1.1.4';
		$self->{OID_EtherACL_Profile_RowStatus} = $dlink_common . '.9.2.1.1.8';
		$self->{OID_EtherACL_ProfileName} = $dlink_common . '.9.2.1.1.11';
		$self->{OID_EtherACL_RuleID} = $dlink_common . '.9.3.1.1.2';
		$self->{OID_EtherACL_Etype} = $dlink_common . '.9.3.1.1.7';
		$self->{OID_EtherACL_Permit} = $dlink_common . '.9.3.1.1.13';
		$self->{OID_EtherACL_SrcMAC} = $dlink_common . '.9.3.1.1.4';
		$self->{OID_EtherACL_SrcMACMask} = $dlink_common . '.9.3.1.1.23';
		$self->{OID_EtherACL_Port} = $dlink_common . '.9.3.1.1.14';
		$self->{OID_EtherACL_Rule_RowStatus} = $dlink_common . '.9.3.1.1.15';
		$self->{str_EtherACL_UseEtype} = ([0, $enabled, $disabled]);
		$self->{str_EtherACL_Permit} = ([0, $deny, $permit]);
		$self->{str_EtherACL_UseMAC} = ([0, $none, 'dst', 'src', 'srcdst']);
		# Safeguard
		$self->{OID_SafeguardGlobalState} = $dlink_common . '.19.1.1.0';
		$self->{OID_SafeguardRisingThreshold} = $dlink_common . '.19.2.1.0';
		$self->{OID_SafeguardFallingThreshold} = $dlink_common . '.19.2.2.0';
		$self->{OID_SafeguardMode} = $dlink_common . '.19.2.3.0';
		$self->{OID_SafeguardTrap} = $dlink_common . '.19.2.4.0';
		$self->{OID_SafeguardStatus} = $dlink_common . '.19.2.5.0';
		$self->{str_SafeguardGlobalState} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardMode} = ([0, 'strict', 'fuzzy']);
		$self->{str_SafeguardTrap} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardStatus} = ([0, 'normal', 'exhausted']);
	} elsif ($model eq '118.2') {
	#######################
	#
	#	DGS-3620-28SC
	#
	#######################
		$self->{name} = 'DGS-3620-28SC';
		$self->{type} = 'L3';
		$self->{stackable} = 1;
		$self->{unit_ports} = 28;
		$self->{unit_bitmask} = 64;
		$self->{unit_portcount} = 64;
		# Ports
		$self->{OID_PortAdminNway} = $prefix . '.2.3.2.1.5';
		$self->{OID_PortAdminState} = $prefix . '.2.3.2.1.4';
		$self->{OID_PortErrDisabled} = $prefix . '.2.3.1.1.8';
		$self->{OID_PortOperNway} = $prefix . '.2.3.1.1.6';
		$self->{OID_PortOperState} = $prefix . '.2.3.1.1.5';
		$self->{str_PortAdminState} = ([0, $other, $disabled, $enabled]);
		$self->{str_PortAdminNway} = ([0, $other, $nway_auto, $nway_10half, $nway_10full, $nway_100half, $nway_100full, '1000-half', $nway_1G, '1000-full-master', '1000-full-slave']);
		$self->{str_PortErrDisabled} = ([$none, $storm, $lbd, $lbd, $ddm, 'bpdu', $unknown, 'power-saving']);
		$self->{str_PortOperNway} = ([$link_fail, '10-full-8023x', $nway_10full, '10-half-backup', $nway_10half, '100-full-8023x', $nway_100full, '100-half-backup', $nway_100half, '1000-full-8023x', $nway_1G, '1000-half-backup', '1000-half', '10000-full-8023x', $nway_10G, '10000-half-8023x', '10000-half', $empty]);
		$self->{str_PortOperState} = ([0, $other, $link_pass, $link_fail]);
		$self->{copper} = 1;
		$self->{fiber} = 2;
		$self->{default_medium} = 'fiber';
		$self->{ErrDisabledCheckStatus} = 0;
		$self->{max_ports} = 28;
		# ISM VLAN - not used
		#
		# IGMP
		my $IGMP_prefix = $dlink_common . '.73.3.1';
		$self->{OID_IGMP_Querier_Version} = $IGMP_prefix . '.1.1.60.' . $self->{mvr};
		$self->{OID_IGMP_DataDriven} = $IGMP_prefix . '.1.1.65.' . $self->{mvr};
		$self->{OID_IGMP_DataDriven_AgedOut} = $IGMP_prefix . '.1.1.70.' . $self->{mvr};
		$self->{OID_IGMP_FastLeave} = $IGMP_prefix . '.1.1.50.' . $self->{mvr};
		$self->{OID_IGMP_ReportSuppression} = $IGMP_prefix . '.1.1.55.' . $self->{mvr};
		$self->{OID_IGMP_AA_PortState} = $prefix . '.2.11.13.1.2';
		$self->{OID_IGMP_Snooping} = $dlink_common . '.73.1.1.0';
		$self->{OID_IGMP_Info} = $dlink_common . '.73.2.1.2.1.4';
		$self->{str_IGMP_AA_PortState} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_Snooping} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_DataDriven} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_DataDriven_AgedOut} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_FastLeave} = ([0, $enabled, $disabled]);
		$self->{str_IGMP_ReportSuppression} = ([0, $enabled, $disabled]);
		$self->{OID_IGMP_McastVLANgroupStart} = $dlink_common . '.64.3.3.1.2';
		$self->{OID_IGMP_McastVLANgroupEnd} = $dlink_common . '.64.3.3.1.3';
		$self->{IGMPInfoIndex} = 'src255grp';
		# DHCP Relay
		$self->{OID_DHCPRelay_State} = $dlink_common . '.42.3.1.1.3';
		$self->{str_DHCPRelay_State} = ([0, $enabled]);
		# Syslog
		$self->{OID_Syslog_HostIP} = $dlink_common . '.12.2.1.9';
		$self->{OID_Syslog_AddrType} = $dlink_common . '.12.2.1.8';
		$self->{OID_Syslog_Facility} = $dlink_common . '.12.2.1.3';
		$self->{OID_Syslog_Severity} = $dlink_common . '.12.2.1.4';
		$self->{OID_Syslog_ServerState} = $dlink_common . '.12.2.1.6';
		$self->{OID_Syslog_RowStatus} = $dlink_common . '.12.2.1.7';
		$self->{OID_Syslog_State} = $dlink_common . '12.1.0';
		$self->{str_Syslog_Facility} = ([$local0, $local1, $local2, $local3, $local4, $local5, $local6, $local7]);
		$self->{str_Syslog_Severity} = ([0, $all, $warn, $info, $emergency, $alert, $critical, $error, $notice, $debug]);
		$self->{str_Syslog_ServerState} = ([0, $other, $disabled, $enabled]);
		$self->{str_Syslog_State} = ([0, $other, $disabled, $enabled]);
		# RADIUS - not used
		#
		# IMPB - not used
		#
		# TrafCtrl - not used
		#
		# TrafSegmentation - not used
		#
		# SNTP
		$self->{OID_SNTP_State} = $dlink_common . '.10.11.1.0';
		$self->{OID_SNTP_PrimaryIP} = $dlink_common . '.10.11.3.0';
		$self->{OID_SNTP_SecondaryIP} = $dlink_common . '.10.11.4.0';
		$self->{OID_SNTP_PollInterval} = $dlink_common . '.10.11.5.0';
		$self->{str_SNTP_State} = ([0, $other, $disabled, $enabled]);
		# DHCP/Netbios filter - not used
		#
		# LBD - not used
		#
		# Mcast filtering - not used
		#
		# IP interfaces
		$self->{OID_L3_Iface_Name} = $prefix . '.3.2.1.3.1.1';
		$self->{OID_L3_Iface_IP} = $prefix . '.3.2.1.3.1.3';
		$self->{OID_L3_Iface_Subnet} = $prefix .'.3.2.1.3.1.4';
		$self->{OID_L3_Iface_VLAN} = $prefix . '.3.2.1.3.1.5';
		$self->{OID_L3_Iface_State} = $prefix . '.3.2.1.3.1.9';
		$self->{str_L3_Iface_State} = ([0, $enabled, $disabled]);
		# Safeguard
		$self->{OID_SafeguardGlobalState} = $dlink_common . '.19.1.1.0';
		$self->{OID_SafeguardRisingThreshold} = $dlink_common . '.19.2.1.0';
		$self->{OID_SafeguardFallingThreshold} = $dlink_common . '.19.2.2.0';
		$self->{OID_SafeguardMode} = $dlink_common . '.19.2.3.0';
		$self->{OID_SafeguardTrap} = $dlink_common . '.19.2.4.0';
		$self->{OID_SafeguardStatus} = $dlink_common . '.19.2.5.0';
		$self->{str_SafeguardGlobalState} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardMode} = ([0, 'strict', 'fuzzy']);
		$self->{str_SafeguardTrap} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardStatus} = ([0, 'normal', 'exhausted']);
	} elsif ($model eq '70.8') {
	#######################
	#
	#	DGS-3627G
	#
	#######################
		$self->{name} = 'DGS-3627G';
		$self->{type} = 'L3';
		# Ports
		$self->{OID_PortAdminNway} = $prefix . '.2.3.2.1.5';
		$self->{OID_PortAdminState} = $prefix . '.2.3.2.1.4';
		$self->{OID_PortErrDisabled} = $prefix . '.2.3.1.1.8';
		$self->{OID_PortOperNway} = $prefix . '.2.3.1.1.6';
		$self->{OID_PortOperState} = $prefix . '.2.3.1.1.5';
		$self->{str_PortAdminState} = ([0, $other, $disabled, $enabled]);
		$self->{str_PortAdminNway} = ([0, $other, $nway_auto, $nway_10half, $nway_10full, $nway_100half, $nway_100full, '1000-half', $nway_1G, '1000-full-master', '1000-full-slave']);
		$self->{str_PortErrDisabled} = ([$none, $storm, $lbd, $lbd, $ddm, 'bpdu', $unknown, 'power-saving']);
		$self->{str_PortOperNway} = ([$link_fail, '10-full-8023x', $nway_10full, '10-half-backup', $nway_10half, '100-full-8023x', $nway_100full, '100-half-backup', $nway_100half, '1000-full-8023x', $nway_1G, '1000-half-backup', '1000-half', '10000-full-8023x', $nway_10G, '10000-half-8023x', '10000-half', $empty]);
		$self->{str_PortOperState} = ([0, $other, $link_pass, $link_fail]);
		$self->{copper} = 1;
		$self->{fiber} = 2;
		$self->{default_medium} = 'fiber';
		$self->{ErrDisabledCheckStatus} = 0;
		$self->{max_ports} = 27;
		# ISM VLAN - not used
		#
		# IGMP
		$self->{OID_IGMP_FastLeave} = $prefix . '.2.11.3.1.12.' . $self->{mvr};
		$self->{OID_IGMP_Snooping} = $prefix . '.2.1.2.2.0';
		$self->{OID_IGMP_Info} = $prefix . '.2.11.5.1.4';
		$self->{str_IGMP_Snooping} = ([0, $other, $disabled, $enabled]);
		$self->{str_IGMP_FastLeave} = ([0, $other, $disabled, $enabled]);
		$self->{OID_IGMP_McastVLANgroupStart} = $prefix . '.2.7.9.1.2';
		$self->{OID_IGMP_McastVLANgroupEnd} = $prefix . '.2.7.9.1.3';
		$self->{IGMPInfoIndex} = 'grponly';
		# DHCP Relay
		$self->{OID_DHCPRelay_State} = $prefix . '.3.3.1.4.1.3';
		$self->{str_DHCPRelay_State} = ([0, $disabled, $disabled, $enabled]);
		#
		# Syslog
		$self->{OID_Syslog_HostIP} = $dlink_common . '.12.2.1.2';
		$self->{OID_Syslog_Facility} = $dlink_common . '.12.2.1.3';
		$self->{OID_Syslog_Severity} = $dlink_common . '.12.2.1.4';
		$self->{OID_Syslog_ServerState} = $dlink_common . '.12.2.1.6';
		$self->{OID_Syslog_RowStatus} = $dlink_common . '.12.2.1.7';
		$self->{OID_Syslog_State} = $dlink_common . '12.1.0';
		$self->{str_Syslog_Facility} = ([$local0, $local1, $local2, $local3, $local4, $local5, $local6, $local7]);
		$self->{str_Syslog_Severity} = ([0, $all, $warn, $info]);
		$self->{str_Syslog_ServerState} = ([0, $other, $disabled, $enabled]);
		$self->{str_Syslog_State} = ([0, $other, $disabled, $enabled]);
		# RADIUS - not used
		#
		# IMPB - not used
		#
		# TrafCtrl - not used
		#
		# TrafSegmentation - not used
		#
		# SNTP
		$self->{OID_SNTP_State} = $dlink_common . '.10.11.1.0';
		$self->{OID_SNTP_PrimaryIP} = $dlink_common . '.10.11.3.0';
		$self->{OID_SNTP_SecondaryIP} = $dlink_common . '.10.11.4.0';
		$self->{OID_SNTP_PollInterval} = $dlink_common . '.10.11.5.0';
		$self->{str_SNTP_State} = ([0, $other, $disabled, $enabled]);
		# DHCP/Netbios filter - not used
		#
		# LBD - not used
		#
		# Mcast filtering - not used
		#
		# IP interfaces
		$self->{OID_L3_Iface_Name} = $prefix . '.3.2.1.3.1.1';
		$self->{OID_L3_Iface_IP} = $prefix . '.3.2.1.3.1.3';
		$self->{OID_L3_Iface_Subnet} = $prefix .'.3.2.1.3.1.4';
		$self->{OID_L3_Iface_VLAN} = $prefix . '.3.2.1.3.1.5';
		$self->{OID_L3_Iface_State} = $prefix . '.3.2.1.3.1.9';
		$self->{str_L3_Iface_State} = ([0, $enabled, $disabled]);
		# L3 FDB
		$self->{OID_L3_FDB_Port} = $prefix . '.3.2.2.1.1.3';
		# Other
		$self->{OID_VLAN_Name} = $prefix . '.2.17.1.1.2';
		# Safeguard
		$self->{OID_SafeguardGlobalState} = $dlink_common . '.19.1.1.0';
		$self->{OID_SafeguardRisingThreshold} = $dlink_common . '.19.2.1.0';
		$self->{OID_SafeguardFallingThreshold} = $dlink_common . '.19.2.2.0';
		$self->{OID_SafeguardMode} = $dlink_common . '.19.2.3.0';
		$self->{OID_SafeguardTrap} = $dlink_common . '.19.2.4.0';
		$self->{OID_SafeguardStatus} = $dlink_common . '.19.2.5.0';
		$self->{str_SafeguardGlobalState} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardMode} = ([0, 'strict', 'fuzzy']);
		$self->{str_SafeguardTrap} = ([0, $other, $disabled, $enabled]);
		$self->{str_SafeguardStatus} = ([0, 'normal', 'exhausted']);
	}
	
	my $snmp_key = $self->{snmp_key} ? $self->{snmp_key} : '0x91a90399be01f1866daec2977e89ee54';
	
	if (!$self->{mask_size}) {
		$self->{mask_size} = 16;
	}
	
	if ($self->{type} ne 'L3') {
		my ($set, $v3error) = Net::SNMP->session(
			-hostname => $host,
			-version => 3,
			-username => 'dlaccess',
			-authprotocol => 'md5',
			-authkey => $snmp_key,
			-privprotocol => 'des',
			-privkey => $snmp_key,
			-timeout => 4);
		$self->{snmpv3} = $set;
	}
	
	return $self;
}

#
#	Aux. subs
#

=head3 name

=begin html

Возвращает имя модели устройства.

<p class="code">print $dlink->name;<span class="code-comment"># DES-3526</span></p>

=end html

=begin man

=over 1

=item

C<< print $dlink->name; >> I<# DES-3526>

=back

=end man

=cut

sub name {
	my $self = shift;
	return $self->{name};
}

=head3 _snmpget

=begin html

Возвращает результат <span class="code">snmpget</span>-запроса по указанному OID. Если OID не существует,
возвращает <i>noSuchObject</i>.

<p class="code">
$var = $dlink->_snmpget('1.3.6.1.2.1.1.2');<br>
print $var; <span class="code-comment"># iso.3.6.1.4.1.171.10.64.1</span>
</p>
Одна из немногих внутренних функций, которые безопасно использовать напрямую.

=end html

=begin man

=over 1

=item

C<< $var = $dlink->_snmpget('1.3.6.1.2.1.1.2'); >>

C<< print $var; >> I<# iso.3.6.1.4.1.171.10.64.1>

=back

=end man

=cut

sub _snmpget {
	my $self = shift;
	my $OID = shift;
	
	if (!$OID) {
		return "noSuchObject";
	}
	
	my $result = $self->{snmp_session}->get_request(-varbindlist => [$OID]);
	return $result->{$OID};
}

sub _name_to_index {
	my $self = shift;
	my $name = shift;
	my $count;
	my $result;
	
	while ($name ne '') {
		$count++;
		my $symbol = substr $name, 0, 1;
		if ($result) {
			$result = $result . '.' . ord($symbol);
		} else {
			$result = ord($symbol);
		}
		$name = substr $name, 1, length($name) - 1;
	}
	
	return $count . '.' . $result;
}

=head3 _telnet_cmd

Выполняет команду в командной строке коммутатора и возвращает результат в виде
списка строк. Безопасна при использовании напрямую.

=cut

sub _telnet_cmd {
	my $self = shift;
	my $cmd = shift;
	
	if (!defined($self->{telnet})) {
		my $telnet = new Net::Telnet(-timeout => 30, -prompt => '/#/', -host => $self->{ip});
		$telnet->login($telnet_login, $telnet_pass);
		$self->{telnet} = $telnet;
	}
	
	if ($self->{telnet}->errmsg) {
		$self->{telnet}->open;
		$self->{telnet}->login($telnet_login, $telnet_pass);
	}
	
	my @text = $self->{telnet}->cmd($cmd);
	return @text;	
}

=head3 model

=begin html

Возвращает OID модели коммутатора.

<p class="code">print $dlink->model;<span class="code-comment"># 1.3.6.1.4.1.171.10.64.1</span></p>

=end html

=begin man

=over 1 

=item

C<< print $dlink->model; >> I<# 1.3.6.1.4.1.171.10.64.1>

=back

=end man

=cut

sub model {
	my $self = shift;
	return $self->{model};
}

=head3 error

=begin html

Возвращает строку с ошибкой SNMPv3. Как правило используется в связке с <span class="code">_snmpset</span>.

=end html

=cut

sub error {
	my $self = shift;
	return $self->{snmpv3}->error();
}

=head3 description

=begin html

Возвращает строку с описанием коммутатора.

<p class="code">print $dlink->description;<span class="code-comment"># DES-3526 Fast-Ethernet Switch</span></p>

=end html

=begin man

=over 1

=item

C<< print $dlink->description; >> I<// DES-3526 Fast-Ethernet Switch>

=back

=end man

=cut

sub description {
	my $self = shift;
	return $self->_snmpget($OID_description);
}

sub _translate {
	my $self = shift;
	my $action = shift;
	my $value = shift;
	
	if ((not defined $action) || !$action) {
		die '(internal)DLink::SNMP->_translate: no $action';
	}
	
	if (not defined $value) {
		die '(internal)DLink::SNMP->_translate: no $value';
	}
	
	if ($value =~ 'noSuchObject') {
		return 'not_supported';
	}
	
	if ($value =~ 'noSuchInstance') {
		return 'not_available';
	}
	
	if ($action =~ 'OperNway') {
		return $self->{str_PortOperNway}[$value];
	} elsif ($action =~ 'OperState') {
		return $self->{str_PortOperState}[$value];
	} elsif ($action =~ 'AdminNway') {
		return $self->{str_PortAdminNway}[$value];
	} elsif ($action =~ 'AdminState') {
		return $self->{str_PortAdminState}[$value];
	} elsif ($action =~ 'ErrDisabled') {
		return $self->{str_PortErrDisabled}[$value];
	} elsif ($action =~ 'LBDState') {
		return $self->{str_LBD_State}[$value];
	} elsif ($action =~ 'LBDPortState') {
		return $self->{str_LBD_PortState}[$value];
	} elsif ($action =~ 'LBDPortLoopStatus') {
		return $self->{str_LBD_PortLoopStatus}[$value];
	} elsif ($action =~ 'IMPBDHCPSnooping') {
		return $self->{str_IMPB_DHCPSnooping}[$value];
	} elsif ($action =~ 'IMPBPortState') {
		return $self->{str_IMPB_PortState}[$value];
	} elsif ($action =~ 'IMPBPortZeroIP') {
		return $self->{str_IMPB_ZeroIP}[$value];
	} elsif ($action =~ 'IMPBPortForwardDHCPPkt') {
		return $self->{str_IMPB_ForwardDHCPPkt}[$value];
	} elsif ($action =~ 'SNTPState') {
		return $self->{str_SNTP_State}[$value];
	} elsif ($action =~ 'DHCPRelay') {
		return $self->{str_DHCPRelay_State}[$value];
	} elsif ($action =~ 'DHCPLocalRelay') {
		return $self->{str_DHCPLocalRelay_State}[$value];
	} elsif ($action =~ 'DataDriven$') {
		return $self->{str_IGMP_DataDriven}[$value];
	} elsif ($action =~ 'DataDrivenAgedOut') {
		return $self->{str_IGMP_DataDriven_AgedOut}[$value];
	} elsif ($action =~ 'FastLeave') {
		return $self->{str_IGMP_FastLeave}[$value];
	} elsif ($action =~ 'ReportSuppression') {
		return $self->{str_IGMP_ReportSuppression}[$value];
	} elsif ($action =~ 'AAPortState') {
		return $self->{str_IGMP_AA_PortState}[$value];
	} elsif ($action =~ 'BroadcastStatus') {
		return $self->{str_TrafCtrl_BroadcastStatus}[$value];
	} elsif ($action =~ 'MulticastStatus') {
		return $self->{str_TrafCtrl_MulticastStatus}[$value];
	} elsif ($action =~ 'UnicastStatus') {
		return $self->{str_TrafCtrl_UnicastStatus}[$value];
	} elsif ($action =~ 'ActionStatus') {
		return $self->{str_TrafCtrl_ActionStatus}[$value];
	} elsif ($action =~ 'SyslogState') {
		return $self->{str_Syslog_State}[$value];
	} elsif ($action =~ 'SyslogServerState') {
		return $self->{str_Syslog_ServerState}[$value];
	} elsif ($action =~ 'SyslogFacility') {
		return $self->{str_Syslog_Facility}[$value];
	} elsif ($action =~ 'SyslogSeverity') {
		return $self->{str_Syslog_Severity}[$value];
	} elsif ($action =~ 'WebState') {
		return $self->{str_WebState}[$value];
	} elsif ($action =~ 'TelnetState') {
		return $self->{str_TelnetState}[$value];
	} elsif ($action =~ 'FilterDHCPPortState') {
		return $self->{str_Filter_DHCP_PortState}[$value];
	} elsif ($action =~ 'FilterNetbiosPortState') {
		return $self->{str_Filter_Netbios_PortState}[$value];
	} elsif ($action =~ 'FilterExtNetbiosPortState') {
		return $self->{str_Filter_ExtNetbios_PortState}[$value];
	} elsif ($action =~ 'McastFilterAccess') {
		return $self->{str_Mcast_PortAccess}[$value];
	} elsif ($action =~ 'McastFilterState') {
		return $self->{str_Mcast_PortState}[$value];
	} elsif ($action =~ 'L3IfaceState') {
		return $self->{str_L3_Iface_State}[$value];
	} elsif ($action =~ 'ACLEtherPermit') { 
		return $self->{str_EtherACL_Permit}[$value];
	} elsif ($action =~ 'PCFPermit') {
		return $self->{str_PCF_Permit}[$value];
	} elsif ($action =~ 'ACLEtherUseEtype') {
		return $self->{str_EtherACL_UseEtype}[$value];
	} elsif ($action =~ 'ACLEtherUseMAC') {
		return $self->{str_EtherACL_UseMAC}[$value];
	} elsif ($action =~ 'SafeguardGlobalState') {
		return $self->{str_SafeguardGlobalState}[$value];
	} elsif ($action =~ 'SafeguardStatus') {
		return $self->{str_SafeguardStatus}[$value];
	} elsif ($action =~ 'SafeguardMode') {
		return $self->{str_SafeguardMode}[$value];
	} elsif ($action =~ 'SafeguardTrap') {
		return $self->{str_SafeguardTrap}[$value];
	} elsif ($action =~ 'ISMReplace') {
		return $self->{str_ISM_VLAN_Replace}[$value];
	} else {
		die '(internal)DLink::SNMP->_translate: wrong $action=' . $action;
	}
	
}

sub _checkPort {
	my $self = shift;
	my $port = shift;

	if (not defined $port) {
		return 0;
	}
	
	if (!$self->{stackable}) {
		
		if (($port < 1) || ($port > $self->{max_ports})) {
			return 0;
		}
		
		return $port;
	}
	
	if (($port !~ ':') and ($port > 0) and ($port < ($self->{unit_ports} + 1))) {
		return $port;
	}
	
	my @buf = split /:/, $port;
	my $unit = $buf[0];
	my $port = $buf[1];
	
	if (($port < 1) or ($port > $self->{unit_ports})) {
		return 0;
	}
	
	if (($unit < 1) or ($unit > $self->units)) {
		return 0;
	}
	
	return ($port + ($unit - 1) * $self->{unit_portcount});
}

sub _OOR {
	my $self = shift;
	my $port = shift;
	
	if (defined $port) {
		return "port $port is out of range (max_ports=" . $self->{max_ports} . ")";
	} else {
		return "no port specified";
	}
}

sub _normalize_mask {
	my $self = shift;
	my $mask = shift;
	
	if ($mask =~ 'noSuch') {
		return $mask;
	}
	
	if ($mask =~ '0x') {
		return $mask;
	}
	
	if (!$mask) {
		$mask = unpack("H*", $mask);
	}
	
	$mask = '0x' . $mask;
	$mask =~ s/\x00/00/g;
	$mask =~ s/\x08/08/g;
	$mask =~ s/\x10/10/g;
	$mask =~ s/\x20/20/g;
	$mask =~ s/\x40/40/g;
	$mask =~ s/\x50/50/g;
	$mask =~ s/\x60/60/g;
	$mask =~ s/\x70/70/g;
	$mask = $mask . '00000000';
	
	my $result;
	
	if ($self->{mask_size} == 16) {
		$result = substr $mask, 0, 18;
	}
	
	if ($self->{mask_size} == 8) {
		$result = substr $mask, 0, 10;
	}
	
	return $result;
}

sub _prepare_octet {
	my $mask = shift;
	$mask =~ s/0x//;
	return pack("H*", $mask);
}

sub _convert_mac {
	my $self = shift;
	my $mac = shift;
	my $result;
	
	
	$mac =~ s/0x//;
	
	for (my $i = 0; $i <= 5; $i++) {
		my $octet = substr $mac, ($i * 2), 2;
		$result = $result . $octet . '-';
	}
	
	$result =~ s/-$//;
	return $result;
}

sub _normalize_ip {
	my $self = shift;
	my $ip = shift;
	my $result;
	my $octet;
	
	if (!$ip) {
		return 0;
	}
	
	if ($ip !~ '0x') {
		return $ip;
	}
	
	my $number = hex($ip);	
	for (my $i = 4; $i; $i--) {
		$octet = ($number >> 8*($i - 1));
		$number = $number - ($octet << 8*($i - 1));
		$result = $result ? $result . '.' . $octet : $octet;
	}
	
	return $result;	
}

=head3 ip_to_hex

=begin html

Возвращает шестнадцатиричное представление IP-адреса.

<p class="code">print DLink::Mgmt::ip_to_hex('172.16.128.200');<span class="code-comment"># AC1080C8</span></p>

=end html

=begin man

=over 1

=item

C<< print DLink::Mgmt::ip_to_hex('172.16.128.200'); >> I<// AC1080C8>

=back

=end man

=cut

sub ip_to_hex {
	my $ip = shift;
	my $result;
	my @buf = split /\./, $ip;
	
	foreach my $octet(@buf) {
		$result = $result . sprintf('%02X', $octet);
	}
	
	return $result;
}

=head3 units

=begin html

Возвращает количество юнитов в стеке. Для нестекируемых коммутаторов возвращает <i>1</i>.

=end html

=cut

sub units {
	my $self = shift;
	
	if ($self->{model} eq '1.3.6.1.4.1.171.10.118.2') {		# DGS-3620-28SC
		return $self->_snmpget('1.3.6.1.4.1.171.12.11.1.9.3.0');
	}
	
	if ($self->{model} eq '1.3.6.1.4.1.171.10.94.5') {		# DGS-3100-24TG
		my $units;
		my @buf = $self->_snmpwalk('1.3.6.1.4.1.171.10.94.89.89.107.1.1.2');
		
		foreach my $i(@buf) {
			$units++;
		}
		
		return $units;
	}
	
	return 1;
}

sub _portconv {
	my $self = shift;
	my $mask = $self->_normalize_mask(shift);
	my $buf;
	my $result;

	if (!$self->{stackable}) {
		
		if (length($mask) > 10) {
			$mask = substr $mask, 0, 18;
			$buf = reverse sprintf("%064b", hex($mask));
		} else {
			$buf = reverse sprintf("%032b", hex($mask));
		}
		
		my $p = hex(sprintf("%x", oct("0b$buf")));
		for (my $i = 1; $i <= 64; $i++) {
			if ($p & (1 << ($i - 1))) {
				if ($result) {
					$result = $result . ',' . $i;
				} else {
					$result = $i;
				}
			}
		}
		
		if (!$result) {
			return '0';
		}
		
		return $result;
	}
	
	if (!$self->{units}) {
		$self->{units} = $self->units;
	}
	
	my $bm_count = 18;
	
	if ($self->{unit_bitmask} == 48) {
		$bm_count = 14;
	}
	
	for my $unit (1..$self->{units}) {
		my $unit_mask = substr($mask, 0, $bm_count);
		$mask =~ s/^$unit_mask//;
		$mask = '0x' . $mask;
		
		if ($self->{unit_bitmask} == 48) {
			$buf = reverse sprintf("%048b", hex($unit_mask));
		} else {
			$buf = reverse sprintf("%064b", hex($unit_mask));
		}
		
		my $p = hex(sprintf("%x", oct("0b$buf")));
		for (my $i = 1; $i <= 64; $i++) {
			if ($p & (1 << ($i - 1))) {
				if ($result) {
					$result = $result . ',' . $unit . ':' . $i;
				} else {
					$result = $unit . ':' . $i;
				}
			}
		}
	}
	
	$result =~ s/1://g;
	return $result;	
}

=head3 createMask

=begin html

Возвращает битовую маску на основе указанных портов.

<p class="code">print $dlink->createMask('1-3,9-12');<span class="code-comment"># E0F0000000000000</span></p>

<b>На данный момент интервалы с указанием номера юнита не поддерживаются!</b>

=end html

=begin man

=over 1

=item

C<< print $dlink->createMask('1-3,9-12'); >> I<// E0F0000000000000>

=back

=end man

B<>

=cut

sub createMask {
	my $self = shift;
	my $ports = shift;
	my $mask;
	my $prep;
	
	$ports =~ s/ //g;
	
	if ($ports =~ ':') {
		return;		# here must be some sub call (createMask with stack unit support)
	}
	
	my @slices = split /,/, $ports;
	
	foreach my $slice(@slices) {
		
		if ($slice !~ '-') {
			
			if (!$prep) {
				$prep = $slice;
			} else {
				$prep = $prep . ',' . $slice;
			}
			
		} else {
			my @edge = split /-/, $slice;
			
			for my $i ($edge[0]..$edge[1]) {
				
				if (!$prep) {
					$prep = $i;
				} else {
					$prep = $prep . ',' . $i;
				}
			}
			
		}
		
	}
	
	my @entries = split /,/, $prep;
	
	foreach my $port(@entries) {
		$mask += (1 << (64 - $port));
	}
	
	my $result = sprintf('%016X', $mask);
	
	if ($self->{mask_size} == 16) {
		return $result;
	} elsif ($self->{mask_size} == 8) {
		return substr($result, 0, 8);
	}
	
}

=head3 addMasks

=begin html

Возвращает результат сложения двух заданных масок.

<p class="code">print $dlink->addMasks('00ff000000000000', 'ac00ed0000000000');
<span class="code-comment"># ACFFED0000000000</span></p>

=end html

=begin man

=over 1

=item

C<< print $dlink->addMasks('00ff000000000000', 'ac00ed0000000000'); >> I<// ACFFED0000000000>

=back

=end man

=cut

sub addMasks {
	my $self = shift;
	my $mask1 = shift;
	my $mask2 = shift;
	$mask1 =~ s/0x//;
	$mask2 =~ s/0x//;
	$mask1 = substr($mask1, 0, $self->{mask_size});
	$mask2 = substr($mask2, 0, $self->{mask_size});
	
	if ($self->{mask_size} == 16) {
		return sprintf('%016X', (hex($mask1) | hex($mask2)));
	}
	
	if ($self->{mask_size} == 8) {
		return sprintf('%08X', (hex($mask1) | hex($mask2)));
	}
}

=head3 subtractMasks

=begin html

Возвращает результат вычитания второй указанной маски из первой.
<p class="code">print $dlink->subtractMasks('FFFFFFC000000000', '8000000000000000');
<span class="code-comment"># 7FFFFFC000000000</span></p>

=end html

=begin man

=over 1

=item

C<< print $dlink->subtractMasks('FFFFFFC000000000', '8000000000000000'); >> I<// 7FFFFFC000000000>

=back

=end man

=cut

sub subtractMasks {
	my $self = shift;
	my $mask1 = shift;
	my $mask2 = shift;
	$mask1 =~ s/0x//;
	$mask2 =~ s/0x//;
	$mask1 = substr($mask1, 0, $self->{mask_size});
	$mask2 = substr($mask2, 0, $self->{mask_size});
	
	if ($self->{mask_size} == 16) {
		return sprintf('%016X', (hex($mask1) ^ hex($mask2) & hex($mask1)));
	}
	
	if ($self->{mask_size} == 8) {
		return sprintf('%08X', (hex($mask1) ^ hex($mask2) & hex($mask1)));
	}
	
}

=head3 AddToMask

=begin html

Возвращает результат добавления в указанную маску указанных портов.

<p class="code">print DLink::Mgmt::AddToMask('FFFFFF0000000000', '25-26');
<span class="code-comment"># FFFFFFC000000000</span></p>

=end html

=begin man

=over 1

=item

C<< print DLink::Mgmt::AddToMask('FFFFFF0000000000', '25-26'); >> I<// FFFFFFC000000000>

=back

=end man

=cut

sub AddToMask {
	my $self = shift;
	my $mask = shift;
	my $ports = shift;
	return $self->addMasks($mask, $self->createMask($ports));
}

=head3 RemoveFromMask

=begin html

Возвращает результат вычитания из указанной маски указанных портов.

<p class="code">print DLink::Mgmt::RemoveFromMask('FFFFFFC000000000', '1-4,20-26');
<span class="code-comment"># 0FFFE00000000000</span></p>

=end html

=begin man

=over 1

=item

C<< print DLink::Mgmt::RemoveFromMask('FFFFFFC000000000', '1-4,20-26'); >> I<// 0FFFE00000000000>

=back

=end man

=cut

sub RemoveFromMask {
	my $self = shift;
	my $mask = shift;
	my $ports = shift;
	return $self->subtractMasks($mask, $self->createMask($ports));
}

sub _addToMask {
	my $self = shift;
	my $OID = shift;
	my $ports = shift;
	
	my $old_mask = $self->_normalize_mask($self->_snmpget($OID));
	$old_mask =~ s/0x//;
	$old_mask = substr($old_mask, 0, 8);
	return $self->_snmpset($OID, $t_octet, _prepare_octet($self->AddToMask($old_mask, $ports)));
}

sub _removeFromMask {
	my $self = shift;
	my $OID  = shift;
	my $ports = shift;
	
	my $old_mask = $self->_normalize_mask($self->_snmpget($OID));
	$old_mask =~ s/0x//;
	return $self->_snmpset($OID, $t_octet, _prepare_octet($self->RemoveFromMask($old_mask, $ports)));
}

sub _setMask {
	my $self = shift;
	my $OID = shift;
	my $mask = shift;
	$mask =~ s/0x//;
	return $self->_snmpset($OID, $t_octet, _prepare_octet($mask));
}

=head3 _snmpwalk

=begin html

Возвращает результат <span class="code">snmpwalk</span>-запроса по указанному OID в виде списка хэшей.
Если OID не указан, возвращает <i>noSuchObject</i>.

=end html

=cut

sub _snmpwalk {
	my $self = shift;
	my $origin_oid = shift;
	
	if (!$origin_oid) {
		return 'noSuchObject';
	}
	
	my @vars;
	my $oid = $origin_oid;
	while ($oid =~ $origin_oid) {
		my $result = $self->{snmp_session}->get_next_request(-varbindlist => [$oid]);
		my ($key, $value) = each %{$result};
		if ($key =~ $origin_oid) {
			push @vars, {$key => $value};
		}
	$oid = $key;
	}
	return @vars;
}

=head3 _snmpgetnext

=begin html

Возвращает результат <span class="code">snmpgetnext</span>-запроса по указанному OID. Если OID не указан,
возвращает <i>noSuchObject</i>.

=end html

=cut

sub _snmpgetnext {
	my $self = shift;
	my $oid = shift;
	
	if (!$oid) {
		return 'noSuchObject';
	}
	
	my $result = $self->{snmp_session}->get_next_request(-varbindlist => [$oid]);
	my ($key, $value) = each %{$result};
	return $value;
}

=head3 _snmpset

=begin html

Возвращает результат <span class="code">snmpset</span>-запроса по списку параметров. 
Является оберткой для <span class="code">Net::SNMP->set_request</span>. В случае, 
если запрос прошел неудачно, возвращает <i>undef</i>, при этом ошибку можно получить, 
вызвав функцию <span class="code>error</span>. Если при инициализации устройства 
не создается объект-свойство <span class="code">snmpv3</span>, функция 
<span class="code>_snmpset</span> вызывает завершение работы с сообщением <i>"SNMPv3
&nbspwas not initialized!"</i>

=end html

=cut

sub _snmpset {
	my $self = shift;
	my @args = @_;
	
	if (!$self->{snmpv3}) {
		die 'SNMPv3 was not initialized!';
	}
	
	my $result = $self->{snmpv3}->set_request(@args);
	
	if (!$result && $self->{debug}) {
		
		foreach my $arg(@args) {
			print $arg, "\t";
		}
		
		print "\n", $self->error, "\n";
		
	}
	
	return $result;
}

=head3 save

=begin html

Производит сохранение конфигурации и/или системного журнала коммутатора в зависимости 
от указанного параметра:

<p class="list">
<span class="code">cfg</span> - сохранить конфигурацию<br>
<span class="code">log</span> - сохранить системный журнал<br>
<span class="code">all</span> - сохранить все
</p>

При вызове без параметра считается, что был назначен параметр <span class="code">all</span>.<br>

<b>Внимание! В этой функции используются OID, не указанные в конструкторе <span class="code">new</span>.
Подробнее в разделе "Добавление новых устройств".</b>

=end html

=cut

sub save {
	my $self = shift;
	my $type = shift;
	
	$type = $type ? $type : 'all';
	
	if ($self->model eq '1.3.6.1.4.1.171.10.64.1') {	# DES-3526
		return $self->_snmpset('1.3.6.1.4.1.171.12.1.2.6.0', $t_integer, 3);
	}
	
	if ($self->model =~ "1.3.6.1.4.1.171.10.113.[36].1") {	# DES-3200/C1 series
		
		if ($type eq 'cfg') {
			$type = 2;
		} elsif ($type eq 'log') {
			$type = 3;
		} else {
			$type = 4;
		}
		
		return $self->_snmpset('1.3.6.1.4.1.171.12.1.2.18.4.0', $t_integer, $type);
	}
	
	if ($type eq 'cfg') {
		$type = 2;
	} elsif ($type eq 'log') {
		$type = 4;
	} else {
		$type = 5;
	}
	
	return $self->_snmpset('1.3.6.1.4.1.171.12.1.2.6.0', $t_integer, $type);
}

=head3 reboot

=begin html

Производит перезагрузку коммутатора.
<br/>
<b>Внимание! В этой функции используются OID, не указанные в конструкторе
<span class="code">new</span>.
Подробнее в разделе "Добавление новых устройств".</b>

=end html

=cut

sub reboot {
	my $self = shift;
	
	if (($self->model eq '1.3.6.1.4.1.171.10.64.1')	or ($self->model eq '1.3.6.1.4.1.171.10.63.6')) {	# DES-3526/3028
		$self->_snmpset('1.3.6.1.4.1.171.12.1.2.3.0', $t_integer, 3);
		return 'OK';
	}
	
	$self->_snmpset('1.3.6.1.4.1.171.12.1.2.19.0', $t_integer, 2);
	return 'OK';
}

sub _interval {
	my $self = shift;
	my $string = shift;
	my @ports = split /,/, $string;
	push @ports, -1;
	my $out;
	my $first;
	my $last;
	my $old_unit;
	my $unit;
	
	foreach my $port(@ports) {
		
		if ($port =~':') {
			my @buf = split /:/, $port;
			$unit = $buf[0];
			$port = $buf[1];
		} 
		
		if (!$first) {
			$first = $port;
			$last = $port;
			$old_unit = $unit;
			next;
		}
		
		if (($port == ($last + 1)) and ($unit == $old_unit)) {
			$last = $port;
		} else {
			my $int;
			
			if ($first != $last) {
				
				if (!$old_unit) {
					$int = $first . '-' . $last;
				} else {
					$int = $old_unit . ':' . $first . '-' . $old_unit . ':' . $last;
				}
			} else {
				
				if (!$old_unit) {
					$int = $first;
				} else {
					$int = $old_unit . ':' . $first;
				}
			}
			
			if (!$out) {
				$out = $int;
			} else {
				$out = $out . ',' . $int;
			}
			
			if ($port != -1) {
				$first = $port;
				$last = $port;
				$old_unit = $unit;
			} else {
				last;
			}
		}
		
	}
	
	return $out;	
}

=head3 uplink

=begin html

Возвращает номер uplink-порта.
<br/><br/>
<i>Важно! Функция запрашивает коммутатор по SNMP только в первый раз, все последующие вызовы
возвращают значение свойства <span class="code">uplink_port</span> в целях минимизации 
количества запросов к устройству. Поэтому в случаях, когда <b>uplink-порт мог измениться</b>, 
перед новым вызовом <span class="code">uplink</span> стоит назначать свойству 
<span class="code">uplink_port</span> значение <b>undef</b>.</i>

=end html

=cut

sub uplink {
	my $self = shift;
	
	if ($self->{uplink_port}) {
		return $self->{uplink_port};
	}
	
	my $binmac;
	my @buf = split /-/, $self->{gw};
	foreach my $octet(@buf) {
		$binmac = $binmac . hex('0x'.$octet) . '.';
	}
	$binmac =~ s/\.$//;
	my $OID = $OID_FDB_port . '.' . $binmac;
	$self->{uplink_port} = $self->_snmpget($OID);
	return $self->{uplink_port};
}

=head3 firmwareBoot

=begin html

Возвращает версию прошивки, на которой работает коммутатор в данный момент.
<p class="code">print $dlink->firmwareBoot;<span class="code-comment"># 6.20.B07</span></p>

=end html

=cut

sub firmwareBoot {
	my $self = shift;
	my $result;
	my @fws = $self->_snmpwalk($OID_DLink_FW);
	
	foreach my $fw(@fws) {
		my ($key, $value) = each %{$fw};
		
		if ($value =~ '\*') {
			$value =~ s/\*//;
			$result = $value;
			last;
		}
	}
	return $result;
}

=head3 firmwareList

=begin html

Возвращает список прошивок на устройстве. Кстати, прошивка, использующаяся при
загрузке, помечена символом <b>*</b>
<p class="code">@fw_list = $dlink->firmwareList;<br/>
foreach my $fw (@fw_list) {<br/>
<span class="tab">print $fw, "\n";</span><br/>
}<br/>
<br/>
<span class="code-comment">6.00.B057<br/></span>
<span class="code-comment">*6.20.B018</span>
</p>

=end html

=cut

sub firmwareList {
	my $self = shift;
	my @fws = $self->_snmpwalk($OID_DLink_FW);
	my @array;
	
	foreach my $fw(@fws) {
		my ($key, $value) = each %{$fw};
		push @array, $value;
	}
	
	return @array;
}

=head3 isPortInMask

=begin html

Функция проверяет, входит ли указанный порт в указанную битовую маску, и возвращает
битовую маску порта. Если порт не входит в указанную битовую маску порта, возвращает
0.

<p class="code">
print DLink::Mgmt::isPortInMask(1, 'FF00000000000000');
<span class="code-comment"># 8000000000000000</span><br/>
print DLink::Mgmt::isPortInMask(10, 'FF00000000000000');
<span class="code-comment"># 0</span>
</p>

=end html

=cut

sub isPortInMask {
	my $self = shift;
	my $port = $self->createMask(shift);
	my $mask = shift;
	
	return hex('0x'.$port) & hex('0x'.$mask);
}

#
#	Ports section
#

sub _getPort {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $type = shift;
	my $snmp = $self->{snmp_session};
	my $OID_copper;
	my $OID_fiber;
	my $OID;
	my @str;
	
	if ($self->{custom_port_functions}) {
		return $self->_getPortCustom($action, $port);
	}
	
	$port = $self->_checkPort($port);
	if (!$port) {
		die 'DLink::SNMP->getPort' . $action . ": " . $self->_OOR($port);
	}
	
	if ($action =~ 'OperNway') {
		$OID = $self->{OID_PortOperNway} . '.' . $port;
	} elsif ($action =~ 'OperState') {
		$OID = $self->{OID_PortOperState} . '.' . $port;
	} elsif ($action =~ 'AdminNway') {
		$OID = $self->{OID_PortAdminNway} . '.' . $port;
	} elsif ($action =~ 'AdminState') {
		$OID = $self->{OID_PortAdminState} . '.' . $port;
	} elsif ($action =~ 'ErrDisabled') {
		$OID = $self->{OID_PortErrDisabled} . '.' . $port;
	} elsif ($action =~ 'Description') {
		return $self->_snmpget($OID_PortDescription . '.' . $port);
	} else {
		die '(internal)DLink::SNMP->_getPort: wrong $action=' . $action;
	}
	
	if (!$OID) {
		return "not_supported";
	}
	
	$OID_copper = $OID . '.' . $self->{copper};
	$OID_fiber = $OID . '.' . $self->{fiber};
	$OID = $self->{default_medium} =~ 'fiber' ? $OID_fiber : $OID_copper;
	
	if ($type =~ 'all') {
		my @list;
		push @list, $self->_translate($action, $self->_snmpget($OID_copper));
		push @list, $self->_translate($action, $self->_snmpget($OID_fiber));
		return @list;
	} elsif ($type =~ 'fiber') {
		$OID = $OID_fiber;
	} elsif ($type =~ 'copper') {
		$OID = $OID_copper;
	}

	return $self->_translate($action, $self->_snmpget($OID));
}

sub _getPortCustom {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $result;
	
	if ($action =~ 'OperNway') {
		my $duplex = $self->_snmpget($self->{OID_PortOperDuplex} . '.' . $port);
		my $speed = int($self->_snmpget($self->{OID_PortOperSpeed} . '.' . $port) / 1000000);
		
		if ($self->{model} == '1.3.6.1.4.1.171.10.94.5') {		# DGS-3100-24TG
		
			if ($duplex == 4) {
				return $link_fail;
			}
		
			$duplex = ($duplex == 1) ? 'half' : 'full';
		}
		
		$result = $speed ? $speed . '-' . $duplex : $link_fail;
	}
	
	if ($action =~ 'OperState') {
		$result = ($self->_snmpget($self->{OID_PortOperState} . '.' . $port) == 1) ? $link_pass : $link_fail;
	}
	
	if ($action =~ 'AdminState') {
		$result = ($self->_snmpget($self->{OID_PortAdminState} . '.' . $port) == 1) ? $link_pass : $link_fail;
	}
	
	if ($action =~ 'AdminNway') {
		my $duplex = $self->_snmpget($self->{OID_PortAdminDuplex} . '.' . $port);
		my $speed = $self->_snmpget($self->{OID_PortAdminSpeed} . '.' . $port);
		
		$speed = $speed ? int($speed / 1000000) : 'auto';
		
		if ($self->{model} == '1.3.6.1.4.1.171.10.94.5') {		# DGS-3100-24TG
			if ($duplex == 1) {
				$duplex = 'auto';
			} elsif ($duplex == 2) {
				$duplex = 'half';
			} elsif ($duplex == 3) {
				$duplex = 'full';
			}
		}
		
		if ($speed =~ $duplex) {
			$result = 'auto';
		} else {
			$result = $speed . '-' . $duplex;
		}
	}
	
	if ($action =~ 'Description') {
		return $self->_snmpget($OID_PortDescription . '.' . $port);
	}
	
	return $result;
}

=head3 getPort...

=begin html

Список функций, возвращающих ту или иную информацию о состоянии и настройках порта. 
Все нижеописанные функции реализованы в виде интерфейсов к функции <span class="code">
_getPort</span>, которая поддерживает стеки коммутаторов. Первым параметром должен
быть указан порт, вторым (необязательным) параметром может быть указан тип порта:
<span class="code">copper, fiber, all</span>. Если второй
параметр будет опущен, будет выбран тип порта по умолчанию (для каждой модели указан в
 конструкторе <span class="code">new</span>). Если вторым параметром будет указано
<span class="code">all</span>, функция вернет список с результатами для каждого из
интерфейсов, причем первым будет медный интерфейс.

=end html

=head4 getPortOperNway

=begin html

Состояние согласования скорости/дуплекса на порту 
(<span class="code">link-fail, 10-half, 10-full, 100-half, 100-full, 1000-full...</span>).

=end html

=head4 getPortOperState

=begin html

Состояние порта (<span class="code">link-fail, link-pass</span>).

=end html

=head4 getPortAdminNway

=begin html

Административное состояние согласования скорости/дуплекса на порту 
(<span class="code">auto, 10-half, 10-full, 100-half, 100-full, 1000-full...</span>).

=end html

=head4 getPortAdminState

=begin html

Адиминстративное состояние порта (<span class="code">enabled, disabled</span>).

=end html

=head4 getPortErrDisabled

=begin html

Состояние Err-Disabled на порту (<span class="code">none, storm, lbd, error, unknown</span>).
На большинстве моделей функция не поддерживается,
т.к. соответствующий OID в дереве создается только при переходе порта в состояние
Err-Disabled. Если функция будет вызвана для устройства с вышеуказанным поведением,
а порт будет функционировать нормально, будет возвращена строка <span class="code">
not_supported</span>.

=end html

=head4 getPortDescription

=begin html

Возвращает пользовательское описание порта (комментарий).

=end html

=cut

sub getPortOperNway {
	my $self = shift;
	my $port = shift;
	my $type = shift;
	return $self->_getPort('OperNway', $port, $type);
}

sub getPortOperState {
	my $self = shift;
	my $port = shift;
	my $type = shift;
	return $self->_getPort('OperState', $port, $type);
}

sub getPortAdminNway {
	my $self = shift;
	my $port = shift;
	my $type = shift;
	return $self->_getPort('AdminNway', $port, $type);
}

sub getPortAdminState {
	my $self = shift;
	my $port = shift;
	my $type = shift;
	return $self->_getPort('AdminState', $port, $type);
}

sub getPortErrDisabled {
	my $self = shift;
	my $port = shift;
	my $type = shift;
	return $self->_getPort('ErrDisabled', $port, $type);
}

sub getPortDescription {
	my $self = shift;
	my $port = shift;
	return $self->_getPort('Description', $port);
}

#
#	LBD section
#

sub _getLBD {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $OID;
	
	if ($action !~ '^State') {
		
		$port = $self->_checkPort($port);
		if (!$port) {
			die 'DLink::SNMP->getLBD' . $action . ": " . $self->_OOR($port);
		}
		
		if ($action =~ 'PortState') {
			$OID = $self->{OID_LBD_PortState} . '.' . $port;
		} elsif ($action =~ 'PortLoopStatus') {
			$OID = $self->{OID_LBD_PortLoopStatus} . '.' . $port;
		} else {
			die '(internal)DLink::SNMP->_getLBD: wrong $action=' . $action;
		}
		
	} elsif ($action =~ '^State$') {
		$OID = $self->{OID_LBD_State};
	}
	
	if (!$OID) {
		return "not_supported";
	}
	
	return $self->_translate('LBD' . $action, $self->_snmpget($OID));
}

=head3 getLBDState

=begin html

Возвращает общее состояние функционала Loopback Detection (<span class="code">enabled, disabled</span>).

=end html

=cut

sub getLBDState {
	my $self = shift;
	return $self->_getLBD('State');
}

=head3 getLBDPortState

=begin html

Возвращает состояние настройки LBD на порту (<span class="code">enabled, disabled</span>)
или <span class="code">not_supported</span>, если устройство не поддерживает управление
LBD по SNMP.

=end html

=cut

sub getLBDPortState {
	my $self = shift;
	my $port = shift;
	return $self->_getLBD('PortState', $port);
}

=head3 getLBDPortLoopStatus

=begin html

Возвращает состояние порта по LBD (<span class="code">normal, loop</span>).

=end html

=cut

sub getLBDPortLoopStatus {
	my $self = shift;
	my $port = shift;
	return $self->_getLBD('PortLoopStatus', $port);
}

#
#	ISM VLAN
#

sub _getISM {
	my $self = shift;
	my $action = shift;
	my $format = shift;
	my $var_formats;
	my $OID;
	
	if ($action =~ '^MemberPorts') {
		$OID = $self->{OID_ISM_VLAN_Member};
		$var_formats = 1;
	} elsif ($action =~ 'SourcePorts') {
		$OID = $self->{OID_ISM_VLAN_Source};
		$var_formats = 1;
	} elsif ($action =~ 'TagMemberPorts') {
		$OID = $self->{OID_ISM_VLAN_Tagged};
		$var_formats = 1;
	} elsif ($action =~ 'Name') {
		$OID = $self->{OID_ISM_VLAN_Name};
	} elsif ($action =~ 'ReplaceSrcIP') {
		$OID = $self->{OID_ISM_VLAN_ReplaceSrcIP};
	} elsif ($action =~ 'Remap') {
		$OID = $self->{OID_ISM_VLAN_Remap};
	} elsif ($action eq 'Replace') {
		$OID = $self->{OID_ISM_VLAN_Replace};
	} elsif ($action eq 'State') {
		$OID = $self->{OID_ISM_VLAN_State};
	} else {
		die '(internal)DLink::SNMP->_getISM: wrong $action=' . $action;
	}
	
	if (!$OID) {
		return "not_supported";
	}
	
	if ($var_formats) {
		$format = $format ? $format : 'mask';
		my $result = $self->_normalize_mask($self->_snmpget($OID));
		
		if ($format =~ 'list') {
			
			return $self->_portconv($result);
		} elsif ($format =~ 'interval') {
			return $self->_interval($self->_portconv($result));
		} else {
			return $self->_normalize_mask($result);
		}
	} else {
		return $self->_snmpget($OID);
	}
}

=head3 getISM...

=begin html

Список функций, возвращающих ту или иную информацию о настройках IGMP Snooping 
Multicast VLAN. Функции, возвращающие информацию о портах, имеют три формата вывода:
<p class="list">
Mask: <span class="code">FF000000</span><br/>
Ports: <span class="code">1,2,3,4,5,6,7,8</span><br/>
Interval: <span class="code">1-8</span></p>

=head4 getISMMemberMask

=head4 getISMMemberPorts

=head4 getISMMemberInterval

Возвращает список member портов в заданном формате.

=head4 getISMSourceMask

=head4 getISMSourcePorts

=head4 getISMSourceInterval

Возвращает список source портов в заданном формате.

=head4 getISMTaggedMask

=head4 getISMTaggedPorts

=head4 getISMTaggedInterval

Возвращает список tagged member портов в заданном формате.

=head4 getISMName

Возвращает название ISM VLAN.

=head4 getISMReplaceSrcIP

Возвращает настройку replace source ip, если настройка не задана, возвращает
<span class="code">0.0.0.0</span>

=head4 getISMRemap

Возвращает настройку remap priority.

=head4 getISMReplace

Возвращает настройку replace priority (<span class="code">enabled, disabled</span>).

=end html

=cut

sub getISMMemberMask {
	my $self = shift;
	return $self->_getISM('MemberPorts');
}

sub getISMMemberPorts {
	my $self = shift;
	return $self->_getISM('MemberPorts', 'list');
}

sub getISMMemberInterval {
	my $self = shift;
	return $self->_getISM('MemberPorts', 'interval');
}

sub getISMSourceMask {
	my $self = shift;
	return $self->_getISM('SourcePorts');
}

sub getISMSourcePorts {
	my $self = shift;
	return $self->_getISM('SourcePorts', 'list');
}

sub getISMSourceInterval {
	my $self = shift;
	return $self->_getISM('SourcePorts', 'interval');
}

sub getISMTaggedMask {
	my $self = shift;
	return $self->_getISM('TagMemberPorts');
}

sub getISMTaggedPorts {
	my $self = shift;
	return $self->_getISM('TagMemberPorts', 'list');
}

sub getISMTaggedInterval {
	my $self = shift;
	return $self->_getISM('TagMemberPorts', 'interval');
}

sub getISMName {
	my $self = shift;
	return $self->_getISM('Name');
}

sub getISMReplaceSrcIP {
	my $self = shift;
	my $result = $self->_getISM('ReplaceSrcIP');
	
	if (unpack("H*", $result) eq '00000000') {
		return '0.0.0.0';
	} else {
		return $result;
	}
	
}

sub getISMState {
	my $self = shift;
	my $r = $self->_getISM('State');
	return $self->{str_ISM_VLAN_State}[$r];
}

sub getISMRemap {
	my $self = shift;
	return $self->_getISM('Remap');
}

sub getISMReplace {
	my $self = shift;
	return $self->_translate('ISMReplace', $self->_getISM('Replace'));
}

#
#	RADIUS
#

sub _getRADIUS {
	my $self = shift;
	my $action = shift;
	my $id = shift;
	my $normalize;
	my $OID;
	
	if ($action =~ 'List') {
		$OID = $self->{OID_RADIUS_Index};
		my @indexes;
		my @buf = $self->_snmpwalk($OID);
		foreach my $entry(@buf) {
			my ($key, $value) = each %{$entry};
			push @indexes, $value;
		}
		return @indexes;
	} elsif ($action =~ 'Retransmit') {
		
		if ($self->{RADIUS_separate_params}) {
			$OID = $self->{OID_RADIUS_Retransmit} . '.' . $id;
		} else {
			$OID = $self->{OID_RADIUS_Retransmit};
		}
		
		return $self->_snmpget($OID);
	} elsif ($action =~ 'Timeout') {
		
		if ($self->{RADIUS_separate_params}) {
			$OID = $self->{OID_RADIUS_Timeout} . '.' . $id;
		} else {
			$OID = $self->{OID_RADIUS_Timeout};
		}
		
		return $self->_snmpget($OID);
	}
	
	if (!$id) {
		die "DLink::SNMP->getRADIUS$action: no id found";
	}
	
	if ($action =~ 'IP') {
		$OID = $self->{OID_RADIUS_IP};
		$normalize = 1;
	} elsif ($action =~ 'AuthPort') {
		$OID = $self->{OID_RADIUS_AuthPort};
	} elsif ($action =~ 'AcctPort') {
		$OID = $self->{OID_RADIUS_AcctPort};
	} else {
		die '(internal)DLink::SNMP->_getRADIUS: wrong action=' . $action;
	}
	
	if (!$OID) {
		return 'not_supported';
	}
	
	$OID = $OID . '.' . $id;
	my $result = $normalize ? $self->_normalize_ip($self->_snmpget($OID)) : $self->_snmpget($OID);
	return $result;
}

=head3 getRADIUS...

=begin html

Список функций для получения информации о настроенных RADIUS-серверах.

=end html

=head4 getRADIUSList

=begin html

Возвращает список с индексами указанных на устройстве RADIUS-серверов.

=end html

=cut

sub getRADIUSList {
	my $self = shift;
	return $self->_getRADIUS('List');
}

=head4 getRADIUSIP

=begin html

Возвращает IP адрес RADIUS сервера с указанным индексом.
<p class="code">
print $dlink->getRADIUSIP(1);<span class="code-comment"># 192.168.1.112</span></p>

=end html

=cut

sub getRADIUSIP {
	my $self = shift;
	my $id = shift;
	return $self->_getRADIUS('IP', $id);
}

=head4 getRADIUSAuthPort

=begin html

Возвращает порт авторизации RADIUS сервера с указанным индексом.

=end html

=cut

sub getRADIUSAuthPort {
	my $self = shift;
	my $id = shift;
	return $self->_getRADIUS('AuthPort', $id);
}

=head4 getRADIUSAcctPort

=begin html

Возвращает порт учета RADIUS сервер с указанным индексом.

=end html

=cut

sub getRADIUSAcctPort {
	my $self = shift;
	my $id = shift;
	return $self->_getRADIUS('AcctPort', $id);
}

=head4 getRADIUSTimeOut

=begin html

Возвращает значение таймаута в секундах для RADIUS сервера с указанным индексом.
Даже если устройство не поддерживает различные таймауты для каждого RADIUS сервера
отдельно, индекс сервера необходимо указывать.

=end html

=cut

sub getRADIUSTimeOut {
	my $self = shift;
	my $id = shift;
	return $self->_getRADIUS('Timeout', $id);
}

=head4 getRADIUSRetransmit

=begin html

Возвращает количество повторных попыткок соединения для RADIUS сервера с указанным 
индексом. Даже если устройство не поддерживает раздельную настройку повторных попыток 
соединения для каждого RADIUS сервера отдельно, индекс сервера необходимо указывать.

=end html

=cut

sub getRADIUSRetransmit {
	my $self = shift;
	my $id = shift;
	return $self->_getRADIUS('Retransmit', $id);
}

#
#	IMPB
#

sub _getIMPB {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $OID;
	my $is_port_needed = 1;
	my @array;
	
	if ($action =~ 'DHCPSnooping') {
		$OID = $self->{OID_IMPB_DHCPSnooping};
		$is_port_needed = 0;
	} elsif ($action =~ 'PortState') {
		$OID = $self->{OID_IMPB_PortState} . '.' . $port;
	} elsif ($action =~ 'PortZeroIP') {
		$OID = $self->{OID_IMPB_ZeroIP} . '.' . $port;
	} elsif ($action =~ 'PortForwardDHCPPkt') {
		$OID = $self->{OID_IMPB_ForwardDHCPPkt} . '.' . $port;
	} elsif ($action eq 'Entries') {
		$OID = $self->{OID_IMPB_IP};
		my $OID_mac = $self->{OID_IMPB_MAC};
		my $OID_port = $self->{OID_IMPB_Port};
		my @ips = $self->_snmpwalk($OID);
		
		foreach my $entry(@ips) {
			my ($key, $ip) = each %{$entry};
			
			if ($ip =~ 'noSuch') {
				last;
			}
			
			push @array, $ip, $self->_convert_mac($self->_snmpget($OID_mac . '.' . $ip)), $self->_portconv($self->_snmpget($OID_port . '.' . $ip));
		}
		return @array;
	} elsif ($action =~ 'BlockedEntries') {
		my @vlans = $self->_snmpwalk($self->{OID_IMPB_BlockVID});
		my @macs = $self->_snmpwalk($self->{OID_IMPB_BlockMac});
		my @ports = $self->_snmpwalk($self->{OID_IMPB_BlockPort});
		
		while (@vlans) {
			my ($key, $val) = each %{shift @vlans};
			
			if ($val =~ 'noSuch') {
				last;
			}
			
			push @array, $val;
			($key, $val) = each %{shift @macs};
			push @array, $self->_convert_mac($val);
			($key, $val) = each %{shift @ports};
			push @array, $val;
		}
		
		return @array;		
	} else {
		die '(internal)DLink::SNMP->_getIMPB: wrong $action=' . $action;
	}
	
	$port = $self->_checkPort($port);

	if ($is_port_needed && !($port)) {
		die 'DLink::SNMP->getIMPB' . $action . ': ' . $self->_OOR($port);
	}
	
	if (!$OID) {
		return "not_supported";
	}
	
	return $self->_translate('IMPB' . $action, $self->_snmpget($OID));
}

=head3 getIMBP...

=begin html

Список функций для получения информации о настройках IP-MAC-Port binding.

=end html

=head4 getIMPBPortState

=begin html

Возвращает настройку IP-MAC-Port Binding для указанного порта 
(<span class="code">disabled, strict, loose</span>). Если устройство не поддерживает
функционал IMPB, будет возвращено <span class="code">not_supported</span>.

=end html

=cut

sub getIMPBPortState {
	my $self = shift;
	my $port = shift;
	return $self->_getIMPB('PortState', $port);
}

=head4 getIMPBDHCPSnooping

=begin html

Возвращает состояние глобальной настройки DHCP Snooping (<span class="code">enabled, disabled</span>).
Если устройство не поддерживает функционал IMPB, будет возвращено <span class="code">not_supported</span>.

=end html

=cut

sub getIMPBDHCPSnooping {
	my $self = shift;
	return $self->_getIMPB('DHCPSnooping');
}

=head4 getIMPBPortZeroIP

=begin html

Возвращает состояние настройки IMPB Allow Zero IP для указанного порта 
(<span class="code">enabled, disabled</span>). Если устройство не поддерживает 
функционал IMPB, будет возвращено <span class="code">not_supported</span>.

=end html

=cut

sub getIMPBPortZeroIP {
	my $self = shift;
	my $port = shift;
	return $self->_getIMPB('PortZeroIP', $port);
}

=head4 getIMPBForwardDHCPPkt

=begin html

Возвращает состояние настройки IMPB Forward DHCP Packet для указанного порта 
(<span class="code">enabled, disabled</span>). Если устройство не поддерживает
функционал IMPB, будет возвращено <span class="code">not_supported</span>.

=end html

=cut

sub getIMPBForwardDHCPPkt {
	my $self = shift;
	my $port = shift;
	return $self->_getIMPB('PortForwardDHCPPkt', $port);
}

=head4 getIMPBEntries

=begin html

Возвращает список с тройками IP-MAC-Port из таблицы валидных связок.
<p class="code">
@table = $dlink->getIMPBEntries;<br/>
while (@table) {<br/>
<span class="tab">my $ip = shift @table;<br/></span>
<span class="tab">my $mac = shift @table;<br/></span>
<span class="tab">my $port = shift @table;<br/></span>
<span class="tab">print "$ip - $mac - $port\n";</span><span class="code-comment">
# 172.17.33.50 - 00-11-22-33-44-55 - 15</span><br/>
}
</p>

=end html

=cut

sub getIMPBEntries {
	my $self = shift;
	return $self->_getIMPB('Entries');
}

=head4 getIMPBBlockedEntries

=begin html

Возвращает список с тройками IP-MAC-Port из таблицы заблокированных связок.
<p class="code">
@table = $dlink->getIMPBBlockedEntries;<br/>
while (@table) {<br/>
<span class="tab">my $vlan = shift @table;<br/></span>
<span class="tab">my $mac = shift @table;<br/></span>
<span class="tab">my $port = shift @table;<br/></span>
<span class="tab">print "$vlan - $mac - $port\n";</span><span class="code-comment">
# 33 - 00-11-22-33-44-55 - 15</span><br/>
}
</p>

=end html

=cut

sub getIMPBBlockedEntries {
	my $self = shift;
	return $self->_getIMPB('BlockedEntries');
}

#
#	SNTP
#

sub _getSNTP {
	my $self = shift;
	my $action = shift;
	my $is_ip;
	my $OID;
	
	if ($action =~ 'State') {
		$OID = $self->{OID_SNTP_State};
		return $self->_translate('SNTPState', $self->_snmpget($OID));
	} elsif ($action =~ 'Primary') {
		$is_ip = 1;
		$OID = $self->{OID_SNTP_PrimaryIP};
	} elsif ($action =~ 'Secondary') {
		$is_ip = 1;
		$OID = $self->{OID_SNTP_SecondaryIP};
	} elsif ($action =~ 'PollInterval') {
		$OID = $self->{OID_SNTP_PollInterval};
	} else {
		die '(internal)DLink::SNMP->_getSNTP: wrong $action=' . $action;
	}
	
	if ($is_ip) {
		return $self->_normalize_ip($self->_snmpget($OID));
	}
	
	return $self->_snmpget($OID);
	
}

=head3 getSNTPState

=begin html

Возвращает состояние настройки SNTP на устройстве (<span class="code">enabled, disabled</span>).

=end html

=cut

sub getSNTPState {
	my $self = shift;
	return $self->_getSNTP('State');
}

=head3 getSNTPPrimary

=begin html

Возвращает адрес первичного SNTP сервера.

=end html

=cut

sub getSNTPPrimary {
	my $self = shift;
	return $self->_getSNTP('Primary');
}

=head3 getSNTPSecondary

=begin html

Возвращает адрес вторичного SNTP сервера.

=end html

=cut

sub getSNTPSecondary {
	my $self = shift;
	return $self->_getSNTP('Secondary');
}

=head3 getSNTPPollInterval

=begin html

Возвращает период обновления SNTP в секундах.

=end html

=cut

sub getSNTPPollInterval {
	my $self = shift;
	return $self->_getSNTP('PollInterval');
}

#
#	DHCP Relay
#

=head3 getDHCPRelayState

=begin html

Возвращает состояние настройки DHCP Relay (<span class="code">enabled, disabled</span>).

=end html

=cut

sub getDHCPRelayState {
	my $self = shift;
	return $self->_translate('DHCPRelay', $self->_snmpget($self->{OID_DHCPRelay_State}));
}

=head3 getDHCPLocalRelayState

=begin html

Возвращает состояние настройки DHCP Local Relay (<span class="code">enabled, disabled</span>).

=end html

=cut

sub getDHCPLocalRelayState {
	my $self = shift;
	return $self->_translate('DHCPLocalRelay', $self->_snmpget($self->{OID_DHCPLocalRelay_State}));
}

#
#	IGMP Snooping
#

sub _getIGMP {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $var_formats = 1;
	my $OID;
	
	if ($action =~ 'QuerierVersion') {
		$OID = $self->{OID_IGMP_Querier_Version};
		$var_formats = 2;
	} elsif ($action =~ 'DataDriven$') {
		$OID = $self->{OID_IGMP_DataDriven};
	} elsif ($action =~ 'DataDrivenAgedOut') {
		$OID = $self->{OID_IGMP_DataDriven_AgedOut};
	} elsif ($action =~ 'FastLeave') {
		$OID = $self->{OID_IGMP_FastLeave};
	} elsif ($action =~ 'ReportSuppression') {
		$OID = $self->{OID_IGMP_ReportSuppression};
	} elsif ($action =~ 'Snooping') {
		$OID = $self->{OID_IGMP_Snooping};
	} elsif ($action =~ 'AAPortState') {
		$port = $self->_checkPort($port);
		
		if (!$port) {
			die 'DLink::SNMP->getIMGPAAPortState: ' . $self->_OOR($port);
		}
		
		if (!$self->{OID_IGMP_AA_PortState}) {
			return 'not_supported';
		} else {
			$OID = $self->{OID_IGMP_AA_PortState} . '.' . $port;
		}
		
	} elsif ($action =~ 'RouterDynamic') {
		$OID = $self->{OID_IGMP_RouterDynamic};
		$var_formats = 0;
	} else {
		die '(internal)DLink::SNMP->_getIGMP: wrong $action=' . $action;
	}
	
	if (!$OID) {
		return 'not_supported';
	}
	
	if ($var_formats == 1) {
		return $self->_translate($action, $self->_snmpget($OID));
	} elsif (!$var_formats) {
		return $self->_portconv($self->_snmpget($OID));
	} else {
		return $self->_snmpget($OID);
	}
}

=head3 getIGMP...

=begin html

Список функций, возвращающих информацию о настройках IGMP Snooping.

=end html

=head4 getIGMPQuerierVersion

=begin html

Возвращает версию IGMP протокола в Multicast VLAN по умолчанию.

=end html

=cut

sub getIGMPQuerierVersion {
	my $self = shift;
	return $self->_getIGMP('QuerierVersion');
}

=head4 getIGMPDataDriven

=begin html

Возвращает состояние настройки IGMP Data Driven Groups (<span class="code">enabled, disabled</span>)
в Multicast VLAN по умолчанию. Если устройство не поддерживает 
этот функционал или его управление по SNMP, будет возвращено <span class="code">not_supported</span>.

=end html

=cut

sub getIGMPDataDriven {
	my $self = shift;
	return $self->_getIGMP('DataDriven');
}

=head4 getIGMPDataDrivenAgedOut

=begin html

Возвращает состояние настройки IGMP Data Driven Groups Aged Out (<span class="code">enabled, 
disabled</span>) в Multicast VLAN по умолчанию. Если устройство не поддерживает 
этот функционал или его управление по SNMP, будет возвращено <span class="code">not_supported</span>.

=end html

=cut

sub getIGMPDataDrivenAgedOut {
	my $self = shift;
	return $self->_getIGMP('DataDrivenAgedOut');
}

=head4 getIGMPFastLeave

=begin html

Возвращает состояние настройки IGMP Fast Leave (<span class="code">enabled, 
disabled</span>) в Multicast VLAN по умолчанию. Если устройство не поддерживает 
этот функционал или его управление по SNMP, будет возвращено <span class="code">not_supported</span>.

=end html

=cut

sub getIGMPFastLeave {
	my $self = shift;
	return $self->_getIGMP('FastLeave');
}

=head4 getIGMPReportSuppression

=begin html

Возвращает состояние настройки IGMP Report Suppression (<span class="code">enabled, 
disabled</span>) в Multicast VLAN по умолчанию. Если устройство не поддерживает 
этот функционал или его управление по SNMP, будет возвращено <span class="code">not_supported</span>.

=end html

=cut

sub getIGMPReportSuppression {
	my $self = shift;
	return $self->_getIGMP('ReportSuppression');
}

=head4 getIGMPAAPortState

=begin html

Возвращает состояние настройки IGMP Access Authentication для указанного порта
(<span class="code">enabled, disabled</span>).Если устройство не поддерживает этот
функционал, будет возвращено <span class="code">not_supported</span>.

=end html

=cut

sub getIGMPAAPortState {
	my $self = shift;
	my $port = shift;
	return $self->_getIGMP('AAPortState', $port);
}

=head4 getIGMPRouterDynamicPorts

=begin html

Возвращает строку со списком портов Dynamic Router.<p class="code">
print $dlink->getIGMPRouterDynamicPorts;<span class="code-comment"># 25,26</span>
</p>

<i>Важно! Функция пока что работает только на DES-3526!</i>

=end html

=cut

sub getIGMPRouterDynamicPorts {
	my $self = shift;
	return $self->_getIGMP('RouterDynamic');
}

#
#	Traffic control
#

sub _getTrafCtrl {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $translate;
	my $OID;
	
	$port = $self->_checkPort($port);
	if (!$port) {
		die 'DLink::SNMP->getTrafCtrl' . $action . ': ' . $self->_OOR($port);
	}
	
	if ($action =~ 'BroadcastStatus') {
		$translate = 1;
		$OID = $self->{OID_TrafCtrl_BroadcastStatus} . '.' . $port;
	} elsif ($action =~ 'MulticastStatus') {
		$translate = 1;
		$OID = $self->{OID_TrafCtrl_MulticastStatus} . '.' . $port;
	} elsif ($action =~ 'UnicastStatus') {
		$translate = 1;
		$OID = $self->{OID_TrafCtrl_UnicastStatus} . '.' . $port;
	} elsif ($action =~ 'ActionStatus') {
		$translate = 1;
		$OID = $self->{OID_TrafCtrl_ActionStatus} . '.' . $port;
	} elsif ($action =~ 'Countdown') {
		$OID = $self->{OID_TrafCtrl_Countdown} . '.' . $port;
	} elsif ($action =~ 'Interval') {
		$OID = $self->{OID_TrafCtrl_Interval} . '.' . $port;
	} elsif ($action =~ 'BroadcastThreshold') {
		$OID = $self->{OID_TrafCtrl_BroadcastThreshold} . '.' . $port;
	} elsif ($action =~ 'MulticastThreshold') {
		$OID = $self->{OID_TrafCtrl_MulticastThreshold} . '.' . $port;
	} elsif ($action =~ 'UnicastThreshold') {
		$OID = $self->{OID_TrafCtrl_UnicastThreshold} . '.' . $port;
	} else {
		die '(internal)DLink::SNMP->_getTrafCtrl: wrong $action=' . $action;
	}
	
	if (!$OID) {
		return 'not_supported';
	}
	
	if ($translate) {
		return $self->_translate($action, $self->_snmpget($OID));
	} else {
		return $self->_snmpget($OID);
	}
}

=head3 getTrafCtrl...

=begin html

Список функций, возвращающих информацию о настройках Traffic Control.

=end html

=head4 getTrafCtrlBroadcastStatus

=head4 getTrafCtrlMulticastStatus

=head4 getTrafCtrlUnicastStatus

=begin html

Возвращают наличие/отсутствие реакции (<span class="code">enabled, disabled</span>)
Traffic Control на указанном порту для broadcast, multicast и unicast трафика 
соответственно. В качестве входящего параметра указывается номер порта.

<p class="code">print $dlink->getTrafCtrlBroadcastStatus(5);
<span class="code-comment"># enabled</span><br/>
print $dlink->getTrafCtrlUnicastStatus(25);
<span class="code-comment"># disabled</span>
</p>

=end html

=cut

sub getTrafCtrlBroadcastStatus {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafCtrl('BroadcastStatus', $port);
}

sub getTrafCtrlMulticastStatus {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafCtrl('MulticastStatus', $port);
}

sub getTrafCtrlUnicastStatus {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafCtrl('UnicastStatus', $port);
}

=head4 getTrafCtrlActionStatus

=begin html

Возвращает тип реакции (<span class="code">shutdown, drop</span>) Traffic Control 
на указанном порту.

=end html

=cut

sub getTrafCtrlActionStatus {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafCtrl('ActionStatus', $port);
}

=head4 getTrafCtrlBroadcastThreshold

=head4 getTrafCtrlBroadcastThreshold

=head4 getTrafCtrlBroadcastThreshold

=begin html

Возвращает граничное количество пакетов в секунду для срабатывания Traffic Control
на указанном порту для broadcast, multicast и unicast трафика соответственно.

=end html

=cut

sub getTrafCtrlBroadcastThreshold {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafCtrl('BroadcastThreshold', $port);
}

sub getTrafCtrlMulticastThreshold {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafCtrl('MulticastThreshold', $port);
}

sub getTrafCtrlUnicastThreshold {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafCtrl('UnicastThreshold', $port);
}

=head4 getTrafCtrlCountdown

=begin html

Возвращает настройку Countdown в секундах для Traffic Control на указанном порту.
Это время, выделенное на принятие решения по блокировке порта.

=end html

=cut

sub getTrafCtrlCountdown {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafCtrl('Countdown', $port);
}

=head4 getTrafCtrlInterval

=begin html

Возвращает настройку Interval в минутах для Traffic Control на указанном порту.
Если Traffic Control на порту настроен в режиме Shutdown и шторм на порту за это
время не прекратился, порт переходит в состояние shutdown forever и
может быть включен обратно только вручную.

=end html

=cut

sub getTrafCtrlInterval {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafCtrl('Interval', $port);
}

#
#	Syslog
#

sub _getSyslog {
	my $self = shift;
	my $action = shift;
	my $id = shift;
	my $is_ip;
	my $translate = 1;
	my $id_needed = 1;
	my $OID;
	
	if ($action =~ 'List') {
		$OID = $self->{OID_Syslog_HostIP};
		my @buf = $self->_snmpwalk($OID);
		my @result;
		
		foreach my $entry(@buf) {
			my ($key, $ip) = each %{$entry};
			$key =~ s/$OID.//;
			push @result, $key;
		}
		
		return @result;
	}

	if ($action =~ 'IP') {
		$is_ip = 1;
		$OID = $self->{OID_Syslog_HostIP} . '.' . $id;
		$translate = 0;
	} elsif ($action =~ 'Facility') {
		$OID = $self->{OID_Syslog_Facility} . '.' . $id;
	} elsif ($action =~ 'Severity') {
		$OID = $self->{OID_Syslog_Severity} . '.' . $id;
	} elsif ($action =~ 'ServerState') {
		$OID = $self->{OID_Syslog_ServerState} . '.' . $id;
	} elsif ($action eq 'State') {
		$OID = $self->{OID_Syslog_State};
		$id_needed = 0;
	} else {
		die '(internal)DLink::SNMP->_getSyslog: wrong $action=' . $action;
	}
		
	if ((not defined $id) and ($id_needed)) {
		die 'DLink::SNMP->getSyslog' . $action . ': no id specified';
	}
	
	if ($translate) {
		return $self->_translate('Syslog' . $action, $self->_snmpget($OID));
	} 
	
	if ($is_ip) {
		return $self->_normalize_ip($self->_snmpget($OID));
	}
	
	return $self->_snmpget($OID);
}

=head3 getSyslog...

=begin html

Список функций для получения информации о настройках Syslog.

=end html

=head4 getSyslogList

=begin html

Возвращает список индексов настроенных Syslog серверов.

=end html

=cut

sub getSyslogList {
	my $self = shift;
	return $self->_getSyslog('List');
}

=head4 getSyslogIP

=begin html

Возвращает IP адрес Syslog сервера с указанным индексом.

=end html

=cut

sub getSyslogIP {
	my $self = shift;
	my $id = shift;
	return $self->_getSyslog('IP', $id);
}

=head4 getSyslogFacility

=begin html

Возвращает Facility (<span class="code">local0, local1, local2, local3,
local4, local5, local6, local7</span>) Syslog сервера с указанным индексом.

=end html

=cut

sub getSyslogFacility {
	my $self = shift;
	my $id = shift;
	return $self->_getSyslog('Facility', $id);
}

=head4 getSyslogSeverity

=begin html

Возвращает минимальную категорию событий (<span class="code">all, warn, info,
emergency, alert, critical, error, notice, debug</span>), которые будут отправлены 
на Syslog сервер с указанным индексом.

=end html

=cut

sub getSyslogSeverity {
	my $self = shift;
	my $id = shift;
	return $self->_getSyslog('Severity', $id);
}

=head4 getSyslogServerState

=begin html

Возвращает состояние (<span class="code">enabled, disabled</span>) Syslog сервера
с указанным индексом.

=end html

=cut

sub getSyslogServerState {
	my $self = shift;
	my $id = shift;
	return $self->_getSyslog('ServerState', $id);
}

=head4 getSyslogState

=begin html

Возвращает глобальную настройку Syslog (<span class="code">enabled, disabled</span>).

=end html

=cut

sub getSyslogState {
	my $self = shift;
	return $self->_getSyslog('State');
}

#
#	Other
#

sub getMgmtVLAN {
	my $self = shift;
	return $self->{mgmtVLAN};
}

sub getTelnetState {
	my $self = shift;
	my $result = $self->{OID_TelnetState} ? $self->_translate('TelnetState', $self->_snmpget($self->{OID_TelnetState})) : 'not_supported';
	return $result;
}

sub getWebState {
	my $self = shift;
	my $result = $self->{OID_WebState} ? $self->_translate('WebState', $self->_snmpget($self->{OID_WebState})) : 'not_supported';
	return $result;
}

sub getTelnetPort {
	my $self = shift;
	my $result = $self->{OID_TelnetPort} ? $self->_snmpget($self->{OID_TelnetPort}) : 'not_supported';
	return $result;
}

sub getWebPort {
	my $self = shift;
	my $result = $self->{OID_WebPort} ? $self->_snmpget($self->{OID_WebPort}) : 'not_supported';
	return $result;
}

=head3 getUptime

=begin html

Возвращает строку со временем, прошедшим с момента запуска коммутатора.
<p class="code">print $dlink->getUptime;<span class="code-comment">
#21 hours, 00:41.23</span></p>

=end html

=cut

sub getUptime {
	my $self = shift;
	return $self->_snmpget($OID_Uptime);
}

=head3 getCurrentTime

=begin html

Возвращает строку с текущим временем на устройстве.
<p class="code">print $dlink->getCurrentTime;<span class="code-comment">
# 7 Apr 2015 11:48:9</span></p>

=end html

=cut

sub getCurrentTime {
	my $self = shift;
	return $self->_snmpget($OID_DLink_CurrentTime);
}

=head3 getPortByFDB

=begin html

Возвращает номер порта, на котором изучен указанный MAC-адрес. Если MAC-адрес не
найден в таблице FBD, возвращает 0.<br/><i>Важно! Приемлемая нотация MAC-адреса:
00-11-22-33-44-55<br/>Важно! Может потребовать много времени для выполнения в
зависимости от количества записей в таблице FDB.</i>

=end html

=cut

sub getPortByFDB {
	my $self = shift;
	my $mac = shift;
	my $_vlan = shift;
	my $result;
	
	my $binmac;
	my @buf = split /-/, $mac;
	foreach my $octet(@buf) {
		$binmac = $binmac . hex('0x'.$octet) . '.';
	}
	$binmac =~ s/\.$//;
	
	my $OID = '1.3.6.1.2.1.17.7.1.2.2.1.2';
	
	if (!$_vlan) {
		my @vlans = $self->getVLANList;
		
		foreach my $vlan(@vlans) {
			my $buf = $self->_snmpget($OID . '.' . $vlan . '.' . $binmac);
			
			if ($buf !~ 'noSuch') {
				$result = $buf;
			}
			
		}
	} else {
		$result = $self->_snmpget($OID . '.' . $_vlan . '.' . $binmac);
	}
	
	if ($result =~ 'noSuch') {
		return 0;
	}
	
	if (($result > $self->{unit_ports}) and ($self->{stackable})) {
		my $unit = int($result / $self->{unit_portcount}) + 1;
		my $port = $result % $self->{unit_portcount};
		return $unit . ':' . $port;
	}
	
	return $result;
}

=head3 getFDBOnPort

=begin html

Возвращает список MAC-адресов, изученных на указанном порту.<br/><i>Важно! Может
потребовать много времени для выполнения в зависимости от количества записей в 
таблице FDB.</i>

=end html

=cut

sub getFDBOnPort {
	my $self = shift;
	my $port = shift;
	my $OID = '1.3.6.1.2.1.17.7.1.2.2.1.2';
	$port = $self->_checkPort($port);
	
	if (!$port) {
		die 'DLink::SNMP->getFDBOnPort: ' . $self->_OOR($port);
	}
	
	my @vlans = $self->getVLANList;
	my @fdb;
	
	foreach my $vlan(@vlans) {
		my $vlan_fdb_OID = $OID . '.' . $vlan;
		my @buf = $self->_snmpwalk($vlan_fdb_OID);
		
		foreach my $entry(@buf) {
			my ($key, $val) = each %{$entry};
			
			if ($val == $port) {
				$key =~ s/$vlan_fdb_OID\.//;
				my @octets = split /\./, $key;
				my $mac;
				foreach my $octet(@octets) {
					my $out = sprintf('%02X', $octet);
					if (!$mac) {
						$mac = $out;
					} else {
						$mac = $mac . '-' . $out;
					}
				}
				
				push @fdb, $mac;
			}
		}
	}
	
	return @fdb;
}

#
#	802.1Q
#

sub _getVLAN {
	my $self = shift;
	my $action = shift;
	my $vid = shift;
	my $type = shift;
	my $untag;
	my $egress;
	my $mask;
	
	if ($action =~ 'List') {
		my @buf = $self->_snmpwalk($OID_802dot1q_egress);
		my @array;
		
		foreach my $x(@buf) {
			my ($key, $value) = each %{$x};
			$key =~ s/$OID_802dot1q_egress.//;
			push @array, $key;
		}
		
		return @array;
	}
	
	if (!$vid) {
		die 'DLink::SNMP->getVLAN' . $action . ': no VID specified';
	}
	
	$type = $type ? $type : 'interval';
	
	$untag = $self->_snmpget($OID_802dot1q_untag . '.' . $vid);
	$egress = $self->_snmpget($OID_802dot1q_egress . '.' . $vid);
	
	if ($egress =~ 'noSuchInstance') {
		return 'not_available';
	}
	
	if ($action =~ 'Untagged') {
		$mask = $untag;
	} elsif ($action =~ 'Egressed') {
		$mask = $egress;
	} elsif ($action =~ 'Tagged') {
		$mask = (hex($egress)) ^ (hex($untag)) & (hex($egress));
		$mask = sprintf("%016x", $mask);
	} else {
		die '(internal)DLink::SNMP->_getVLAN: wrong $action=' . $action;
	}
	
	if ($type =~ 'mask') {
		return $mask;
	} elsif ($type =~ 'list') {
		return $self->_portconv($mask);
	} else {
		return $self->_interval($self->_portconv($mask));
	}	
}

=head3 getVLAN...

=begin html

Список функций для получения информации о настройках IEEE 802.1Q VLAN на устройстве.

=end html

=head4 getVLANList

=begin html

Возвращает список номеров VLAN, настроенных на устройстве.

<p class="code">@vlans = $dlink->getVLANList;<br/>
foreach my $vlan(@vlans) {<br/>
<span class="tab">print $vlan, "\n";</span><br/>
}<br/><br/>
<span class="code-comment">1</span><br/>
<span class="code-comment">46</span><br/>
<span class="code-comment">934</span></p>

=end html

=cut

sub getVLANList {
	my $self = shift;
	return $self->_getVLAN('List');
}

=head4 getVLANUntaggedMask

=head4 getVLANUntaggedPorts

=head4 getVLANUntaggedInterval

=head4 getVLANTaggedMask

=head4 getVLANTaggedPorts

=head4 getVLANTaggedInterval

=head4 getVLANEgressedMask

=head4 getVLANEgressedPorts

=head4 getVLANEgressedInterval

=begin html

Функции, возвращающие информацию о портах в указанном VLAN, имеют три формата вывода:
<p class="list">
Mask: <span class="code">FF000000</span><br/>
Ports: <span class="code">1,2,3,4,5,6,7,8</span><br/>
Interval: <span class="code">1-8</span></p>

Три типа функций:
<p class="list">
Untagged - нетегированные в указанном VLAN порты<br/>
Tagged - тегированные в указанном VLAN порты<br/>
Egressed - порты, принадлежащие указанному VLAN, вне зависимости от наличия тега
</p>

=end html

=cut

sub getVLANUntaggedMask {
	my $self = shift;
	my $vid = shift;
	return $self->_getVLAN('Untagged', $vid, 'mask');
}

sub getVLANUntaggedPorts {
	my $self = shift;
	my $vid = shift;
	return $self->_getVLAN('Untagged', $vid, 'list');
}

sub getVLANUntaggedInterval {
	my $self = shift;
	my $vid = shift;
	return $self->_getVLAN('Untagged', $vid, 'interval');
}

sub getVLANEgressedMask {
	my $self = shift;
	my $vid = shift;
	return $self->_getVLAN('Egressed', $vid, 'mask');
}

sub getVLANEgressedPorts {
	my $self = shift;
	my $vid = shift;
	return $self->_getVLAN('Egressed', $vid, 'list');
}

sub getVLANEgressedInterval {
	my $self = shift;
	my $vid = shift;
	return $self->_getVLAN('Egressed', $vid, 'interval');
}

sub getVLANTaggedMask {
	my $self = shift;
	my $vid = shift;
	return $self->_getVLAN('Tagged', $vid, 'mask');
}

sub getVLANTaggedPorts {
	my $self = shift;
	my $vid = shift;
	return $self->_getVLAN('Tagged', $vid, 'list');
}

sub getVLANTaggedInterval {
	my $self = shift;
	my $vid = shift;
	return $self->_getVLAN('Tagged', $vid, 'interval');
}

#
#	Traffic segmentation
#

sub _getTrafSeg {
	my $self = shift;
	my $port = shift;
	my $type = shift;
	
	$port = $self->_checkPort($port);
	if (!$port) {
		die 'DLink::SNMP->getTrafSeg' . $type . ': ' . $self->_OOR($port);
	}
	
	$type = $type ? $type : 'Interval';
	my $mask = $self->_snmpget($self->{OID_TrafficSegForwardPorts} . '.' . $port);
	
	if ($type =~ 'Mask') {
		return $mask;
	}
	
	if ($type =~ 'Ports') {
		return $self->_portconv($mask);
	}
	
	return $self->_interval($self->_portconv($mask));
}

=head3 getTrafSeg...

=head4 getTrafSegInterval

=head4 getTrafSegMask

=head4 getTrafSegPorts

=begin html

Список функций, возвращающих информацию об изоляции портов (Traffic Segmentation).
<p class="list">
Mask: <span class="code">FF000000</span><br/>
Ports: <span class="code">1,2,3,4,5,6,7,8</span><br/>
Interval: <span class="code">1-8</span></p>

<i>Важно! Может не работать на DGS-3100-24TG!</i>

=end html

=cut

sub getTrafSegInterval {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafSeg($port, 'Interval');
}

sub getTrafSegMask {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafSeg($port, 'Mask');
}

sub getTrafSegPorts {
	my $self = shift;
	my $port = shift;
	return $self->_getTrafSeg($port, 'Ports');
}

#
#	Filters
#

=head3 getFilterDHCPPortState

=begin html

Возвращает состояние настройки DHCP Screening (<span class="code">enabled, disabled</span>) 
на указанном порту.

=end html

=cut

sub getFilterDHCPPortState {
	my $self = shift;
	my $port = shift;
	
	$port = $self->_checkPort($port);
	if (!$port) {
		die 'DLink::SNMP->getFilterDHCPPortState: ' . $self->_OOR($port);
	}
	
	if ($self->{OID_Filter_DHCP_PortState}) {
		return $self->_translate('FilterDHCPPortState', $self->_snmpget($self->{OID_Filter_DHCP_PortState} . '.' . $port));
	} else {
		my @text = $self->_telnet_cmd('show filter dhcp_server');
		my $str = $text[2];
		chomp $str;
		$port = $self->createMask($port);
		my @buf = split / /, $str;
		my $mask = $self->createMask($buf[2]);
		
		if (hex($mask) & hex($port)) {
			return $enabled;
		} else {
			return $disabled;
		}
		
	}
	
}

=head3 getFilterNetbiosPortState

=begin html

Возвращает состояние настройки Netbios Filter (<span class="code">enabled, disabled</span>)
на указанном порту. Под фильтр попадают порты 135, 137-139, 445.

=end html

=cut

sub getFilterNetbiosPortState {
	my $self = shift;
	my $port = shift;
	
	$port = $self->_checkPort($port);
	if (!$port) {
		die 'DLink::SNMP->getFilterNetbiosPortState: ' . $self->_OOR($port);
	}
	
	my $result = $self->{FilterNetbiosTroughPCF} ? $self->_getNetbiosPCFState($port) : $self->_translate('FilterNetbiosPortState', $self->_snmpget($self->{OID_Filter_Netbios_PortState} . '.' . $port));
	return $result;
}

sub getFilterExtNetbiosPortState {
	my $self = shift;
	my $port = shift;
	
	$port = $self->_checkPort($port);	
	if (!$port) {
		die 'DLink::SNMP->getFilterExtNetbiosPortState: ' . $self->_OOR($port);
	}
	
	my $result = $self->{FilterNetbiosTroughPCF} ? $disabled : $self->_translate('FilterExtNetbiosPortState', $self->_snmpget($self->{OID_Filter_ExtNetbios_PortState} . '.' . $port));
	return $result;
}

#
# 	IGMP Multicast VLAN Groups
#

=head3 getIGMPMcastGroups

=begin html

Возвращает список интервалов адресов multicast-групп, на которые будет реагировать 
функционал IGMP Snooping на устройстве.<p class="code">
my @result = $dlink->getIGMPMcastGroups;<br/>
foreach my $x(@result) {<br/>
	<span class="tab"></span>print "$x\n";<br/>
}<br/>
<span class="code-comment"><br/>
<span class="tab"></span>224.5.1.0-224.5.1.255<br/>
<span class="tab"></span>224.5.2.0-224.5.2.255<br/>
<span class="tab"></span>224.5.3.0-224.5.3.255<br/>
<span class="tab"></span>224.5.4.0-224.5.4.255<br/>
<span class="tab"></span>224.5.5.0-224.5.5.255<br/>
<span class="tab"></span>224.5.6.0-224.5.6.255<br/>
<span class="tab"></span>224.5.7.0-224.5.7.255<br/>
<span class="tab"></span>224.5.8.0-224.5.8.255<br/>
<span class="tab"></span>224.5.9.0-224.5.9.255<br/>
<span class="tab"></span>224.5.10.0-224.5.10.255</span></p>

=end html

=cut

sub getIGMPMcastGroups {
	my $self = shift;
	my @groups;
	my $OID_from;
	my $OID_to;
	
	
	if (!$self->{IGMPMcastVLANgroupsEqualMcastFilterProfiles}) {
		$OID_from = $self->{OID_IGMP_McastVLANgroupStart};
		$OID_to = $self->{OID_IGMP_McastVLANgroupEnd};
	} else {
		$OID_from = $self->{OID_McastRange_From};
		$OID_to = $self->{OID_McastRange_To};
	}
	
	my @start = $self->_snmpwalk($OID_from);
	my @end = $self->_snmpwalk($OID_to);
	
	while (scalar @start) {
			my $buf = shift @start;
			my ($key1, $st) = each %{$buf};
			$buf = shift @end;
			my ($key2, $en) = each %{$buf};
			push @groups, $st . '-' . $en;
		}
	
	return @groups;
}

=head3 getMcastFilters

=begin html

Возвращает список хэшей с информацией о настроенных на устройстве фильтрах
multicast-групп: <span class="code">индекс => интервал адресов</span>.
<p class="code">my @result = $dlink->getMcastFilters;<br/>
foreach my $x(@result) {<br/>
<span class="tab">my ($key, $val) = each %{$x};</span><br/>
<span class="tab">print "$key - $val\n";</span><br/>
}<br/>
<span class="code-comment">DES-3526:<br/>
<span class="tab"></span>iptv1 - 224.5.1.0-224.5.1.255<br/>
<span class="tab"></span>iptv2 - 224.5.2.0-224.5.2.255<br/>
<span class="tab"></span>iptv3 - 224.5.3.0-224.5.3.255<br/>
<span class="tab"></span>iptv4 - 224.5.4.0-224.5.4.255<br/>
<span class="tab"></span>iptv5 - 224.5.5.0-224.5.5.255<br/>
<span class="tab"></span>iptv6 - 224.5.6.0-224.5.6.255<br/>
<span class="tab"></span>iptv7 - 224.5.7.0-224.5.7.255<br/>
<span class="tab"></span>iptv8 - 224.5.8.0-224.5.8.255<br/>
<span class="tab"></span>iptv9 - 224.5.9.0-224.5.9.255<br/>
<span class="tab"></span>iptv10 - 224.5.10.0-224.5.10.255<br/>
<br/></span>
<span class="code-comment">DES-3528:<br/>
<span class="tab"></span>1 - 224.5.1.0-224.5.1.255<br/>
<span class="tab"></span>2 - 224.5.2.0-224.5.2.255<br/>
<span class="tab"></span>3 - 224.5.3.0-224.5.3.255<br/>
<span class="tab"></span>4 - 224.5.4.0-224.5.4.255<br/>
<span class="tab"></span>5 - 224.5.5.0-224.5.5.255<br/>
<span class="tab"></span>6 - 224.5.6.0-224.5.6.255<br/>
<span class="tab"></span>7 - 224.5.7.0-224.5.7.255<br/>
<span class="tab"></span>8 - 224.5.8.0-224.5.8.255<br/>
<span class="tab"></span>9 - 224.5.9.0-224.5.9.255<br/>
<span class="tab"></span>10 - 224.5.10.0-224.5.10.255<br/>
</span>
</p>

=end html

=cut

sub getMcastFilters {
	my $self = shift;
	my @filters;

	if ($self->{McastFilterSNMPNameIndex}) {
		my @names = $self->_snmpwalk($self->{OID_McastRange_Name});
		#my $id;
		while (scalar @names) {
			my ($key, $name) = each %{shift @names};
			#$id++;
			my $name_id = $self->_name_to_index($name);
			my $start = $self->_snmpget($self->{OID_McastRange_From} . '.' . $name_id);
			my $end = $self->_snmpget($self->{OID_McastRange_To} . '.' . $name_id);
			push @filters, {$name => $start . '-' . $end};
		}
		return @filters;	
	}

	my @id = $self->_snmpwalk($self->{OID_McastRange_ID});
	
	if ($self->{McastFilterAddrInterval}) {
		while (scalar @id) {
			my ($key, $id) = each %{shift @id};
			my $interval = $self->_snmpget($self->{OID_McastRange_Addr} . '.' . $id);
			push @filters, {$id => $interval};
		}
	} else {
		while (scalar @id) {
			my ($key, $id) =each %{shift @id};
			my $start;
			my $end;
			
			if ($self->{McastFilterSNMPTrailingAddr}) {
				$start = $self->_snmpgetnext($self->{OID_McastRange_From} . '.' . $id);
				$end = $self->_snmpgetnext($self->{OID_McastRange_To} . '.' . $id);
			} else {
				$start = $self->_snmpget($self->{OID_McastRange_From} . '.' . $id);
				$end = $self->_snmpget($self->{OID_McastRange_To} . '.' . $id);
			}

			push @filters, {$id => $start . '-' . $end};
		}
	}
	return @filters;
}

=head3 getMcastFiltersOnPort

=begin html

Возвращает список индексов фильтров, примененных к указанному порту.<p class="code">
my @result = $dlink->getMcastFiltersOnPort(10);<br/>
foreach my $x(@result) {<br/>
	<span class="tab">print "$x\n";</span><br/>
}<br/><br/>
<span class="code-comment">Для DES-3526:<br/>
<span class="tab"></span>iptv1<br/>
<span class="tab"></span>iptv2<br/>
<span class="tab"></span>iptv4<br/>
<span class="tab"></span>iptv5<br/>
<span class="tab"></span>iptv3<br/>
</span><br/>
<span class="code-comment">Для DES-3528:<br/>
<span class="tab"></span>1<br/>
<span class="tab"></span>2<br/>
<span class="tab"></span>3<br/>
<span class="tab"></span>4<br/>
<span class="tab"></span>5<br/>
</span></p>

=end html

=cut

sub getMcastFiltersOnPort {
	my $self = shift;
	my $port = shift;
	my @result;
	
	$port = $self->_checkPort($port);
	if (!$port) {
		die 'DLink::SNMP->getMcastFiltersOnPort: ' . $self->_OOR($port);
	}
	
	my $OID = $self->{OID_McastRange_ID} ? $self->{OID_Mcast_PortRangeID} . '.' . $port : $self->{OID_Mcast_PortRangeName} . '.' . $port;
	my @buf = $self->_snmpwalk($OID);
	
	if (!@buf) {	#	fucking DES-3028
		my $buf2 = $self->_snmpget($OID);
		
		if ($buf2 =~ 'noSuch') {
			return @result;
		}
		
		@buf = split /,/, $buf2;
		
		foreach my $tile(@buf) {
			
			if ($tile =~ '-') {
				
				my @buf3 = split /-/, $tile;
				
				foreach my $piece($buf3[0]..$buf3[1]) {
					push @result, $piece;
				}
				
			} else {
				push @result, $tile;
			}
			
		}
		
	} else {
	
		while (@buf) {
			my ($key, $value) = each %{shift @buf};
			push @result, $value;
		}
	
	}
	
	return @result;
}

=head3 getMcastAccessOnPort

=begin html

Возвращает состояние настройки Limited Multicast Address Access 
(<span class="code">permit, deny</span>). Если устройство не поддерживает данную
настройку (как DES-3028, например), функция вернет <span class="code">not_supported
</span>

=end html

=cut

sub getMcastAccessOnPort {
	my $self = shift;
	my $port = shift;
	
	$port = $self->_checkPort($port);
	if (!$port) {
		die 'DLink::SNMP->getMcastAccessOnPort: ' . $self->_OOR($port);
	}
	
	if (!$self->{OID_Mcast_PortAccess}) {
		return 'not_supported';
	}
	
	return $self->_translate('McastFilterAccess', $self->_snmpget($self->{OID_Mcast_PortAccess} . '.' . $port));
}

=head3 getMcastFilterStateOnPort

=begin html

Возвращает состояние настройки Limited Multicast Address State
(<span class="code">enabled, disabled</span>).<br/>
<i>Важно! Данная настройка присутствует только у DES-3526, остальным будет возвращено
<span class="code">enabled</span></i>

=end html

=cut

sub getMcastFilterStateOnPort {
	my $self = shift;
	my $port = shift;
	
	$port = $self->_checkPort($port);
	if (!$port) {
		die 'DLink::SNMP->getMcastFilterStateOnPort: ' . $self->_OOR($port);
	}
	
	if (!$self->{OID_Mcast_PortState}) {
		return $enabled;
	}
	
	return $self->_translate('McastFilterState', $self->_snmpget($self->{OID_Mcast_PortState} . '.' . $port));
}

#
# Port statistics
#

=head3 Port statistics

=begin html

Список функций, отображающих различную информацию с счетчиков указанного порта.

=end html

=cut


sub _getPortStats {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $OID;
	
	$port = $self->_checkPort($port);
	if (!$port) {
		die 'DLink::SNMP->get' . $action . 'OnPort: ' . $self->_OOR($port);
	}
	
	if ($action =~ 'CRC') {
		$OID = $OID_FCSErrors . '.' . $port;
	} elsif ($action =~ 'Coll') {
		$OID = $OID_Collisions . '.' . $port;
	} elsif ($action =~ 'Symbol') {
		$OID = $OID_SymbolErrs . '.' . $port;
	} elsif ($action =~ 'Oversize') {
		$OID = $OID_Oversize . '.' . $port;
	} elsif ($action =~ 'Unicast') {
		$OID = $OID_RxUcast . '.' . $port;
	} elsif ($action =~ 'Multicast') {
		$OID = $OID_RxMcast . '.' . $port;
	} elsif ($action =~ 'Broadcast') {
		$OID = $OID_RxBcast . '.' . $port;
	} elsif ($action =~ 'RxOctets') {
		$OID = $OID_RxOctet . '.' . $port;
	} elsif ($action =~ 'TxOctets') {
		$OID = $OID_TxOctet . '.' . $port;
	} else {
		die '(internal)DLink::SNMP->_getPortStats: wrong $action=' . $action;
	}
	
	return $self->_snmpget($OID);
	
}

=head4 getCRConPort

=begin html

Возвращет значение счетчика CRC.

=end html

=cut

sub getCRCOnPort {
	my $self = shift;
	my $port = shift;
	return $self->_getPortStats('CRC', $port);
}

=head4 getCollOnPort

=begin html

Возвращает значение счетчика коллизий.

=end html

=cut

sub getCollOnPort {
	my $self = shift;
	my $port = shift;
	return $self->_getPortStats('Coll', $port);
}

=head4 getSymbolErrOnPort

=begin html

Возвращает значние счетчика Symbol Errors.

=end html

=cut

sub getSymbolErrOnPort {
	my $self = shift;
	my $port = shift;
	return $self->_getPortStats('SymbolErr', $port);
}

=head4 getOversizeOnPort

=begin html

Возвращает значение счетчика Oversize.

=end html

=cut

sub getOversizeOnPort {
	my $self = shift;
	my $port = shift;
	return $self->_getPortStats('Oversize', $port);
}

=head4 getUnicastOnPort

=head4 getMulticastOnPort

=head4 getBroadcastOnPort

=begin html

Возвращают значение счетчика соответственно Unicast, Multicast и Broadcast пакетов, 
прошедших через порт.

=end html

=cut

sub getUnicastOnPort {
	my $self = shift;
	my $port = shift;
	return $self->_getPortStats('Unicast', $port);
}

sub getMulticastOnPort {
	my $self = shift;
	my $port = shift;
	return $self->_getPortStats('Multicast', $port);
}

sub getBroadcastOnPort {
	my $self = shift;
	my $port = shift;
	return $self->_getPortStats('Broadcast', $port);
}

=head4 getRxOctetsOnPort

=head4 getTxOctetsOnPort

=begin html

Возвращает значение счетчика прошедшего через порт соответственно входящего и 
исходящего трафика в байтах.

=end html

=cut

sub getRxOctetsOnPort {
	my $self = shift;
	my $port = shift;
	return $self->_getPortStats('RxOctets', $port);
}

sub getTxOctetsOnPort {
	my $self = shift;
	my $port = shift;
	return $self->_getPortStats('TxOctets', $port);
}

#
# CPU util
#

=head3 getCPU...

=head4 getCPU5sec

=head4 getCPU1min

=head4 getCPU5min

Возвращает среднее значение нагрузки на CPU коммутатора в процентах за 5 секунд,
1 минуту и 5 минут соответственно.

=cut

sub getCPU5sec {
	my $self = shift;
	my $OID = $self->{OID_CPU5sec} ? $self->{OID_CPU5sec} : $OID_CPU_5sec;
	return $self->_snmpget($OID);
}

sub getCPU1min {
	my $self = shift;
	my $OID = $self->{OID_CPU1min} ? $self->{OID_CPU1min} : $OID_CPU_1min;
	return $self->_snmpget($OID);
}

sub getCPU5min {
	my $self = shift;
	my $OID = $self->{OID_CPU5min} ? $self->{OID_CPU5min} : $OID_CPU_5min;
	return $self->_snmpget($OID);
}

#
#	IGMP Info
#

=head3 getIGMPInfo...

=begin html

Список функций, возвращающих информацию о подписках IGMP Snooping на устройстве.<br/>
<i>Важно! По умолчанию информация о подписках перезапрашивается не раньше, чем
через 5 секунд с момента предыдущего запроса. Если необходимо получить акутальную
информацию о подписках за меньший интервал времени, следует установить время
жизни кэша в 0:<br/><span class="code">$dlink->{cache_igmp_ttl} = 0;</span></i>

=end html

=cut

sub _getIGMPInfoTable {
	my $self = shift;
	my $time = POSIX::strftime('%s', localtime);
	my @result;
	my $refresh;
	
	if ($self->{cache_type} ne 'igmp') {
		$refresh = 1;
	}
	
	if (($time - $self->{cache_timestamp}) > $self->{cache_igmp_ttl}) {
		$refresh = 1;
	}
	
	if ($refresh) {
		my @array = $self->_snmpwalk($self->{OID_IGMP_Info});
		foreach my $i(@array) {
			my ($key, $val) = each %{$i};
			push @result, $key;
			my $mask = $self->_portconv($val);
			push @result, $mask;
		}
		$self->{cache_timestamp} = $time;
		$self->{cache_type} = 'igmp';
		@{$self->{cache}} = @result;
	}
	
	return @{$self->{cache}};
}

sub _getIGMPInfo {
	my $self = shift;
	my $action = shift;
	my $group = shift;
	my $OID = $self->{OID_IGMP_Info} . '.' . $self->{mvr};

	if (($action eq 'Table') or ($action eq 'Groups')) {
		my @array = $self->_getIGMPInfoTable;
		my @result;
		
		while (@array){
			my $group = shift @array;
			my $ports = shift @array;
			$group =~ s/$OID//;
			$group =~ s/\.*0\.0\.0\.0\.*//;
			$group =~ s/\.*255\.255\.255\.255\.*//;
			$group =~ s/^\.//;
			$group =~ s/\.$//;
			
			if ($action eq 'Table') {
				push @result, {$group => $ports};
			} else {
				push @result, $group;
			}
		}
		
		return @result;		
	} elsif ($action eq 'GroupPorts') {
		
		if (!$group) {
			die "DLink::SNMP->getIGMPInfo" . $action . ": no group forwarded!";
		}

		if ($self->{IGMPInfoIndex} eq 'grponly') {
			$OID = $OID . '.' . $group;
		} elsif ($self->{IGMPInfoIndex} eq 'src255grp') {
			$OID = $OID . '.255.255.255.255.' . $group;
		} elsif ($self->{IGMPInfoIndex} eq 'src0grp') {
			$OID = $OID . '.0.0.0.0.' . $group;
		} elsif ($self->{IGMPInfoIndex} eq 'grpsrc0') {
			$OID = $OID . '.' . $group . '.0.0.0.0';
		}
		
		my $result = $self->_snmpget($OID);
		
		if ($result =~ 'noSuch') {
			return 0;
		}
		
		return $self->_portconv($result);	
	} else {
		die '(internal)DLink::SNMP->_getIGMPInfo: wrong $action=' . $action;
	}
}

=head4 getIGMPInfoTable

=begin html

Возвращает список хэшей с информацией о подписках в виде:<span class="code">
адрес группы => список портов.</span><p class="code">
my @result = $dlink->getIGMPInfoTable;<br/>
foreach my $x(@result) {<br/>
	<span class="tab">my ($key, $val) = each %{$x};</span><br/>
	<span class="tab">print "$key - $val\n";</span><br/>
}<br/>
<span class="code-comment"><br/>
224.5.1.11 - 0<br/>
224.5.1.18 - 0<br/>
224.5.1.104 - 0<br/>
224.5.1.112 - 26,27<br/>
224.5.1.113 - 0<br/>
224.5.1.116 - 0<br/>
</span></p>


=end html

=cut

sub getIGMPInfoTable {
	my $self = shift;
	return $self->_getIGMPInfo('Table');
}

=head4 getIGMPInfoGroups

=begin html

Возвращает список адресов групп, на которые в данный момент есть подписка на устройстве.
<p class="code">
my @result = $dlink->getIGMPInfoGroups;<br/>
foreach my $x(@result) {<br/>
<span class="tab"></span>print "$x\n";<br/>
}<br/>
<span class="code-comment"><br/>
224.5.1.11<br/>
224.5.1.18<br/>
224.5.1.104<br/>
224.5.1.112<br/>
224.5.1.113<br/>
224.5.1.116<br/>
</span></p>

=end html

=cut

sub getIGMPInfoGroups {
	my $self = shift;
	return $self->_getIGMPInfo('Groups');
}

=head4 getIGMPInfoGroupPorts

=begin html

Возвращает строчку с номерами портов, за которыми находятся подписчики на указанную 
группу. <p class="code">
my $result = $dlink->getIGMPInfoGroupPorts('224.5.1.112');<br/>
print $result;<span class="code-comment"># 26,27</span>
</p>

=end html

=cut

sub getIGMPInfoGroupPorts {
	my $self = shift;
	my $group = shift;
	return $self->_getIGMPInfo('GroupPorts', $group);
}

#
#	L3
#

=head3 L3 functions

=begin html

Список функций, применимых к L3-коммутаторам.<br/>
<i>Важно! Информация о L3-интерфейсах снимается с коммутатора только в первый раз.
Если необходимо перезапросить информацию, следует очистить значение "тип кэша":<br/>
<span class="code">$dlink->{cache_type} = '';</span>
</i>

=end html

=head4 getVLANName

=begin html

Возвращает имя VLAN по его тегу.

=end html

=cut

sub getVLANName {
	my $self = shift;
	my $tag = shift;

	# ugly bugfix!
	if ($tag == 1) {
		return "default";
	}

	if (($tag < 1) or ($tag > 4095)) {
		die "DLink::SNMP->getVLANName: invalid VLAN ID=$tag!";
	}
	
	my $result = $self->_snmpget($OID_802dot1q_name . '.' . $tag);
	$result =~ s/\x00*$//g;
	
	$result = $result ? $result : 'vlan' . $tag;
	
	return $result;
}

sub _getL3IfaceTable {
	my $self = shift;
	my @result;
	
	if ($self->{cache_type} ne 'L3Iface') {
		my @array = $self->_snmpwalk($self->{OID_L3_Iface_Name});
		foreach my $i(@array) {
			my ($key, $val) = each %{$i};
			push @result, $val;
			my $index = $self->_name_to_index($val);
			push @result, $self->_snmpget($self->{OID_L3_Iface_IP} . '.' . $index);
			push @result, $self->_snmpget($self->{OID_L3_Iface_Subnet} . '.' . $index);
			push @result, $self->_snmpget($self->{OID_L3_Iface_VLAN} . '.' . $index);
			push @result, $self->_translate('L3IfaceState', $self->_snmpget($self->{OID_L3_Iface_State} . '.' . $index));
			
		}
		@{$self->{cache}} = @result;
		$self->{cache_type} = 'L3Iface';
	}
	
	return @{$self->{cache}};	
}

sub _getL3IfaceByVLAN {
	my $self = shift;
	my $action = shift;
	my $vlan = shift;
	
	if (!$action) {
		die '(internal)DLink::SNMP->_getL3IfaceByVLAN: no #action!';
	}
	
	my $vlan_name = $self->getVLANName($vlan);
	my @table = $self->_getL3IfaceTable;
	
	while (@table) {
		my $iface_name = shift @table;
		my $ip = shift @table;			# IP
		my $subnet = shift @table;		# Subnet
		my $L3_vlan = shift @table;		# VLAN Name
		my $state = shift @table;		# State

		if ($L3_vlan eq $vlan_name) {
			
			if ($action eq 'Name') {
				return $iface_name;
			}
			
			if ($action eq 'State') {
				return $state;
			}
			
			if ($action eq 'Addr') {
				return "$ip/$subnet";
			}
			
			last;
		}
	}
	
	#die '(internal)DLink::SNMP->_getL3IfaceByVLAN: wrong $action=' . $action;
}

=head4 getL3IfaceNameByVLAN

=begin html

Возвращает имя ассоциированного L3-интерфейса по тегу VLAN.

=end html

=cut

sub getL3IfaceNameByVLAN {
	my $self = shift;
	my $vlan = shift;
	return $self->_getL3IfaceByVLAN('Name', $vlan);
}

=head4 getL3IfaceStateByVLAN

=begin html

Возвращает состояние (<span class="code">enabled, disabled</span>) ассоциированного 
L3-интерфейса по тегу VLAN.

=end html

=cut

sub getL3IfaceStateByVLAN {
	my $self = shift;
	my $vlan =shift;
	return $self->_getL3IfaceByVLAN('State', $vlan);
}

=head4 getL3IfaceAddrByVLAN

=begin html

Возвращает IP адрес ассоциированного L3-интерфейса по тегу VLAN.

=end html

=cut

sub getL3IfaceAddrByVLAN {
	my $self = shift;
	my $vlan = shift;
	return $self->_getL3IfaceByVLAN('Addr', $vlan);
}

=head4 getL3DHCPRelayByVLAN

=begin html

Возвращает состояние настройки DHCP Relay для ассоциированного L3-интерфейса по
тегу VLAN.

=end html

=cut

sub getL3DHCPRelayByVLAN {
	my $self = shift;
	my $vlan = shift;
	my $iface_name = $self->_getL3IfaceByVLAN('Name', $vlan);
	
	if (!$iface_name) {
		return $disabled;
	}
	
	my @buf = $self->_snmpwalk($self->{OID_DHCPRelay_State} . '.' . $self->_name_to_index($iface_name));
	
	if (!@buf) {
		return $disabled;
	}
	
	my ($key, $val) = each %{shift @buf};
	return $self->_translate('DHCPRelay', $val);	
}

#
#	ACL
#

=head3 getEtherACL...

=begin html

Список функций для получения информации о настройках Ethernet ACL. Во всех функциях,
относящихся к получению информации о настройках правил первым аргументом является
номер профиля ACL, вторым - номер правила в профиле.

=end html

=cut

=head4 getEtherACLList

=begin html

Возвращает список профилей Ethernet ACL.<p class="code">
my @result = $dlink->getEtherACLList;<br/>
foreach my $x(@result) {<br/>
<span class="tab"></span>print "$x\n";<br/>
}<br/><br/>
<span class="code-comment">254</span><br/>
<span class="code-comment">255</span><br/>
</p>

=end html

=cut

sub getEtherACLList {
	my $self = shift;
	my @list;
	my @buf = $self->_snmpwalk($self->{OID_EtherACL_Profile});
	my $previous;
	
	foreach my $entry(@buf) {
		my ($key, $val) = each %{$entry};
		
		if ($val != $previous) {
			push @list, $val;
		}
		
		$previous = $val;	
	}
	
	return @list;	
}

=head4 getEtherACLRuleList

=begin html

Возвращает список правил в указанном профиле ACL.<p class="code">
my @result = $dlink->getEtherACLRuleList(254);<br/>
foreach my $x(@result) {<br/>
<span class="tab"></span>print "$x\n";<br/>
}<br/>
<br/>
<span class="code-comment">1</span><br/>
<span class="code-comment">2</span><br/>
<span class="code-comment">3</span><br/>
<span class="code-comment">4</span><br/>
<span class="code-comment">5</span><br/>
</p>

=end html

=cut

sub getEtherACLRuleList {
	my $self = shift;
	my $profile_id = shift;
	
	if (!$profile_id) {
		die 'DLink::SNMP->getEtherACLRuleList: no $profile_id!';
	}
	
	my @buf = $self->_snmpwalk($self->{OID_EtherACL_RuleID} . '.' . $profile_id);
	my @list;
	
	foreach my $entry(@buf) {
		my ($key, $val) = each %{$entry};
		push @list, $val;
	}
	
	return @list;
}

=head4 getEtherACLUseEtype

=begin html

Возвращает информацию об использовании Ethertype (<span class="code">enabled,
disabled</span>) в указанном профиле Ethernet ACL.

=end html

=cut

sub getEtherACLUseEtype {
	my $self = shift;
	my $profile_id = shift;
	
	if (!$profile_id) {
		die 'DLink::SNMP->getEtherACLRuleList: no $profile_id!';
	}
	
	if ($self->{ACL_rule_per_port}) {
		my $result = $self->_normalize_mask($self->_snmpgetnext($self->{OID_EtherACL_Etype} . '.' . $profile_id));
		
		if (oct($result)) {
			return $enabled;
		} else {
			return $disabled;
		}
		
	} else {
		my $result = $self->_snmpget($self->{OID_EtherACL_UseEtype} . '.' . $profile_id);
		return $self->_translate('ACLEtherUseEtype', $result);
	}
}

=head4 getEtherACLUseMAC

=begin html

Возвращает информацию об использовании MAC (<span class="code">enabled, disabled</span>)
в указанном профиле Ethernet ACL.

=end html

=cut

sub getEtherACLUseMAC {
	my $self = shift;
	my $profile_id = shift;
	
	if (!$profile_id) {
		die 'DLink::SNMP->getEtherACLRuleList: no $profile_id!';
	}
	
		my $result = $self->_snmpget($self->{OID_EtherACL_UseMAC} . '.' . $profile_id);
		return $self->_translate('ACLEtherUseMAC', $result);
}

sub _getEtherACLRule {
	my $self = shift;
	my $action = shift;
	my $profile_id = shift;
	my $rule_id = shift;
	
	if (!$action) {
		die '(internal)DLink::SNMP->_getEtherACLRule: no $action!';
	}
	
	if (!$profile_id) {
		die 'DLink::SNMP->getEtherACLRule'. $action . ': no $profile_id!';
	}
	
	if (!$rule_id) {
		die 'DLink::SNMP->getEtherACLRule' . $action . ': no $rule_id!';
	}
	
	if ($action eq 'Etype') {
		my $result = $self->_normalize_mask($self->_snmpget($self->{OID_EtherACL_Etype} . '.' . $profile_id . '.' . $rule_id));
		$result = substr($result, 0, 6);
		return $result;
	}
	
	if ($action eq 'Port') {
		my $result = $self->_snmpget($self->{OID_EtherACL_Port} . '.' . $profile_id . '.' . $rule_id);
		return $self->_portconv($self->_normalize_mask($result));
	}
	
	if ($action eq 'Permit') {
		return $self->_translate('ACLEtherPermit', $self->_snmpget($self->{OID_EtherACL_Permit} . '.' . $profile_id . '.' . $rule_id));
	}
	
	if ($action eq 'SrcMAC') {
		return $self->_convert_mac($self->_normalize_mask($self->_snmpget($self->{OID_EtherACL_SrcMAC} . '.' . $profile_id . '.' . $rule_id)));
	}
}

=head4 getEtherACLRuleEtype

=begin html

Возвращает Ethertype, использующийся в указанном правиле указанного профиля.<p class="code">
print $dlink->getEtherACLRuleEtype(254, 3);<span class="code-comment">
# 0x8863</span></p>

=end html

=cut

sub getEtherACLRuleEtype {
	my $self = shift;
	my $profile_id = shift;
	my $rule_id = shift;
	return $self->_getEtherACLRule('Etype', $profile_id, $rule_id);
}

=head4 getEtherACLRulePort

=begin html

Возвращает строку с портами, к которым относится указанное правило.<p class="code">
print $dlink->getEtherACLRulePort(254, 1);<span class="code-comment">
1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24</span></p>

=end html

=cut

sub getEtherACLRulePort {
	my $self = shift;
	my $profile_id = shift;
	my $rule_id = shift;
	return $self->_getEtherACLRule('Port', $profile_id, $rule_id);
}

=head4 getEtherACLRulePermit

=begin html

Возвращает информацию о решении (<span class="code">permit, deny</span>) указанного
правила.

=end html

=cut

sub getEtherACLRulePermit {
	my $self = shift;
	my $profile_id = shift;
	my $rule_id = shift;
	return $self->_getEtherACLRule('Permit', $profile_id, $rule_id);
}

=head4 getEtherACLRuleSrcMAC

=begin html

Возвращает используемый в правиле MAC-адрес в нотации 00-11-22-33-44-55.

=end html

=cut

sub getEtherACLRuleSrcMAC {
	my $self = shift;
	my $profile_id = shift;
	my $rule_id = shift;
	return $self->_getEtherACLRule('SrcMAC', $profile_id, $rule_id);
}

sub getPCFProfileList {
	my $self = shift;
	my @buf = $self->_snmpwalk($self->{OID_PCF_Profile});
	my @list;
	
	foreach my $entry(@buf) {
		my ($key, $val) = each %{$entry};
		push @list, $val;
	}
	
	return @list;
} 

sub getPCFRuleList {
	my $self = shift;
	my $profile_id = shift;
	my @list;
	
	if (!$profile_id) {
		die 'DLink::SNMP->getPCFRuleList: no $profile_id!';
	}
	
	my @buf = $self->_snmpwalk($self->{OID_PCF_RuleID} . '.' . $profile_id);
	
	foreach my $entry(@buf) {
		my ($key, $val) = each %{$entry};
		push @list, $val;
	}
	
	return @list;
}

sub _getPCFRule {
	my $self = shift;
	my $action = shift;
	my $profile_id = shift;
	my $rule_id = shift;
	
	if (!$action) {
		die '(internal)DLink::SNMP->_getPCFRule: no $action!';
	}
	
	if (!$profile_id) {
		die 'DLink::SNMP->getPCFRule'. $action . ': no $profile_id!';
	}
	
	if (!$rule_id) {
		die 'DLink::SNMP->getPCFRule' . $action . ': no $rule_id!';
	}
	
	if ($action eq 'Port') {
		return $self->_portconv($self->_normalize_mask($self->_snmpget($self->{OID_PCF_Port} . '.' . $profile_id . '.' . $rule_id)));
	}
	
	if ($action eq 'Permit') {
		return $self->_translate('PCFPermit', $self->_snmpget($self->{OID_PCF_Permit} . '.' . $profile_id . '.' . $rule_id));
	}
	
	if ($action eq 'Payload') {
		my $OID = $self->{OID_PCF_Payload} . '.' . $profile_id . '.' . $rule_id;
		
		if ($self->{model} !~ '1.3.6.1.4.1.171.10.63.6') {
			$OID = $OID . '.1';							# Hello, bitch!
		}
		
		my $result = $self->_normalize_mask($self->_snmpget($OID));		
		return $result;
	}
	
}

sub getPCFRulePort {
	my $self = shift;
	my $profile_id = shift;
	my $rule_id = shift;
	return $self->_getPCFRule('Port', $profile_id, $rule_id);
}

sub getPCFRulePermit {
	my $self = shift;
	my $profile_id = shift;
	my $rule_id = shift;
	return $self->_getPCFRule('Permit', $profile_id, $rule_id);
}

sub getPCFRulePayload {
	my $self = shift;
	my $profile_id = shift;
	my $rule_id = shift;
	return $self->_getPCFRule('Payload', $profile_id, $rule_id);
}

sub _getNetbiosPCFState {
	my $self = shift;
	my $port = shift;
	
	my $_087;
	my $_089;
	my $_08a;
	my $_08b;
	my $_1bd;
	
	my @pcf = $self->getPCFProfileList;
	
	foreach my $profile(@pcf) {
		my @rules = $self->getPCFRuleList($profile);
		
		foreach my $rule(@rules) {
			my $state = $self->getPCFRulePermit($profile, $rule);
		
			if ($state eq $permit) {
				next;
			}
			
			my $ports = $self->getPCFRulePort($profile, $rule);
			
			if (!(($ports =~ "^$port\,") or ($ports =~ "\,$port\,") or ($ports =~ "\,$port\$"))) {
				next;
			}
			
			my $payload = $self->getPCFRulePayload($profile, $rule);
			
			$payload =~ s/0*$//g;
			
			if ($payload eq '0x0087') {
				$_087 = 1;
			} elsif ($payload eq '0x0089') {
				$_089 = 1;
			} elsif ($payload eq '0x008a') {
				$_08a = 1;
			} elsif ($payload eq '0x008b') {
				$_08b = 1;
			} elsif ($payload eq '0x01bd') {
				$_1bd = 1;
			}
			
		}
	}
	
	if ($_087 and $_089 and $_08a and $_08b and $_1bd) {
		return $enabled;
	} else {
		return $disabled;
	}
	
}

#
#	Safeguard
#

=head3 getSafeguard...

=begin html

Список функций для получения информации о настройках Safeguard Engine.

=end html

=head4 getSafeguardAdminState

=begin html

Возвращает административное состояние (<span class="code">enabled, disabled</span>)
Safeguard Engine.

=end html

=cut

sub getSafeguardAdminState {
	my $self = shift;
	return $self->_translate('SafeguardGlobalState', $self->_snmpget($self->{OID_SafeguardGlobalState}));
}

=head4 getSafeguardMode

=begin html

Возвращает настройку режима (<span class="code">strict, fuzzy</span>) Safeguard
Engine.

=end html

=cut

sub getSafeguardMode {
	my $self = shift;
	return $self->_translate('SafeguardMode', $self->_snmpget($self->{OID_SafeguardMode}));
}

=head4 getSafeguardOperStatus

=begin html

Возвращает текущее состояние (<span class="code">normal, exhausted</span>) Safeguard
Engine.

=end html

=cut

sub getSafeguardOperStatus {
	my $self = shift;
	return $self->_translate('SafeguardStatus', $self->_snmpget($self->{OID_SafeguardStatus}));
}

=head4 getSafeguardTrap

=begin html

Возвращает состояние настройки (<span class="code">enabled, disabled</span>)
Safeguard Engine SNMP Trap.

=end html

=cut

sub getSafeguardTrap {
	my $self = shift;
	return $self->_translate('SafeguardTrap', $self->_snmpget($self->{OID_SafeguardTrap}));
}

=head4 getSafeguardRisingThreshold

=begin html

Возвращает настройку верхнего порога нагрузки на CPU для перехода Safeguard
Engine в режим exhausted.

=end html

=cut

sub getSafeguardRisingThreshold {
	my $self = shift;
	return $self->_snmpget($self->{OID_SafeguardRisingThreshold});
}

=head4 getSafeguardFallingThreshold

=begin html

Возвращает настройку нижнего порога нагрузки на CPU для перехода Safeguard
Engine в режим normal.

=end html

=cut

sub getSafeguardFallingThreshold {
	my $self = shift;
	return $self->_snmpget($self->{OID_SafeguardFallingThreshold});
}

#################################################
#################################################
#################################################

sub getIndexFromArray {
	my $entry = shift;
	my @array = @_;
	my $index = 0;
	
	foreach my $x (@array) {
		
		if ($x eq $entry) {
			return $index;
		}
		
		$index++;
	}
	
}

#
#	Port
#

=head3 setPort...

=begin html

Список функций для управления настройками портов. Во всех случаях используются три
аргумента - номер порта, соотвествующая настройка и опционально тип интерфейса:
<span class="code">fiber, copper</span>. В отличие от функций <span class="code">getPort...
</span>тип интерфейса <span class="code">all</span> не поддерживается.

=end html

=cut

sub _setPort {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $value = shift;
	my $type = shift;
	my $index;
	my $OID_copper;
	my $OID_fiber;
	my $OID;
	
	$port = $self->_checkPort($port);
	
	if (!$action) {
		die '(internal)DLink::SNMP->_setPort: no $action!';
	}
	
	if (!$port) {
		die 'DLink::SNMP->_setPort: ' . $self->_OOR($port);
	}
	
	if ($self->{custom_port_functions}) {
		return $self->_setPortCustom($action, $port, $value);
	}
	
	if ($action eq 'State') {
		$OID = $self->{OID_PortAdminState} . '.' . $port;
		$index = getIndexFromArray($value, @{$self->{str_PortAdminState}});
	} elsif ($action eq 'Nway') {
		$OID = $self->{OID_PortAdminNway} . '.' . $port;
		$index = getIndexFromArray($value, @{$self->{str_PortAdminNway}});
	} elsif ($action eq 'Description') {
		$OID = $OID_PortDescription . '.' . $port;
		return $self->{snmpv3}->set_request($OID, $t_string, $value)->{$OID};
	} else {
		die '(internal)DLink::SNMP->_setPort: invalid $action=' . $action;
	}
	
	$OID_copper = $OID . '.' . $self->{copper};
	$OID_fiber = $OID . '.' . $self->{fiber};
	
	if (!$type) {
		
		if (($self->name eq 'DES-1228/ME/B1A') and ($port > 26)) {	# dirty hack for DES-1228/ME/B1A, 'cause it's ports 27-28 are fiber only and default medium type is copper
			$OID = $OID_fiber;
		} else {
			$OID = $self->{default_medium} eq 'fiber' ? $OID_fiber : $OID_copper;
		}
		
	} else {
		$OID = $type eq 'fiber' ? $OID_fiber : $OID_copper;
	}
	
	if (!defined($index)) {
		die 'DLink::SNMP->setPort' . $action . ': invalid $value=' . $value;
	}
	
	return $self->_snmpset($OID, $t_integer, $index);
}

=head4 setPortAdminState

=begin html

Изменяет административное состояние порта (<span class="code">enabled, disabled</span>).

=end html

=cut

sub setPortAdminState {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	my $medium = shift;
	return $self->_setPort('State', $port, $state, $medium);
}

=head4 setPortAdminNway

=begin html

Изменяет административное состояние согласования скорости/дуплекса на порту
(<span class="code">auto, 10-half, 10-full, 100-half, 100-full, 1000-full...</span>).

=end html

=cut

sub setPortAdminNway {
	my $self = shift;
	my $port = shift;
	my $nway = shift;
	my $medium = shift;
	return $self->_setPort('Nway', $port, $nway, $medium);
}

=head4 setPortDescription

=begin html

Изменяет пользовательское описание порта (комментарий).

=end html

=cut

sub setPortDescription {
	my $self = shift;
	my $port = shift;
	my $description = shift;
	my $medium = shift;
	return $self->_setPort('Description', $port, $description, $medium);
}

sub _setPortCustom {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $value = shift;
	my $OID;
	
	if ($action eq 'Description') {
		$OID = $OID_PortDescription . '.' . $port;
		return $self->{snmpv3}->set_request($OID, $t_string, $value)->{$OID};
	}
	
	if (!defined($value)) {
		die 'DLink::SNMP->setPort' . $action . ': invalid $value=' . $value;
	}
	
	if ($action eq 'State') {
		my $index = $value eq $enabled ? 1 : 2;
		$OID = $self->{OID_PortAdminState} . '.' . $port;
		return $self->{snmpv3}->set_request($OID, $t_integer, $index)->{$OID};
	}
	
	if ($action eq 'NWay') {
		
		if ($value eq 'auto') {
			$OID = $self->{OID_PortAutoNegotiate} . '.' . $port;
			return $self->{snmpv3}->set_request($OID, $t_integer, 1)->{$OID};
		}
		
		my @buf = split /-/, $value;
		my $OID_speed = $self->{OID_PortAdminSpeed} . '.' . $port;
		my $OID_duplex = $self->{OID_PortAdminDuplex} . '.' . $port;
		my $speed = $buf[0] * 1000000;
		my $duplex = $buf[1] eq 'full' ? 3 : 2;
		
		my $result1 = $self->{snmpv3}->set_request($OID_speed, $t_integer, $speed);
		my $result2 = $self->{snmpv3}->set_request($OID_duplex, $t_integer, $duplex);
		if ($result1 and $result2) {
			return $value;
		} else {
			return undef;
		}
	}
}

#
#	LBD
#

=head3 setLBDState

=begin html

Изменяет глобальную настройку Loopback Detection (<span class="code">enabled,
disabled</span>).

=end html

=cut

sub setLBDState {
	my $self = shift;
	my $state = shift;
	
	if (!$state) {
		die 'DLink::SNMP->setLBDState: no $state!';
	}
	
	my $OID = $self->{OID_LBD_State};
	my $index = getIndexFromArray($state, @{$self->{str_LBD_State}});
	
	if (!defined($index)) {
		die 'DLink::SNMP->setLBDState: invalid $state=' . $state;
	}
	
	return $self->{snmpv3}->set_request($OID, $t_integer, $index)->{$OID};
}

=head3 setLBDPortState

=begin html

Изменяет настройку Loopback Detection (<span class="code">enabled, disabled</span>)
на указанном порту.

=end html

=cut

sub setLBDPortState {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	
	$port = $self->_checkPort($port);
	
	if (!$port) {
		die 'DLink::SNMP->setLBDPortState: ' . $self->_OOR($port);
	}
	
	my $index = getIndexFromArray($state, @{$self->{str_LBD_PortState}});
	my $OID = $self->{OID_LBD_PortState} . '.' . $port;
	return $self->{snmpv3}->set_request($OID, $t_integer, $index);
}

#
#	IMPB
#

=head3 setIMPB...

=begin html

Список функций для управления функционалом IP-MAC-Port Binding. Во всех функциях,
которые относятся к настройкам отдельных портов, первым аргументов всегда является 
порт, а вторым - значение настройки.

=end html

=cut

=head4 setIMPBDHCPSnooping

=begin html

Изменяет настройку состояния (<span class="code">enabled, disabled</span>) DHCP Snooping.

=end html

=cut

sub setIMPBDHCPSnooping {
	my $self = shift;
	my $state = shift;
	my $OID = $self->{OID_IMPB_DHCPSnooping};
	my $index = getIndexFromArray($state, @{$self->{str_IMPB_DHCPSnooping}});
	
	if (!defined($index)) {
		die 'DLink::SNMP->setIMPBDHCPSnooping: wrong $state=' . $state;
	}
	
	return $self->{snmpv3}->set_request($OID, $t_integer, $index);
}

sub _setIMPB {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $value = shift;
	my $OID;
	my $index;
	
	$port = $self->_checkPort($port);
	
	if (!$port) {
		die 'DLink::SNMP->setIMPB' . $action . ': ' . $self->_OOR($port);
	}
	
	if ($action eq 'PortState') {
		$OID = $self->{OID_IMPB_PortState} . '.' . $port;
				
		if ($value eq $enabled) { 
			$value = $strict;
		}
		
		$index = getIndexFromArray($value, @{$self->{str_IMPB_PortState}});
	} elsif ($action eq 'PortZeroIP') {
		$OID = $self->{OID_IMPB_ZeroIP} . '.' . $port;
		$index = getIndexFromArray($value, @{$self->{str_IMPB_ZeroIP}});
	} elsif ($action eq 'ForwardDHCPPkt') {
		$OID = $self->{OID_IMPB_ForwardDHCPPkt} . '.' . $port;
		$index = getIndexFromArray($value, @{$self->{str_IMPB_ForwardDHCPPkt}});
	} else {
		die '(internal)DLink::SNMP->_setIMPB: wrong $action=' . $action;
	}
	
	if (!defined($index)) {
		die 'DLink::SNMP->setIMPB' . $action . ': no index reference for $value=' . $value;
	}
	
	return $self->{snmpv3}->set_request($OID, $t_integer, $index);
}

=head4 setIMPBPortState

=begin html

Изменяет состояние настройки IMPB на указанном порту (<span class="code">strict,
loose, disabled</span>).

=end html

=cut

sub setIMPBPortState {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	return $self->_setIMPB('PortState', $port, $state);
}

=head4 setIMPBPortZeroIP

=begin html

Изменяет состояние настройки IMPB Allow Zero IP (<span class="code">enabled,
disabled</span>)для указанного порта.

=end html

=cut

sub setIMPBPortZeroIP {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	return $self->_setIMPB('PortZeroIP', $port, $state);
}

=head4 setIMPBForwardDHCPPkt

=begin html

Возвращает состояние настройки IMPB Forward DHCP Packet (<span class="code">enabled,
disabled</span>)для указанного порта.

=end html

=cut

sub setIMPBForwardDHCPPkt {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	return $self->_setIMPB('ForwardDHCPPkt', $port, $state);
}

=head4 createIMPBEntry

=begin html

Создает запись в таблице связок IMPB, требует три аргумента: IP, MAC и номер порта.

=end html

=cut

sub createIMPBEntry {
	my $self = shift;
	my $ip = shift;
	my $mac = shift;
	my $port = shift;
	
	$mac =~ s/://g;
	$mac =~ s/-//g;
	$mac =~ s/\.//g;
	
	push my @args, $self->{OID_IMPB_MAC} . '.' . $ip, $t_octet, _prepare_octet($mac);
	push @args, $self->{OID_IMPB_RowStatus} . '.' . $ip, $t_integer, $createAndGo;
	push @args, $self->{OID_IMPB_Port} . '.' . $ip, $t_octet, _prepare_octet($self->createMask($port));
	return $self->_snmpset(@args);
}

=head4 removeIMPBEntry

=begin html

Удаляет запись из таблицы связок IMPB. В связи с механизмом реализации IP-MAC-Port
Binding на коммутаторах компании D-Link, функция требует <b>только IP адрес</b>
из связки.

=end html

=cut

sub removeIMPBEntry {
	my $self = shift;
	my $ip = shift;
	return $self->_snmpset($self->{OID_IMPB_RowStatus} . '.' . $ip, $t_integer, $destroy);
}

=head4 clearIMPBEntries

=begin html

Очищает таблицу связок IMPB. Функция не требует аргументов.

=end html

=cut

sub clearIMPBEntries {
	my $self = shift;
	my @entries = $self->_snmpwalk($self->{OID_IMPB_IP});
	
	foreach my $entry(@entries) {
		my ($key, $val) = each %{$entry};
		$self->_snmpset($self->{OID_IMPB_RowStatus} . '.' . $val, $t_integer, $destroy);
		
		if ($self->error) {
			return undef;
		}
	}
	
	return 1;
}

=head4 removeIMPBBlockedEntry

=begin html

Удаляет запись из таблицы заблокированных связок IMPB. Требует указания VLAN, к
которому принадлежит связка, и MAC.

=end html

=cut

sub removeIMPBBlockedEntry {
	my $self = shift;
	my $vlan = shift;
	my $mac = shift;
	
	$mac =~ s/://g;
	$mac =~ s/-//g;
	$mac =~ s/\.//g;
	
	my $suffix = '.' . $vlan;
	
	while ($mac) {
		my $byte = substr($mac, 0, 2);
		$mac =~ s/$byte//;
		$byte = '0x' . $byte;
		$suffix = $suffix . '.' . hex($byte);
	}
	
	if ($self->{IMPBBlockDelete}) {
		return $self->_snmpset($self->{OID_IMPB_BlockRowStatus} . $suffix, $t_integer, $self->{IMPBBlockDelete});
	}
	
	return $self->_snmpset($self->{OID_IMPB_BlockRowStatus} . $suffix, $t_integer, $destroy);
}

=head4 clearIMPBBlockedEntries

=begin html

Очищает таблицу заблокированных IMPB связок. Функция не требует аргументов.

=end html

=cut

sub clearIMPBBlockedEntries {
	my $self = shift;
	my @entries = $self->getIMPBBlockedEntries;
	
	while (@entries) {
		my $vlan = shift @entries;
		my $mac = shift @entries;
		my $port = shift @entries;
		$self->removeIMPBBlockedEntry($vlan, $mac);
		
		if ($self->error) {
			return undef;
		}
		
	}
	
	return 1;
}

#
#	ISM VLAN
#

=head3 setISM...

=begin html

Список функций для управления IGMP Snooping Multicast VLAN.<br/>
<i>Внимание! Если устройство не поддерживает Tagged Member порты, скрипт может
аварийно завершиться при попытке назначить эти порты в ISM VLAN.</i>

=end html

=cut

sub _ISM {
	my $self = shift;
	my $action = shift;
	my $type = shift;
	my $format = shift;
	my $value = shift;
	my $OID;
	
	if ($type eq 'Member') {
		$OID = $self->{OID_ISM_VLAN_Member};
	} elsif ($type eq 'Source') {
		$OID = $self->{OID_ISM_VLAN_Source};
	} elsif ($type eq 'Tagged') {
		$OID = $self->{OID_ISM_VLAN_Tagged};
	} else {
		die '(internal)DLink::SNMP->_ISM: wrong $type=' . $type;
	}
	
	if (!$OID) {
		return 0;
	}
	
	if (!defined($value)) {
		$value = '';
	}
	
	if (($format eq 'Ports') and ($action eq 'Set')) {
		
		if ($value !~ ':') {
			$value = $self->createMask($value);
		}	# else - some sub with stack support. Not implemented yet, just stub now.
		
	}
	
	if ($action eq 'Set') {
		return $self->_setMask($OID, $value);
	} elsif ($action eq 'Add') {
		return $self->_addToMask($OID, $value);
	} elsif ($action eq 'Remove') {
		return $self->_removeFromMask($OID, $value);
	} else {
		die '(internal)DLink::SNMP->_ISM: wrong $action=' . $action;
	}
	
}

=head4 setISMMemberMask

=head4 setISMSourceMask

=head4 setISMTaggedMask

=head4 setISMMemberPorts

=head4 setISMSourcePorts

=head4 setISMTaggedPorts

=begin html

Функции задают ISM VLAN битовые маски или список портов соответственно Member,
Source и Tagged Member. Формат аргумента:<p class="list">
Mask - FFFFFFC000000000<br/>
Ports - 1-26 или 1,3-5,8-12 или 1,2,3,4,5,6,7,8
</p>

=end html

=cut

sub setISMMemberMask {
	my $self = shift;
	my $mask = shift;
	return $self->_ISM('Set', 'Member', 'Mask', $mask);
}

sub setISMSourceMask {
	my $self = shift;
	my $mask = shift;
	return $self->_ISM('Set', 'Source', 'Mask', $mask);
}

sub setISMTaggedMask {
	my $self = shift;
	my $mask = shift;
	return $self->_ISM('Set', 'Tagged', 'Mask', $mask);
}

sub setISMMemberPorts {
	my $self = shift;
	my $ports = shift;
	return $self->_ISM('Set', 'Member', 'Ports', $ports);
}

sub setISMSourcePorts {
	my $self = shift;
	my $ports = shift;
	return $self->_ISM('Set', 'Source', 'Ports', $ports);
}

sub setISMTaggedPorts {
	my $self = shift;
	my $ports = shift;
	return $self->_ISM('Set', 'Tagged', 'Ports', $ports);
}

=head4 addISMMemberPorts

=head4 addISMSourcePorts

=head4 addISMTaggedPorts

=head4 removeISMMemberPorts

=head4 removeISMSourcePorts

=head4 removeISMTaggedPorts

=begin html

Функции для добавления/удаления соответственно Member, Source и Tagged Member 
портов.<br/>
<i>Внимание! Перед добавлением портов, убедитесь, что они уже удалены из ISM VLAN!</i>

=end html

=cut

sub addISMMemberPorts {
	my $self = shift;
	my $ports = shift;
	return $self->_ISM('Add', 'Member', 'Ports', $ports);
}

sub addISMSourcePorts {
	my $self = shift;
	my $ports = shift;
	return $self->_ISM('Add', 'Source', 'Ports', $ports);
}

sub addISMTaggedPorts {
	my $self = shift;
	my $ports = shift;
	return $self->_ISM('Add', 'Tagged', 'Ports', $ports);
}

sub removeISMMemberPorts {
	my $self = shift;
	my $ports = shift;
	return $self->_ISM('Remove', 'Member', 'Ports', $ports);
}

sub removeISMSourcePorts {
	my $self = shift;
	my $ports = shift;
	return $self->_ISM('Remove', 'Source', 'Ports', $ports);
}

sub removeISMTaggedPorts {
	my $self = shift;
	my $ports = shift;
	return $self->_ISM('Remove', 'Tagged', 'Ports', $ports);
}

=head4 setISMReplaceSrcIP

=begin html

Задает значение опции replace source IP. Для выключения опции следует передавать
аргумент <span class="code">0.0.0.0</span> 

=end html

=cut

sub setISMReplaceSrcIP {
	my $self = shift;
	my $ip = shift;
	my $OID_rpl_type = $self->{OID_ISM_VLAN_ReplaceSrcIPType};
	my $type = $t_ipaddr;
	
	if ($OID_rpl_type) {
		$self->_snmpset($OID_rpl_type, $t_integer, 1);
		$type = $t_octet;	#	All, except of DES-3526
	}
	
	if ($self->{model} eq '1.3.6.1.4.1.171.10.105.1') {
		return $self->_snmpset($self->{OID_ISM_VLAN_ReplaceSrcIP}, Net::SNMP::OCTET_STRING, $ip);
	}
	
	if ($self->{model} !~ '1.3.6.1.4.1.171.10.113.[36].1') {
		return $self->_snmpset($self->{OID_ISM_VLAN_ReplaceSrcIP}, Net::SNMP::IPADDRESS, $ip);
	}

	my @buf = split /\./, $ip;
	my $str;
	
	foreach my $octet(@buf) {
		$str = $str . sprintf('%02X', $octet);
	}
	
	return $self->_snmpset($self->{OID_ISM_VLAN_ReplaceSrcIP}, Net::SNMP::OCTET_STRING, _prepare_octet($str));
}

=head4 setISMRemap

=begin html

Задает значение опции Remap priority (<span class="code">0-7</span>).

=end html

=cut

sub setISMRemap {
	my $self = shift;
	my $priority = shift;
	
	return $self->_snmpset($self->{OID_ISM_VLAN_Remap}, $t_integer, $priority);
}

=head4 setISMReplace

=begin html

Задает значение опции Replace priority (<span class="code">enabled, disabled</span>).

=end html

=cut

sub setISMReplace {
	my $self = shift;
	my $replace = getIndexFromArray(shift, @{$self->{str_ISM_VLAN_Replace}});
	
	return $self->_snmpset($self->{OID_ISM_VLAN_Replace}, $t_integer, $replace);
}

=head4 createISMVLAN

=begin html

Создает IGMP Snooping Multicast VLAN с указанным именем.<br/>
<i>Внимание! Тег для ISM VLAN задается при инициализации устройства и равен по
умолчанию 24. Если нужно создать ISM VLAN с другим тегом, это нужно учитывать при
вызове конструктора <span class="code">new</span>.
</i>

=end html

=cut

sub createISMVLAN {
	my $self = shift;
	my $name = shift;
	
	if ($self->{ISM_full_creation}) {
		push my @args, $self->{OID_ISM_VLAN_Name}, $t_octet, $name;
		push @args, $self->{OID_ISM_VLAN_Source}, $t_octet, _prepare_octet('0'x$self->{mask_size});
		push @args, $self->{OID_ISM_VLAN_Member}, $t_octet, _prepare_octet('0'x$self->{mask_size});
		push @args, $self->{OID_ISM_VLAN_RowStatus}, $t_integer, $createAndGo;
		return $self->_snmpset(@args);
	}
	
	push my @args, $self->{OID_ISM_VLAN_Name}, $t_octet, $name;
	push @args, $self->{OID_ISM_VLAN_RowStatus}, $t_integer, $createAndGo;
	push @args, $self->{OID_ISM_VLAN_State}, $t_integer, getIndexFromArray($enabled, @{$self->{str_ISM_VLAN_State}});
	return $self->_snmpset(@args);
}

sub setISMState {
	my $self = shift;
	my $state = getIndexFromArray(shift, @{$self->{str_ISM_VLAN_State}});
	push my @args, $self->{OID_ISM_VLAN_State}, $t_integer, $state;
	return $self->_snmpset(@args);
}

#
#	SNTP
#

=head3 setSNTP...

=begin html

Спсиок функций для управления настройками SNTP на коммутаторе.

=end html

=head4 setSNTPState

=begin html

Изменяет глобальное состояние (<span class="code">enabled, disabled</span>)SNTP 
на устройстве.

=end html

=cut

sub setSNTPState {
	my $self = shift;
	my $state = shift;
	return $self->_snmpset($self->{OID_SNTP_State}, $t_integer, getIndexFromArray($state, @{$self->{str_SNTP_State}}));
}

=head4 setSNTPPrimary

=begin html

Устанавливает IP адрес основного SNTP сервера.

=end html

=cut

sub setSNTPPrimary {
	my $self = shift;
	my $ip = shift;
	return $self->_snmpset($self->{OID_SNTP_PrimaryIP}, $t_ipaddr, $ip);
}

=head4 setSNTPSecondary

=begin html

Устанавливает IP адрес вторичного SNTP сервера.

=end html

=cut

sub setSNTPSecondary {
	my $self = shift;
	my $ip = shift;
	return $self->_snmpset($self->{OID_SNTP_SecondaryIP}, $t_ipaddr, $ip);
}

=head4 setSNTPPollInterval

=begin html

Задает интервал опроса SNTP серверов.

=end html

=cut

sub setSNTPPollInterval {
	my $self = shift;
	my $poll = shift;
	return $self->_snmpset($self->{OID_SNTP_PollInterval}, $t_integer, $poll);
}

#
#	IGMP
#

=head3 setIGMP...

=begin html

Список функций для управления IGMP Snooping.<br/>
<i>Важно! Скрипт может аварийно завершиться, если устройство не поддерживает тот
или иной функционал.</i>

=end html

=cut

=head4 setIGMPQuerierVersion

=begin html

Устанавливает версию протокола IGMP (<span class="code">1, 2, 3</span>).

=end html

=cut

sub setIGMPQuerierVersion {
	my $self = shift;
	my $ver = shift;
	return $self->_snmpset($self->{OID_IGMP_Querier_Version}, $t_integer, $ver);
}

=head4 setIGMPDataDriven

=begin html

Устанавливает значение опции IGMP Data Driven Groups (<span class="code">enabled,
disabled</span>).

=end html

=cut

sub setIGMPDataDriven {
	my $self = shift;
	my $state = shift;
	return $self->_snmpset($self->{OID_IGMP_DataDriven}, $t_integer, getIndexFromArray($state, @{$self->{str_IGMP_DataDriven}}));
}

=head4 setIGMPDataDrivenAgedOut

=begin html

Устанавливает значение опции IGMP Data Driven Groups Aged Out 
(<span class="code">enabled, disabled</span>).

=end html

=cut

sub setIGMPDataDrivenAgedOut {
	my $self = shift;
	my $state = shift;
	return $self->_snmpset($self->{OID_IGMP_DataDriven_AgedOut}, $t_integer, getIndexFromArray($state, @{$self->{str_IGMP_DataDriven_AgedOut}}));
}

=head4 setIGMPFastLeave

=begin html

Устанавливает значение опции IGMP Fast Leave (<span class="code">enabled,
disabled</span>).

=end html

=cut

sub setIGMPFastLeave {
	my $self = shift;
	my $state = shift;
	return $self->_snmpset($self->{OID_IGMP_FastLeave}, $t_integer, getIndexFromArray($state, @{$self->{str_IGMP_FastLeave}}));
}

=head4 setIGMPReportSuppression

=begin html

Устанавливает значение опции IGMP Report Suppression (<span class="code">enabled,
disabled</span>).

=end html

=cut

sub setIGMPReportSuppression {
	my $self = shift;
	my $state = shift;
	return $self->_snmpset($self->{OID_IGMP_ReportSuppression}, $t_integer, getIndexFromArray($state, @{$self->{str_IGMP_ReportSuppression}}));
}

=head4 setIGMPAAPortState

=begin html

Изменяет настройку IGMP Access Authentication (<span class="code">enabled,
disabled</span>) на указанном порту. Первым аргументов является порт, вторым - 
значение настройки.

=end html

=cut

sub setIGMPAAPortState {
	my $self = shift;
	my $port = $self->_checkPort(shift);
	my $state = shift;
	
	if (!$port) {
		die 'DLink::SNMP->setIGMPAAPortState: ' . $self->_OOR($port);
	}
	
	return $self->_snmpset($self->{OID_IGMP_AA_PortState} . '.' . $port, $t_integer, getIndexFromArray($state, @{$self->{str_IGMP_AA_PortState}}));
}

#
#	TrafCtrl
#

=head3 setTrafCtrl...

=begin html

Список функций для управления Traffic Control. Первым параметром указывается номер
порта, вторым - состояние настройки.

=end html

=cut

sub _setTrafCtrl {
	my $self = shift;
	my $action = shift;
	my $port = $self->_checkPort(shift);
	my $value = shift;
	my $OID;
	my $val = $value;
	
	if (!$port) {
		die 'DLink::SNMP->setTrafCtrl' . $action . ':' . $self->_OOR($port);
	}
	
	if ($action eq 'BroadcastStatus') {
		$OID = $self->{OID_TrafCtrl_BroadcastStatus} . '.' . $port;
		$val = getIndexFromArray($value, @{$self->{str_TrafCtrl_BroadcastStatus}});
	} elsif ($action eq 'MulticastStatus') {
		$OID = $self->{OID_TrafCtrl_MulticastStatus} . '.' . $port;
		$val = getIndexFromArray($value, @{$self->{str_TrafCtrl_MulticastStatus}});
	} elsif ($action eq 'UnicastStatus') {
		$OID = $self->{OID_TrafCtrl_UnicastStatus} . '.' . $port;
		$val = getIndexFromArray($value, @{$self->{str_TrafCtrl_UnicastStatus}});
	} elsif ($action eq 'BroadcastThreshold') {
		$OID = $self->{OID_TrafCtrl_BroadcastThreshold} . '.' . $port;
	} elsif ($action eq 'MulticastThreshold') {
		$OID = $self->{OID_TrafCtrl_MulticastThreshold} . '.' . $port;
	} elsif ($action eq 'UnicastThreshold') {
		$OID = $self->{OID_TrafCtrl_UnicastThreshold} . '.' . $port;
	} elsif ($action eq 'ActionStatus') {
		$OID = $self->{OID_TrafCtrl_ActionStatus} . '.' . $port;
		$val = getIndexFromArray($value, @{$self->{str_TrafCtrl_ActionStatus}});
	} elsif ($action eq 'Countdown') {
		$OID = $self->{OID_TrafCtrl_Countdown} . '.' . $port;
	} elsif ($action eq 'Interval') {
		$OID = $self->{OID_TrafCtrl_Interval} . '.' . $port;
	} else {
		die '(internal)DLink::SNMP->_setTrafCtrl: wrong $action=' . $action;
	}
	
	return $self->_snmpset($OID, $t_integer, $val);
}

=head4 setTrafCtrlBroadcastStatus

=head4 setTrafCtrlMulticastStatus

=head4 setTrafCtrlUnicastStatus

=begin html

Задают наличие/отсутствие реакции (<span class="code">enabled, disabled</span>)
Traffic Control на указанном порту для broadcast, multicast и unicast трафика
соответственно. 

=end html

=cut

sub setTrafCtrlBroadcastStatus {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	return $self->_setTrafCtrl('BroadcastStatus', $port, $state);
}

sub setTrafCtrlMulticastStatus {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	return $self->_setTrafCtrl('MulticastStatus', $port, $state);
}

sub setTrafCtrlUnicastStatus {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	return $self->_setTrafCtrl('UnicastStatus', $port, $state);
}

=head4 setTrafCtrlBroadcastThreshold

=head4 setTrafCtrlMulticastThreshold

=head4 setTrafCtrlUnicastThreshold

=begin html

Задает граничное количество пакетов в секунду для срабатывания Traffic Control на
указанном порту для broadcast, multicast и unicast трафика соответственно.

=end html

=cut

sub setTrafCtrlBroadcastThreshold {
	my $self = shift;
	my $port = shift;
	my $value = shift;
	return $self->_setTrafCtrl('BroadcastThreshold', $port, $value);
}

sub setTrafCtrlMulticastThreshold {
	my $self = shift;
	my $port = shift;
	my $value = shift;
	return $self->_setTrafCtrl('MulticastThreshold', $port, $value);
}

sub setTrafCtrlUnicastThreshold {
	my $self = shift;
	my $port = shift;
	my $value = shift;
	return $self->_setTrafCtrl('UnicastThreshold', $port, $value);
}

=head4 setTrafCtrlActionStatus

=begin html

Задает тип реакции (<span class="code">shutdown, drop</span>) Traffic Control на
указанном порту.

=end html

=cut

sub setTrafCtrlActionStatus {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	return $self->_setTrafCtrl('ActionStatus', $port, $state);
}

=head4 setTrafCtrlCountdown

=begin html

Задает интервал времени в секундах для принятия решения о блокировке на указанном
порту.

=end html

=cut

sub setTrafCtrlCountdown {
	my $self = shift;
	my $port = shift;
	my $value = shift;
	return $self->_setTrafCtrl('Countdown', $port, $value);
}

=head4 setTrafCtrlInterval

=begin html

Задает значение настройки Interval в минутых для указанного порта. Если Traffic 
Control на порту настроен в режиме Shutdown и шторм на порту за это время не 
прекратился, порт переходит в состояние shutdown forever и может быть включен 
обратно только вручную.

=end html

=cut

sub setTrafCtrlInterval {
	my $self = shift;
	my $port = shift;
	my $value = shift;
	return $self->_setTrafCtrl('Interval', $port, $value);
}

#
#	Syslog
#

=head3 setSyslog...

=begin html

Список функций для управления настройками Syslog на устройстве.

=end html

=cut

=head4 createSyslogHost

=begin html

Добавляет в список Syslog host с указанными индексом и IP адресом.<br/>
<i>Внимание! Индексы не назначаются автоматически!</i>

=end html

=cut

sub createSyslogHost {
	my $self = shift;
	my $index = shift;
	my $ip = shift;
	my @args;
	
	if ($self->{OID_Syslog_AddrType}) {
		push @args, $self->{OID_Syslog_RowStatus} . '.' . $index, $t_integer, $createAndGo;
		push @args, $self->{OID_Syslog_HostIP} . '.' . $index, $t_octet, _prepare_octet(ip_to_hex($ip));
		push @args, $self->{OID_Syslog_AddrType} . '.' . $index, $t_integer, 1;		# IPv4 address type
		push @args, $self->{OID_Syslog_ServerState} . '.' . $index, $t_integer, getIndexFromArray($enabled, @{$self->{str_Syslog_ServerState}});
	} else {
		push @args, $self->{OID_Syslog_HostIP} . '.' . $index, $t_ipaddr, $ip;
		push @args, $self->{OID_Syslog_ServerState} . '.' . $index, $t_integer, getIndexFromArray($enabled, @{$self->{str_Syslog_ServerState}});
		push @args, $self->{OID_Syslog_RowStatus} . '.' . $index, $t_integer, $createAndGo;
	}
	
	return $self->_snmpset(@args);
}

=head4 removeSyslogHost

=begin html

Удаляет из списка запись о Syslog host с указанным индексом.

=end html

=cut

sub removeSyslogHost {
	my $self = shift;
	my $index = shift;
	return $self->_snmpset($self->{OID_Syslog_RowStatus} . '.' . $index, $t_integer, $destroy);
}

=head4 setSyslogState

=begin html

Изменяет глобальную настройку (<span class="code">enabled, disabled</span>) Syslog.

=end html

=cut

sub setSyslogState {
	my $self = shift;
	my $state = shift;
	return $self->_snmpset($self->{OID_Syslog_State}, $t_integer, getIndexFromArray($state, @{$self->{str_Syslog_State}}));
}

=head4 setSyslogIP

=begin html

Задает IP адрес Syslog хосту с указанным индексом.

=end html

=cut

sub setSyslogIP {
	my $self = shift;
	my $index = shift;
	my $ip = shift;
	
	if (!$self->{OID_Syslog_AddrType}) {
		return $self->_snmpset($self->{OID_Syslog_HostIP} . '.' . $index, $t_ipaddr, $ip);
	}
	
	my @octets = split /\./, $ip;
	my $octet_string;
	
	foreach my $octet(@octets) {
		
		if (!$octet_string) {
			$octet_string = sprintf('%02X', $octet);
		} else {
			$octet_string = $octet_string . sprintf('%02X', $octet);
		}
	}
	
	return $self->_snmpset($self->{OID_Syslog_AddrType} . '.' . $index, $t_integer, 1, $self->{OID_Syslog_HostIP} . '.' . $index, $t_octet, _prepare_octet($octet_string));
}

=head4 setSyslogFacility

=begin html

Задает Facility (<span class="code">local0, local1, local2, local3, local4, local5,
local6, local7</span>) Syslog хосту с указанным индексом.

=end html

=cut

sub setSyslogFacility {
	my $self = shift;
	my $index = shift;
	my $facility = shift;
	return $self->_snmpset($self->{OID_Syslog_Facility} . '.' . $index, $t_integer, getIndexFromArray($facility, @{$self->{str_Syslog_Facility}}));
}

=head4 setSyslogSeverity

=begin html

Задает минимальную категорию событий (<span class="code">all, warn, info, 
emergency, alert, critical, error, notice, debug</span>), которые будут отправлены
на Syslog сервер с указанным индексом.

=end html

=cut

sub setSyslogSeverity {
	my $self = shift;
	my $index = shift;
	my $severity = shift;
	return $self->_snmpset($self->{OID_Syslog_Severity} . '.' . $index, $t_integer, getIndexFromArray($severity, @{$self->{str_Syslog_Severity}}));
}

=head4 setSyslogServerState

=begin html

Задает состояние (<span class="code">enabled, disabled</span>) Syslog сервера с
указанным индексом.

=end html

=cut

sub setSyslogServerState {
	my $self = shift;
	my $index = shift;
	my $state = shift;
	return $self->_snmpset($self->{OID_Syslog_ServerState} . '.' . $index, $t_integer, getIndexFromArray($state, @{$self->{str_Syslog_ServerState}}));
}

#
#	VLAN
#

=head3 VLAN management

=begin html

Список функций для работы с IEEE 802.1Q VLAN. Все функции в качестве первого 
аргумента принимают тег, второй аргумент указан в соответствующих описаниях.

=end html

=cut

=head4 createVLAN

=begin html

Создает VLAN с указанным тегом и именем.

=end html

=cut

sub createVLAN {
	my $self = shift;
	my $tag = shift;
	my $name = shift;
	my @args;
	
	if (($tag > 4094) or ($tag < 1)) {
		die 'DLink::SNMP->createVLAN: wrong $tag=' . $tag;
	}
	
	$name = $name ? $name : 'vlan' . $tag;
	$name = substr($name, 0, 32);
	
	# bugfix
	if ($tag == 1) {
		$name = 'default';
	}
	# end
	
	push @args, $OID_802dot1q_name . '.' . $tag, $t_octet, $name;
	push @args, $OID_802dot1q_egress . '.' . $tag, $t_octet, '';
	push @args, $OID_802dot1q_forbidden . '.' . $tag, $t_octet, '';
	push @args, $OID_802dot1q_untag . '.' . $tag, $t_octet, '';
	push @args, $OID_802dot1q_status . '.' . $tag, $t_integer, $createAndGo;
	return $self->_snmpset(@args);
}

=head4 deleteVLAN

=begin html

Удаляет VLAN с указанным тегом.

=end html

=cut

sub deleteVLAN {
	my $self = shift;
	my $tag = shift;
	
	if (($tag > 4094) or ($tag < 1)) {
		die 'DLink::SNMP->createVLAN: wrong $tag=' . $tag;
	}
	
	my $OID1 = $OID_802dot1q_status . '.' . $tag;
	return $self->_snmpset($OID1, $t_integer, $destroy);
}

=head4 setVLANuntaggedMask

=begin html

Задает в указанном VLAN битовую маску для untagged портов.<br/>
<i>Внимание! Если в маске будут указаны порты, не являющиеся egressed в данном
VLAN, они будут добавлены в список Egressed и Untagged.</i>

=end html

=cut

sub setVLANuntaggedMask {
	my $self = shift;
	my $tag = shift;
	my $mask = shift;
	my @args;
	
	if (($tag > 4094) or ($tag < 1)) {
		die 'DLink::SNMP->setVLANuntaggedMask: wrong $tag=' . $tag;
	}
	
	my $name = $self->getVLANName($tag);
	my $old_egress = $self->_normalize_mask($self->_snmpget($OID_802dot1q_egress . '.' . $tag));
	my $old_untag = $self->_normalize_mask($self->_snmpget($OID_802dot1q_untag . '.' . $tag));
	my $tagged = $self->subtractMasks($old_egress, $old_untag);
	my $new_egress = $self->addMasks($tagged, $mask);
	
	if ($self->{archaic_802dot1q}) {
		push my @args, $OID_802dot1q_name . '.' . $tag, $t_string, $name;
		push @args, $OID_802dot1q_egress . '.' . $tag, $t_octet, _prepare_octet($old_egress);
		push @args, $OID_802dot1q_forbidden . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
		push @args, $OID_802dot1q_untag . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
		push @args, $OID_802dot1q_status . '.' . $tag, $t_integer, 1;
		push @args, $OID_802dot1q_name . '.' . $tag, $t_string, $name;
		push @args, $OID_802dot1q_egress . '.' . $tag, $t_octet, _prepare_octet($new_egress);
		push @args, $OID_802dot1q_forbidden . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
		push @args, $OID_802dot1q_untag . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
		push @args, $OID_802dot1q_status . '.' . $tag, $t_integer, 1;
		push @args, $OID_802dot1q_name . '.' . $tag, $t_string, $name;
		push @args, $OID_802dot1q_egress . '.' . $tag, $t_octet, _prepare_octet($new_egress);
		push @args, $OID_802dot1q_forbidden . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
		push @args, $OID_802dot1q_untag . '.' . $tag, $t_octet, _prepare_octet($mask);
		push @args, $OID_802dot1q_status . '.' . $tag, $t_integer, 1;
		return $self->_snmpset(@args);
	}
	
	push @args, $OID_802dot1q_name . '.' . $tag, $t_string, $name;
	push @args, $OID_802dot1q_egress . '.' . $tag, $t_octet, _prepare_octet($old_egress);
	push @args, $OID_802dot1q_forbidden . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
	push @args, $OID_802dot1q_untag . '.' . $tag, $t_octet, _prepare_octet($mask);
	push @args, $OID_802dot1q_status . '.' . $tag, $t_integer, 1;
	push @args, $OID_802dot1q_name . '.' . $tag, $t_string, $name;
	push @args, $OID_802dot1q_egress . '.' . $tag, $t_octet, _prepare_octet($tagged);
	push @args, $OID_802dot1q_forbidden . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
	push @args, $OID_802dot1q_untag . '.' . $tag, $t_octet, _prepare_octet($mask);
	push @args, $OID_802dot1q_status . '.' . $tag, $t_integer, 1;
	return $self->_snmpset(@args);
}

=head4 setVLANtaggedMask

=begin html

Задает в указанном VLAN tagged порты согласно маске.

=end html

=cut

sub setVLANtaggedMask {
	my $self = shift;
	my $tag = shift;
	my $mask = shift;
	
	if (($tag > 4094) or ($tag < 1)) {
		die 'DLink::SNMP->setVLANtaggedMask: wrong $tag=' . $tag;
	}
	
	my $name = $self->getVLANName($tag);
	my $old_egress = $self->_normalize_mask($self->_snmpget($OID_802dot1q_egress . '.' . $tag));
	my $old_untag = $self->_normalize_mask($self->_snmpget($OID_802dot1q_untag . '.' . $tag));
	my $new_egress = $self->addMasks($old_untag, $mask);
	my $new_untag = $self->subtractMasks($new_egress, $mask);
	
	push my @args, $OID_802dot1q_name . '.' . $tag, $t_string, $name;
	push @args, $OID_802dot1q_egress . '.' . $tag, $t_octet, _prepare_octet($old_egress);
	push @args, $OID_802dot1q_forbidden . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
	push @args, $OID_802dot1q_untag . '.' . $tag, $t_octet, _prepare_octet($new_untag);
	push @args, $OID_802dot1q_status . '.' . $tag, $t_integer, 1;
	push @args, $OID_802dot1q_name . '.' . $tag, $t_string, $name;
	push @args, $OID_802dot1q_egress . '.' . $tag, $t_octet, _prepare_octet($new_egress);
	push @args, $OID_802dot1q_forbidden . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
	push @args, $OID_802dot1q_untag . '.' . $tag, $t_octet, _prepare_octet($new_untag);
	push @args, $OID_802dot1q_status . '.' . $tag, $t_integer, 1;
	return $self->_snmpset(@args);
}

sub setVLANegressMask {
	my $self = shift;
	my $tag = shift;
	my $mask = shift;
	
	if (($tag > 4094) or ($tag < 1)) {
		die 'DLink::SNMP->setVLANegressMask: wrong $tag=' . $tag;
	}
	
	my $name = $self->getVLANName($tag);
	push my @step2, $OID_802dot1q_name . '.' . $tag, $t_string, $name;
	push @step2, $OID_802dot1q_egress . '.' . $tag, $t_octet, _prepare_octet($mask);
	push @step2, $OID_802dot1q_forbidden . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
	#push @step2, $OID_802dot1q_untag . '.' . $tag, $t_octet, _prepare_octet($new_untag);
	push @step2, $OID_802dot1q_status . '.' . $tag, $t_integer, 1;
	return $self->_snmpset(@step2);
}

=head4 setVLANuntaggedPorts

=begin html

Аналогично функции <span class="code">setVLANuntaggedMask</span>, но в качестве 
аргумента принимает строку с перечислением портов.

=end html

=cut

sub setVLANuntaggedPorts {
	my $self = shift;
	my $tag = shift;
	my $ports = shift;
	
	if (($tag > 4094) or ($tag < 1)) {
		die 'DLink::SNMP->setVLANuntaggedPorts: wrong $tag=' . $tag;
	}
	
	if (!$ports) {
		die 'DLink::SNMP->setVLANuntaggedPorts: no $ports!';
	}
	
	return $self->setVLANuntaggedMask($tag, $self->createMask($ports));
}

=head4 setVLANtaggedPorts

=begin html

Аналогично функции <span class="code">setVLANtaggedMask</span>, но в качестве 
аргумента принимает строку с перечислением портов.

=end html

=cut

sub setVLANtaggedPorts {
	my $self = shift;
	my $tag = shift;
	my $ports = shift;
	
	if (($tag > 4094) or ($tag < 1)) {
		die 'DLink::SNMP->setVLANtaggedPorts: wrong $tag=' . $tag;
	}
	
	if (!$ports) {
		die 'DLink::SNMP->setVLANtaggedPorts: no $ports!';
	}
	
	return $self->setVLANtaggedMask($tag, $self->createMask($ports));	
	
}

=head4 addVLANuntaggedPorts

=begin html

Добавляет untagged порт к указанному VLAN.

=end html

=cut

sub addVLANuntaggedPorts {
	my $self = shift;
	my $tag = shift;
	my $ports = shift;
	
	if (($tag > 4094) or ($tag < 1)) {
		die 'DLink::SNMP->addVLANuntaggedPorts: wrong $tag=' . $tag;
	}
	
	if (!$ports) {
		die 'DLink::SNMP->addVLANuntaggedPorts: no $ports!';
	}
	
	my $delta = $self->createMask($ports);
	my $egress_mask = $self->_normalize_mask($self->_snmpget($OID_802dot1q_egress . '.' . $tag));
	my $untag_mask = $self->_normalize_mask($self->_snmpget($OID_802dot1q_untag . '.' . $tag));
	my $new_egress = $self->addMasks($egress_mask, $delta);
	my $new_untag = $self->addMasks($untag_mask, $delta);
	return $self->setVLANuntaggedMask($tag, $new_untag);
}

=head4 addVLANtaggedPorts

=begin html

Добавляет tagged порт к указанному VLAN.

=end html

=cut

sub addVLANtaggedPorts {
	my $self = shift;
	my $tag = shift;
	my $ports = shift;
	
	if (($tag > 4094) or ($tag < 1)) {
		die 'DLink::SNMP->addVLANtaggedPorts: wrong $tag=' . $tag;
	}
	
	if (!$ports) {
		die 'DLink::SNMP->addVLANtaggedPorts: no $ports!';
	}
	
	my $delta = $self->createMask($ports);
	my $egress_mask = $self->_normalize_mask($self->_snmpget($OID_802dot1q_egress . '.' . $tag));
	my $untag_mask = $self->_normalize_mask($self->_snmpget($OID_802dot1q_untag . '.' . $tag));
	my $new_egress = $self->addMasks($egress_mask, $delta);
	my $new_untag = $self->subtractMasks($untag_mask, $delta);
	
	$self->setVLANtaggedMask($tag, $new_egress);
	return $self->setVLANuntaggedMask($tag, $new_untag);
	
}

=head4 removeVLANPorts

=begin html

Удаляет указанные порты из указанного VLAN.

=end html

=cut

sub removeVLANPorts {
	my $self = shift;
	my $tag = shift;
	my $ports = shift;
	my @args;
	
	if (($tag > 4094) or ($tag < 1)) {
		die 'DLink::SNMP->removeVLANPorts: wrong $tag=' . $tag;
	}
	
	if (!$ports) {
		die 'DLink::SNMP->removeVLANPorts: no $ports!';
	}
	
	my $delta = $self->createMask($ports);	
	my $name = $self->getVLANName($tag);
	my $egress_mask = $self->_normalize_mask($self->_snmpget($OID_802dot1q_egress . '.' . $tag));
	my $untag_mask = $self->_normalize_mask($self->_snmpget($OID_802dot1q_untag . '.' . $tag));
	my $new_egress = $self->subtractMasks($egress_mask, $delta);	
	my $new_untag = $self->subtractMasks($untag_mask, $delta);
	
	if ($self->{archaic_802dot1q}) {
		push @args, $OID_802dot1q_name . '.' . $tag, $t_string, $name;
		push @args, $OID_802dot1q_egress . '.' . $tag, $t_octet, _prepare_octet($egress_mask);
		push @args, $OID_802dot1q_forbidden . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
		push @args, $OID_802dot1q_untag . '.' . $tag, $t_octet, _prepare_octet($new_untag);
		push @args, $OID_802dot1q_status . '.' . $tag, $t_integer, 1;
		$self->_snmpset(@args);
		@args = ();
	}
	
	push @args, $OID_802dot1q_name . '.' . $tag, $t_string, $name;
	push @args, $OID_802dot1q_egress . '.' . $tag, $t_octet, _prepare_octet($new_egress);
	push @args, $OID_802dot1q_forbidden . '.' . $tag, $t_octet, _prepare_octet('0'x$self->{mask_size});
	push @args, $OID_802dot1q_untag . '.' . $tag, $t_octet, _prepare_octet($new_untag);
	push @args, $OID_802dot1q_status . '.' . $tag, $t_integer, 1;
	
	return $self->_snmpset(@args);

}

#
#	DHCP Relay
#

=head3 setDHCPRelayState

=begin html

Изменяет состояние (<span class="code">enabled, disabled</span>) DHCP Relay.

=end html

=cut

sub setDHCPRelayState {
	my $self = shift;
	my $state = shift;
	$state = getIndexFromArray($state, @{$self->{str_DHCPRelay_State}});
	return $self->_snmpset($self->{OID_DHCPRelay_State}, $t_integer, $state);
}

=head3 setDHCPLocalRelayState

=begin html

Изменяет состояние (<span class="code">enabled, disabled</span>) DHCP Local Relay.

=end html

=cut

sub setDHCPLocalRelayState {
	my $self = shift;
	my $state = shift;
	$state = getIndexFromArray($state, @{$self->{str_DHCPLocalRelay_State}});
	return $self->_snmpset($self->{OID_DHCPLocalRelay_State}, $t_integer, $state);
}

#
#	Traffic Segmentation
#

=head3 setTrafSegMask

=begin html

Задает указанному порту указанную битовую маску Traffic Segmentation.<br/>
<i>Важно! Не работает на DGS-3100 Series!</i>

=end html

=cut

sub setTrafSegMask {
	my $self = shift;
	my $port = $self->_checkPort(shift);
	my $mask = shift;
	
	if (!$port) {
		die 'DLink::SNMP->setTrafSegMask: ' . $self->_OOR($port);
	}
	
	return $self->_snmpset($self->{OID_TrafficSegForwardPorts} . '.' . $port, $t_octet, _prepare_octet($mask));
}

=head3 setTrafSegPorts

=begin html

Задает указанному порту список портов Traffic Segmentation.<br/>
<i>Важно! Не работает на DGS-3100 Series!</i>

=end html

=cut

sub setTrafSegPorts {
	my $self = shift;
	my $port = $self->_checkPort(shift);
	my $ports = shift;
	
	if (!$port) {
		die 'DLink::SNMP->setTrafSegMask: ' . $self->_OOR($port);
	}
	
	return $self->_snmpset($self->{OID_TrafficSegForwardPorts} . '.' . $port, $t_octet, _prepare_octet($self->createMask($ports)));
}

#
#	ACL
#

=head3 ACL management

=begin html

Список функций для управления Ethernet ACL. Во всех случаях первым аргументом
является номер профиля ACL.

=end html

=cut

=head4 removeACLProfile

=begin html

Удаляет заданный профиль ACL.

=end html

=cut

sub removeACLProfile {
	my $self = shift;
	my $profile = shift;
	return $self->_snmpset($self->{OID_EtherACL_Profile_RowStatus} . '.' . $profile, $t_integer, $destroy);
}

=head4 deleteACLRule

=begin html

Удаляет заданное правило в заданном профиле.

=end html

=cut

sub deleteACLRule {
	my $self = shift;
	my $profile = shift;
	my $rule = shift;
	return $self->_snmpset($self->{OID_EtherACL_Rule_RowStatus} . '.' . $profile . '.' . $rule, $t_integer, $destroy);
}

=head4 createACLProfileEtype

=begin html

Создает профиль Ethernet ACL с фильтом по Ethertype. Первый аргумент - номер профиля,
второй аргумент - имя профиля.

=end html

=cut

sub createACLProfileEtype {
	my $self = shift;
	my $profile_id = shift;
	my $profile_name = shift;
	my @args;

	if ($self->{ACLProfileHasName}) {
		push @args, $self->{OID_EtherACL_ProfileName} . '.' . $profile_id, $t_octet, $profile_name;
	}
	
	push @args, $self->{OID_EtherACL_UseEtype} . '.' . $profile_id, $t_integer, 1;
	push @args, $self->{OID_EtherACL_Profile_RowStatus} . '.' . $profile_id, $t_integer, $createAndGo;
	return $self->_snmpset(@args);
}

=head4 createACLProfileMAC

=begin html

Создает профиль Ethernet ACL с фильтром по MAC.<p class="code">
createACLProfileMAC($profile_id, $profile_name, $type, $mask, $mask2)</p>
profile_id - номер профиля ACL<br/>
profile_name - имя профиля ACL<br/>
type - тип фильтрации:<p class="list">
dst - MAC получателя<br/>
src - MAC отправителя<br/>
srcdst - фильтрация по адресам и отправителя, и получателя</p>
mask - маска для MAC отправителя<br/>
mask2 - маска для MAC получателя

=end html

=cut

sub createACLProfileMAC {
	my $self = shift;
	my $profile_id = shift;
	my $profile_name = shift;
	my $type = shift;
	my $mask = shift;
	my $mask2 = shift;
	my @args;
	
	if ($type eq 'dst') {
		$type = 2;
	} elsif ($type eq 'src') {
		$type = 3;
	} elsif ($type eq 'srcdst') {
		$type = 4;
	} else {
		die 'DLink::SNMP->createACLProfileMAC: wrong $type=' . $type;
	}
	
	$mask =~ s/[:.-]//g;
	$mask2 =~ s/[:.-]//g;
	

	if ($self->{ACLProfileHasName}) {
		push @args, $self->{OID_EtherACL_ProfileName} . '.' . $profile_id, $t_octet, $profile_name;
	}
	
		push @args, $self->{OID_EtherACL_UseMAC} . '.' . $profile_id, $t_integer, $type;
	
	if ($type == 3) {
		push @args, $self->{OID_EtherACL_Profile_SrcMACMask} . '.' . $profile_id, $t_octet, _prepare_octet($mask);
	}
	
	push @args, $self->{OID_EtherACL_Profile_RowStatus} . '.' . $profile_id, $t_integer, $createAndGo;
	return $self->_snmpset(@args);
}

=head4 addACLRuleEtype

=begin html

Создает правило в профиле Ethernet ACL с фильрацией по Ethertype:<p class="code">
addACLRuleEtype($profile_id, $access_id, $etype, $action, $port)</p>
profile_id - номер профиля<br/>
access_id - номер правила<br/>
etype - Ethertype в формате <span class="code">0x0000</span><br/>
action - действие правила (<span class="code">permit, deny</span>)<br/>
port - номер порта.

=end html

=cut

sub addACLRuleEtype {
	my $self = shift;
	my $profile_id = shift;
	my $access_id = shift;
	my $etype = shift;
	my $action = shift;
	my $port = shift;
	my @args;
	
	$action = $action eq $permit ? 2 : 1;
	
	push @args, $self->{OID_EtherACL_Etype} . '.' . $profile_id . '.' . $access_id, $t_octet, _prepare_octet($etype);
	push @args, $self->{OID_EtherACL_Permit} . '.' . $profile_id . '.' . $access_id, $t_integer, $action;
	push @args, $self->{OID_EtherACL_Port} . '.' . $profile_id . '.' . $access_id, $t_octet, _prepare_octet($self->createMask($port));
	push @args, $self->{OID_EtherACL_Rule_RowStatus} . '.' . $profile_id . '.' . $access_id, $t_integer, $createAndGo;
	return $self->_snmpset(@args);
}

=head4 addACLRuleMAC

=begin html

Создает правило в профиле Ethernet ACL с фильтрацией по MAC:<p class="code>
addACLRuleMAC($profile_id, $access_id, $action, $port, $type, $mask, $mac, 
$mask2, $mac2)</p>
profile_id - номер профиля<br/>
access_id - номер правила<br/>
action - действие правила (<span class="code">permit, deny</span>)<br/>
port - номер порта<br/>
type - тип фильтрации:<p class="list">
dst - MAC получателя<br/>
src - MAC отправителя<br/>
srcdst - фильтрация по адресам и отправителя, и получателя</p>
mask - маска для MAC отправителя<br/>
mac - MAC отправителя<br/>
mask2 - маска для MAC получателя<br/>
mac2 - MAC получателя<br/><br/>
Все MAC адреса можно писать в любой из нижеуказанных нотаций:<p class="list">
001122334455<br/>
00-11-22-33-44-55<br/>
00:11:22:33:44:55<br/>
0011.2233.4455</p>

=end html

=cut

sub addACLRuleMAC {
	my $self = shift;
	my $profile_id = shift;
	my $access_id = shift;
	my $action = shift;
	my $port = shift;
	my $type = shift;
	my $mask = shift;
	my $mac = shift;
	my $mask2 = shift;		#	Reserved for
	my $mac2 = shift;		#	'srcdst' type
	my @args;
	
	if ($type eq 'src') {
		$type = 3;
	}
	
	$mask =~ s/[:.-]//g;
	$mac =~ s/[:.-]//g;
	$mask2 =~ s/[:.-]//g;
	$mac2 =~ s/[:.-]//g;
	
	$action = $action eq $permit ? 2 : 1;
	$mac2 = $mac2 ? $mac2 : '000000000000';
	
	if ($self->{OID_EtherACL_SrcMACMask}) {		# 	DES-3028!
		push @args, $self->{OID_EtherACL_SrcMACMask} . '.' . $profile_id . '.' . $access_id, $t_octet, _prepare_octet($mask);
	}
	
	push @args, $self->{OID_EtherACL_SrcMAC} . '.' . $profile_id . '.' . $access_id, $t_octet, _prepare_octet($mac);
	push @args, $self->{OID_EtherACL_Port} . '.' . $profile_id . '.' . $access_id, $t_octet, _prepare_octet($self->createMask($port));
	push @args, $self->{OID_EtherACL_Permit} . '.' . $profile_id . '.' . $access_id, $t_integer, $action;
	push @args, $self->{OID_EtherACL_Rule_RowStatus} . '.' . $profile_id . '.' . $access_id, $t_integer, $createAndGo;
	return $self->_snmpset(@args);
}

sub createPCFNetbiosProfile {
	my $self = shift;
	my $profile_id = shift;
	my @args;
	
	if ($self->{OID_PCF_ProfileOffset}) {
		push @args, $self->{OID_PCF_ProfileOffset} . '.' . $profile_id, $t_octet, _prepare_octet($self->{PCF_Netbios_Mask});
		push @args, $self->{OID_PCF_Profile_RowStatus} . '.' . $profile_id, $t_integer, $createAndGo;
		return $self->_snmpset(@args);
	}
	
	push @args, $self->{OID_PCF_Offset_Bytes} . '.' . $profile_id . '.1', $t_integer, 2;
	push @args, $self->{OID_PCF_Offset_Mask} . '.' . $profile_id . '.1', $t_octet, _prepare_octet('ffff');
	push @args, $self->{OID_PCF_Offset_RowStatus} . '.' . $profile_id . '.1', $t_integer, $createAndGo;
	return $self->_snmpset(@args);
	
}

sub removePCFProfile {
	my $self = shift;
	my $profile_id = shift;
	return $self->_snmpset($self->{OID_PCF_Profile_RowStatus} . '.' . $profile_id, $t_integer, $destroy);
}

sub addPCFNetbiosRule {
	my $self = shift;
	my $profile_id = shift;
	my $access_id = shift;
	my $payload = shift;
	my $port = shift;
	my @args;
	
	if ($self->{OID_PCF_RuleOffset_RowStatus}) {
		push @args, $self->{OID_PCF_Payload} . '.' . $profile_id . '.' . $access_id . '.1', $t_octet, _prepare_octet($payload);
		push @args, $self->{OID_PCF_RuleOffset_RowStatus} . '.' . $profile_id . '.' . $access_id . '.1' , $t_integer, 4;
		push @args, $self->{OID_PCF_Permit} . '.' . $profile_id . '.' . $access_id, $t_integer, getIndexFromArray($deny, @{$self->{str_PCF_Permit}});
		push @args, $self->{OID_PCF_Port} . '.' . $profile_id . '.' . $access_id, $t_octet, _prepare_octet($self->createMask($port));
		push @args, $self->{OID_PCF_Rule_RowStatus} . '.' . $profile_id . '.' . $access_id, $t_integer, $createAndGo;
		return $self->_snmpset(@args);
	}
	
	$payload = $payload . '0000';
	push @args, $self->{OID_PCF_Offset1} . '.' . $profile_id . '.' . $access_id, $t_integer, 40;
	push @args, $self->{OID_PCF_Payload} . '.' . $profile_id . '.' . $access_id, $t_octet, _prepare_octet($payload);
	push @args, $self->{OID_PCF_Permit} . '.' . $profile_id . '.' . $access_id, $t_integer, getIndexFromArray($deny, @{$self->{str_PCF_Permit}});
	push @args, $self->{OID_PCF_Port} . '.' . $profile_id . '.' . $access_id, $t_octet, _prepare_octet($self->createMask($port));
	push @args, $self->{OID_PCF_Rule_RowStatus} . '.' . $profile_id . '.' . $access_id, $t_integer, $createAndGo;
	return $self->_snmpset(@args);
}

sub deletePCFRule {
	my $self = shift;
	my $profile_id = shift;
	my $access_id = shift;
	return $self->_snmpset($self->{OID_PCF_Rule_RowStatus} . '.' . $profile_id . '.' . $access_id, $t_integer, $destroy);
}

#
#	Filter
#

=head3 setFilterDHCPPortState

=begin html

Изменяет состояние (<span class="code">enabled, disabled</span>) фильтра DHCP 
на указанном порту.

=end html

=cut

sub setFilterDHCPPortState {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	
	if (!$self->_checkPort($port)) {
		die 'DLink::SNMP->setFilterDHCPPortState: ' . $self->_OOR($port);
	} else {
		$port = $self->_checkPort($port);
	}	
	
	if ($self->{OID_Filter_DHCP_PortState}) {
		return $self->_snmpset($self->{OID_Filter_DHCP_PortState} . '.' . $port, $t_integer, getIndexFromArray($state, @{$self->{str_Filter_DHCP_PortState}}));
	} else {
		$state = $state eq $enabled ? 'enable' : 'disable';
		$self->_telnet_cmd("config filter dhcp_server ports $port state $state");
		return 1;
	}
}

=head3 setFilterNetbiosPortState

=begin html

Изменяет состояние фильтра Netbios (<span class="code">enabled, disabled</span>)
на указанном порту.

=end html

=cut

sub setFilterNetbiosPortState {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	
	if (!$self->_checkPort($port)) {
		die 'DLink::SNMP->setFilterNetbiosPortState: ' . $self->_OOR($port);
	} else {
		$port = $self->_checkPort($port);
	}
	
	my $result = $self->{FilterNetbiosTroughPCF} ? $self->_setFilterNetbiosThroughPCF($port, $state) : $self->_snmpset($self->{OID_Filter_Netbios_PortState} . '.' . $port, $t_integer, getIndexFromArray($state, @{$self->{str_Filter_Netbios_PortState}}));
	return $result;
}

sub _setFilterNetbiosThroughPCF {
	my $self = shift;
	my $port = $self->createMask(shift);
	my $state = shift;
	my $profile;
	my $rule_087;
	my $rule_089;
	my $rule_08a;
	my $rule_08b;
	my $rule_1bd;
	my $mask_087;
	my $mask_089;
	my $mask_08a;
	my $mask_08b;
	my $mask_1bd;
	my $next_free = 1;
	my @free;
	my @pcf_profiles = $self->getPCFProfileList;
	
	if (@pcf_profiles == 1)	{
		$profile = $pcf_profiles[0];
	}
	
	if (!@pcf_profiles) {
		$self->createPCFNetbiosProfile(200); 	# very dirty
		$profile = 200;
	}
	
	my @rules = $self->getPCFRuleList($profile);
	
	foreach my $rule(@rules) {
		my $payload = $self->getPCFRulePayload($profile, $rule);
		my $rule_port = $self->getPCFRulePort($profile, $rule);
		
		if ($next_free == $rule) {
			$next_free++;
		} else {
			push @free, $next_free;
			$next_free = $rule + 1;
		}
		
		if ($payload =~ '0087') {
			$rule_087 = $rule;
			$mask_087 = $self->createMask($rule_port);
		} elsif ($payload =~ '0089') {
			$rule_089 = $rule;
			$mask_089 = $self->createMask($rule_port);
		} elsif ($payload =~ '008a') {
			$rule_08a = $rule;
			$mask_08a = $self->createMask($rule_port);
		} elsif ($payload =~ '008b') {
			$rule_08b = $rule;
			$mask_08b = $self->createMask($rule_port);
		} elsif ($payload =~ '01bd') {
			$rule_1bd = $rule;
			$mask_1bd = $self->createMask($rule_port);
		}
	}
	
	while ((@rules + @free) < 5) {
		
		if ($rules[-1] > $free[-1]) {
			push @free, $rules[-1] + 1;
		} else {
			push @free, $free[-1] + 1;
		}
		
	}
	
	if (!$rule_087) {
		$rule_087 = shift @free;
		$mask_087 = $port;
	}
	
	if (!$rule_089) {
		$rule_089 = shift @free;
		$mask_089 = $port;
	}
	
	if (!$rule_08a) {
		$rule_08a = shift @free;
		$mask_08a = $port;
	}
	
	if (!$rule_08b) {
		$rule_08b = shift @free;
		$mask_08b = $port;
	}
	
	if (!$rule_1bd) {
		$rule_1bd = shift @free;
		$mask_1bd = $port;
	}
	
	
	push my @buf, $rule_087, '0087', $mask_087, $rule_089, '0089', $mask_089, $rule_08a, '008a', $mask_08a, $rule_08b, '008b', $mask_08b, $rule_1bd, '01bd', $mask_1bd;
	
	while (@buf) {
		my $rule = shift @buf;
		my $payload = shift @buf;
		my $mask = shift @buf;
		$self->deletePCFRule($profile, $rule);
		
		my $new_mask = $state eq $enabled ? $self->addMasks($mask, $port) : $self->subtractMasks($mask, $port);
		$self->addPCFNetbiosRule($profile, $rule, $payload, $self->_portconv($new_mask));
		
		if ($self->error) {
			return undef;
		}
	}
	
	return 1;	
}

#
#	Other
#

=head3 clearARPTable

=begin html

Очищает таблицу ARP.

=end html

=cut

sub clearARPTable {
	my $self = shift;
	return $self->_snmpset('1.3.6.1.4.1.171.12.1.2.12.1.0', $t_integer, 2);
}

#
#	Safeguard
#

=head3 setSafeguard...

=begin html

Список функций для управления Safeguard Engine.

=end html

=cut

=head4 setSafeguardAdminState

=begin html

Изменяет состояние работы (<span class="code">enabled, disabled</span>) 
Safeguard Engine.

=end html

=cut

sub setSafeguardAdminState {
	my $self = shift;
	my $state = shift;
	return $self->_snmpset($self->{OID_SafeguardGlobalState}, $t_integer, getIndexFromArray($state, @{$self->{str_SafeguardGlobalState}}));
}

=head4 setSafeguardMode

=begin html

Изменяет режим работы (<span class="code">strict, fuzzy</span>) Safeguard Engine.

=end html

=cut

sub setSafeguardMode {
	my $self = shift;
	my $mode = shift;
	return $self->_snmpset($self->{OID_SafeguardMode}, $t_integer, getIndexFromArray($mode, @{$self->{str_SafeguardMode}}));
}

=head4 setSafeguardTrap

=begin html

Изменяет состояние настройки (<span class="code">enabled, disabled</span>)
Safeguard Engine SNMP Trap.

=end html

=cut

sub setSafeguardTrap {
	my $self = shift;
	my $state = shift;
	return $self->_snmpset($self->{OID_SafeguardTrap}, $t_integer, getIndexFromArray($state, @{$self->{str_SafeguardTrap}}));
}

=head4 setSafeguardRisingThreshold

=begin html

Устанавливает верхний порог нагрузки на CPU для перехода Safeguard Engine в режим
exhausted.

=end html

=cut

sub setSafeguardRisingThreshold {
	my $self = shift;
	my $thold = shift;
	return $self->_snmpset($self->{OID_SafeguardRisingThreshold}, $t_integer, $thold);
}

=head4 setSafeguardFallingThreshold

=begin html

Устанавливает нижний порог нагрузки на CPU для перехода Safeguard Engine в режим
normal.

=end html

=cut

sub setSafeguardFallingThreshold {
	my $self = shift;
	my $thold = shift;
	return $self->_snmpset($self->{OID_SafeguardFallingThreshold}, $t_integer, $thold);
}

#
# 	IGMP Multicast VLAN Groups
#

=head3 Multicast Groups/Filters management

=begin html

Список функций для управления multicast группами и фильтрами. Во всех функциях,
которые управляют настройками на портах, номер порта всегда идет первым аргументом.

=end html

=cut

=head4 setMcastFilterStateOnPort

=begin html

Включает/выключает (<span class="code">enabled, disabled</span>) работу фильтра
на порту.<br/><i>Внимание! Данная функция доступна только для DES-3526!</i>

=end html

=cut

sub setMcastFilterStateOnPort {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	
	if (!$self->_checkPort($port)) {
		die 'DLink::SNMP->setMcastFilterStateOnPort: ' . $self->_OOR($port);
	} else {
		$port = $self->_checkPort($port);
	}
	
	if (!$self->{OID_Mcast_PortState}) {
		return 1;
	}
	
	return $self->_snmpset($self->{OID_Mcast_PortState} . '.' . $port, $t_integer, getIndexFromArray($state, @{$self->{str_Mcast_PortState}}));
}

=head4 setMcastAccessOnPort

=begin html

Задает режим работы фильтров на указанном порту (<span class="code">permit,
deny</span>).<br/>
<i>Внимание! Из представленных моделей коммутаторов эта функция не поддерживается
DES-3028!</i>

=end html

=cut

sub setMcastAccessOnPort {
	my $self = shift;
	my $port = shift;
	my $state = shift;
	
	if (!$self->_checkPort($port)) {
		die 'DLink::SNMP->setMcastFilterStateOnPort: ' . $self->_OOR($port);
	} else {
		$port = $self->_checkPort($port);
	}
	
	if (!$self->{OID_Mcast_PortAccess}) {
		return 1;
	}
	
	my $OID = $self->{OID_Mcast_setPortAccess} ? $self->{OID_Mcast_setPortAccess} . '.' . $port : $self->{OID_Mcast_PortAccess} . '.' . $port;
	
	return $self->_snmpset($OID, $t_integer, getIndexFromArray($state, @{$self->{str_Mcast_PortAccess}}));
}

=head4 createMcastFilter

=begin html

Создает фильтр для multicast групп.<p class="code">
createMcastFilter($index, $name, $start, $end);</p>
index - индекс фильтра<br/>
name - имя фильтра<br/>
start - первый адрес диапазона групп<br/>
end - последний адрес диапазона групп.

=end html

=cut

sub createMcastFilter {
	my $self = shift;
	my $index = shift;
	my $name = shift;
	my $start = shift;
	my $end = shift;
	
	if ($self->{IGMPMcastVLANgroupsEqualMcastFilterProfiles}) {
		return undef;
	}
	
	push my @args, $self->{OID_McastRange_Name} . '.' . $index, $t_octet, $name;
	
	if ($self->{OID_McastRange_Action}) {
		push @args, $self->{OID_McastRange_Action} . '.' . $index, $t_integer, 2;	# 'add' action
		push @args, $self->{OID_McastRange_Addr} . '.' . $index, $t_octet, $start . '-' . $end;
		push @args, $self->{OID_McastRange_RowStatus} . '.' . $index, $t_integer, $createAndGo;
	} else {
		push @args, $self->{OID_McastRange_RowStatus} . '.' . $index, $t_integer, $createAndGo;
		push @args, $self->{OID_McastRangeAddress_RowStatus} . '.' . $index . '.' . $start . '.' . $end, $t_integer, $createAndGo;
	}
	
	return $self->_snmpset(@args);
}

=head4 removeMcastFilter

=begin html

Удаляет фильтр multicast групп.<br/>
<i>Внимание! На DES-3526 не работает, т.к. там нет отдельного функционала фильтров.
Фильтрация на DES-3526 реализована добавлением/удалением на порт именованного
диапазона групп, участвующих в IGMP Snooping (об этом ниже).</i>

=end html

=cut

sub removeMcastFilter {
	my $self = shift;
	my $index = shift;
	
	if ($self->{IGMPMcastVLANgroupsEqualMcastFilterProfiles}) {
		return undef;
	}
	
	return $self->_snmpset($self->{OID_McastRange_RowStatus} . '.' . $index, $t_integer, $destroy);
}

=head4 createIGMPMcastGroup

=begin html

Создает запись о диапазоне multicast групп, на которые распространяется функционал
IGMP Snooping. <p class="code">createIGMPMcastGroup($name, $start, $end);</p>
name - имя диапазона<br/>
start - первый адрес диапазона<br/>
end - последний адрес диапазона.

=end html

=cut

sub createIGMPMcastGroup {
	my $self = shift;
	my $name = shift;
	my $start = shift;
	my $end = shift;
	my $suffix = $self->_name_to_index($name);
	
	if ($self->{IGMPMcastVLANgroupsEqualMcastFilterProfiles}) {
		push my @args, $self->{OID_McastRange_From} . '.' . $suffix, $t_ipaddr, $start;
		push @args, $self->{OID_McastRange_To} . '.' . $suffix, $t_ipaddr, $end;
		push @args, $self->{OID_McastRange_RowStatus} . '.' . $suffix, $t_integer, $createAndGo;
		return $self->_snmpset(@args);
	}
	
	if ($self->{OID_IGMP_McastVLANgroupName_RowStatus}) {
		push my @args, $self->{OID_IGMP_McastVLANgroupName_RowStatus} . '.' . $suffix, $t_integer, $createAndGo;
		push @args, $self->{OID_IGMP_McastVLANgroup_RowStatus} . '.' . $suffix . '.1.4.' . $start . '.4.' . $end, $t_integer, $createAndGo;
		
		my $result = $self->_snmpset(@args);
		
		if ($result) {
			my $index = $self->_snmpget($self->{OID_IGMP_McastVLANgroupName_Index} . '.' . $suffix);
			my $groups = $self->_snmpget($self->{OID_IGMP_McastVLANgroups});
			$groups = $groups ? $groups . ',' . $index : $index;
			return $self->_snmpset($self->{OID_IGMP_McastVLANgroups}, $t_octet, $groups);
		} else {
			return undef;
		}
		
	}
	
	return $self->_snmpset($self->{OID_IGMP_McastVLANgroup_RowStatus} . '.' . $start . '.' . $end, $t_integer, $createAndGo);	
}

=head4 removeIGMPMcastGroup

=begin html

Удаляет запись о диапазоне multicast групп, на которые распространяется функционал
IGMP Snooping. Ввиду различий в реализации функционала на различных моделях и для
унификации кода вызов функции выглядит так:<p class="code">
removeIGMPMcastGroup($name, $start, $end);</p>
name - имя диапазона<br/>
start - первый адрес диапазона<br/>
end - последний адрес диапазона.

=end html

=cut

sub removeIGMPMcastGroup {
	my $self = shift;
	my $name = shift;
	my $start = shift;
	my $end = shift;
	my $suffix = $self->_name_to_index($name);

	if ($self->{IGMPMcastVLANgroupsEqualMcastFilterProfiles}) {
		return $self->_snmpset($self->{OID_McastRange_RowStatus} . '.' . $suffix, $t_integer, $destroy);
	}
	
	if ($self->{OID_IGMP_McastVLANgroupName_RowStatus}) {
		return $self->_snmpset($self->{OID_IGMP_McastVLANgroupName_RowStatus} . '.' . $suffix, $t_integer, $destroy);
	}
	
	#print $self->{OID_IGMP_McastVLANgroup_RowStatus}. '.' . $start . '.' . $end;
	
	return $self->_snmpset($self->{OID_IGMP_McastVLANgroup_RowStatus} . '.' . $start . '.' . $end, $t_integer, $destroy);
}

sub _McastFiltersOnPortByID {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $profile_id = shift;
	my @args;
	
	if (!$self->{OID_McastRange_ID}) {
		return undef;
	}
	
	if (!$self->_checkPort($port)) {
		die 'DLink::SNMP->' . $action . 'McastFilterOnPortByID: ' . $self->_OOR($port);
	} else {
		$port = $self->_checkPort($port);
	}
	
	if ($self->{OID_Mcast_setPortProfileAction}) {
		$action = $action eq 'add' ? 2 : 3;
		push @args, $self->{OID_Mcast_setPortProfileAction} . '.' .$port, $t_integer, $action;
		push @args, $self->{OID_Mcast_setPortProfileID} . '.' . $port, $t_integer, $profile_id;
	} else {
		$action = $action eq 'add' ? $createAndGo : $destroy;
		push @args, $self->{OID_Mcast_Port_RowStatus} . '.' . $port . '.' . $profile_id, $t_integer, $action;
	}
	
	return $self->_snmpset(@args);		
}

=head4 addMcastFiltersOnPortByID

=head4 addMcastFiltersOnPortByName

=head4 deleteMcastFiltersOnPortByID

=head4 deleteMcastFiltersOnPortByName

=begin html

Функции для добавления/удаления multicast фильтров на портах по номеру/имени фильтра.
<br/><i>Важно! На DES-3526 фильтры не имеют номеров, а на DES-3028 - имен.
Остальные модели пользуются и номерами, и именами для multicast фильтров.</i>

=end html

=cut

sub addMcastFiltersOnPortByID {
	my $self = shift;
	my $port = shift;
	my $profile_id = shift;
	return $self->_McastFiltersOnPortByID('add', $port, $profile_id);
}

sub deleteMcastFiltersOnPortByID {
	my $self = shift;
	my $port = shift;
	my $profile_id = shift;
	return $self->_McastFiltersOnPortByID('delete', $port, $profile_id);
}

sub _McastFiltersOnPortByName {
	my $self = shift;
	my $action = shift;
	my $port = shift;
	my $profile_name = shift;
	my @args;
	
	if (!$self->{OID_McastRange_Name}) {
		return undef;
	}
		
	if (!$self->_checkPort($port)) {
		die 'DLink::SNMP->' . $action . 'McastFilterOnPortByID: ' . $self->_OOR($port);
	} else {
		$port = $self->_checkPort($port);
	}
	
	if ($self->model eq '1.3.6.1.4.1.171.10.64.1') {		# DES-3526
		
		if ($action eq 'add') {
			push @args, $self->{OID_Mcast_PortRangeName} . '.' . $port, $t_octet, $profile_name;
			push @args, $self->{OID_Mcast_PortRange_RowStatus} . '.' . $port, $t_integer, $createAndGo;
		} else {
			my @filters = $self->getMcastFiltersOnPort($port);
			my $id = getIndexFromArray($profile_name, @filters) + 1;
			push @args, $self->{OID_Mcast_PortRange_RowStatus} . '.' . $port . '.' . $id, $t_integer, $destroy;
		}
		
		return $self->_snmpset(@args);
	} else {
		my @names = $self->_snmpwalk($self->{OID_McastRange_Name});
		my @ids = $self->_snmpwalk($self->{OID_McastRange_ID});
		
		while (@names) {
			my $buf = shift @names;
			my ($x, $name) = each %{$buf};
			$buf = shift @ids;
			my ($y, $id) = each %{$buf};
			
			if ($name eq $profile_name) {
				return $self->_McastFiltersOnPortByID($action, $port, $id);
			}
			
		}
	}
}

sub addMcastFiltersOnPortByName {
	my $self = shift;
	my $port = shift;
	my $name = shift;
	return $self->_McastFiltersOnPortByName('add', $port, $name);
}

sub deleteMcastFiltersOnPortByName {
	my $self = shift;
	my $port = shift;
	my $name = shift;
	return $self->_McastFiltersOnPortByName('delete', $port, $name);
}

#
#	Telnet stuff
#

=head3 getARPAgingTimeInMinutes

=begin html

Возвращает время жизни записей ARP таблицы в минутах. В качестве побочного эффекта
очищает таблицу ARP.

=end html

=cut

sub getARPAgingTimeInMinutes {
	my $self = shift;
	$self->_telnet_cmd('clear arptable');
	my @text = $self->_telnet_cmd('show arpentry');
	my $time;
	
	foreach my $str(@text) {
		chomp $str;
		
		if ($str =~ 'ARP') {
			my @buf = split / : /, $str;
			$time = $buf[1];
		}
		
	}
	
	if ($self->model eq '1.3.6.1.4.1.171.10.64.1') {
		
		if ($self->firmwareBoot !~ '6.00') {
			return int($time / 60);
		}
		
	}
	
	return $time;	
}

=head3 setARPAgingTimeInMinutes

=begin html

Устанавливает время жизни записей ARP таблицы в минутах.

=end html

=cut

sub setARPAgingTimeInMinutes {
	my $self = shift;
	my $time = shift;
	
	if ($self->model eq '1.3.6.1.4.1.171.10.64.1') {
		
		if ($self->firmwareBoot !~ '6.00') {
			$time = $time * 60;
		}
		
	}
	
	$self->_telnet_cmd("config arp_aging time $time");
	
	if ($self->{telnet}->errmsg) {
		return undef;
	} else {
		return 1;
	}
	
}

=head3 getSNMPHostList

=begin html

Возвращает список с параметрами SNMP хостов. <p class="code">
my @result = $dlink->getSNMPHostList;<br/>
while (@result) {<br/>
<span class="tab"></span>my $ip = shift @result;<br/>
<span class="tab"></span>my $version = shift @result;<br/>
<span class="tab"></span>my $user = shift @result;<br/>
<span class="tab"></span>print "$ip - $version - $user\n";<br/>
}<br/>
<span class="code-comment"><br/>
172.16.128.5 - V2c - dlread<br/>
192.168.1.101 - V1 - dlread<br/>
</span>
</p>

=end html

=cut

sub getSNMPHostList {
	my $self = shift;
	my @result;
	my @text = $self->_telnet_cmd('show snmp host');
	
	for (my $i = 5; $i <= 7; $i++) {
		my $s = $text[$i];
		chomp $s;
		$s =~ s/\x0d//g;

		if ($s) {
			$s =~ s/\ +/\ /g;
			push @result, (split / /, $s);
		} else {
			last;
		}
		
	}
	
	return @result;
}

=head3 removeSNMPHost

=begin html

Удаляет SNMP хост по указанному IP адресу.

=end html

=cut

sub removeSNMPHost {
	my $self = shift;
	my $SNMP_host = shift;
	$self->_telnet_cmd("delete snmp host $SNMP_host");

	if ($self->{telnet}->errmsg) {
		return undef;
	} else {
		return 1;
	}

}

=head3 createSNMPHost

=begin html

Создает SNMP хост.<p class="code">
createSNMPHost($SNMP_host, $version, $community);</p>
SNMP_host - IP адрес SNMP хоста<br/>
version - версия протокола SNMP: <span class="code">v1, v2c, v3</span><br/>
community - community или username для отправки SNMP traps.

=end html

=cut

sub createSNMPHost {
	my $self = shift;
	my $SNMP_host = shift;
	my $version = lc shift;
	my $community = shift;
	my $cmd = "create snmp host $SNMP_host $version $community";
	print "$cmd\n";
	$self->_telnet_cmd($cmd);
	
	if ($self->{telnet}->errmsg) {
		return undef;
	} else {
		return 1;
	}

}

=head3 getRADIUSKey

=begin html

Возвращает ключ авторизации на RADIUS сервере с указанным индексом.

=end html

=cut

sub getRADIUSKey {
	my $self = shift;
	my $id = shift;
	my $cmd = "show config current_config include \"radius\"";
	my @text = $self->_telnet_cmd($cmd);

	foreach my $str(@text) {
		
		if ($str =~ "config radius add $id") {
			my @buf = split / /, $str;
			my $key = $buf[6];
			$key =~ s/"//g;
			return $key;
		}
		
	}
}

=head3 createRADIUSHost

=begin html

Создает запись о RADIUS сервере на устройстве.<p class="code">
createRADIUSHost($id, $ip, $key);
</p>
id - индекс сервера<br/>
ip - IP адрес сервера<br/>
key - ключ авторизации на сервере.

=end html

=cut

sub createRADIUSHost {
	my $self = shift;
	my $id = shift;
	my $ip = shift;
	my $key = shift;
	$self->_telnet_cmd("config radius add $id $ip key $key default");
	
	if ($self->{telnet}->errmsg) {
		return undef;
	} else {
		return 1;
	}

}

=head3 removeRADIUSHost

=begin html

Удаляет запись о RADIUS сервере с укзанным индексом.

=end html

=cut

sub removeRADIUSHost {
	my $self = shift;
	my $id = shift;
	$self->_telnet_cmd("config radius delete $id");
	
	if ($self->{telnet}->errmsg) {
		return undef;
	} else {
		return 1;
	}

}

=head3 setRADIUS...

=begin html

Список функций для изменения записей о RADIUS серверах на устройстве. Первым
аргументом всегда является индекс записи.

=end html

=head4 setRADIUSIP

=head4 setRADIUSKey

=head4 setRADIUSAcctPort

=head4 setRADIUSAuthPort

=head4 setRADIUSRetransmit

=head4 setRADIUSTimeOut

=begin html

Соответственно назначают записи о сервере с указанным индексом IP адрес, ключ 
авторизации, порт учета(статистики, accounting), порт авторизации, количество
повторных попыток соединения, таймаут на ожидание соединения/ответа.

=end html

=cut

sub setRADIUSIP {
	my $self = shift;
	my $id = shift;
	my $ip = shift;
	$self->_telnet_cmd("config radius $id ipaddress $ip");
	
	if ($self->{telnet}->errmsg) {
		return undef;
	} else {
		return 1;
	}
}

sub setRADIUSKey {
	my $self = shift;
	my $id = shift;
	my $key = shift;
	$self->_telnet_cmd("config radius $id key $key");
	
	if ($self->{telnet}->errmsg) {
		return undef;
	} else {
		return 1;
	}
}

sub setRADIUSAcctPort {
	my $self = shift;
	my $id = shift;
	my $acct = shift;
	$self->_telnet_cmd("config radius $id acct_port $acct");
	
	if ($self->{telnet}->errmsg) {
		return undef;
	} else {
		return 1;
	}
}

sub setRADIUSAuthPort {
	my $self = shift;
	my $id = shift;
	my $auth = shift;
	$self->_telnet_cmd("config radius $id auth_port $auth");
	
	if ($self->{telnet}->errmsg) {
		return undef;
	} else {
		return 1;
	}
}

sub setRADIUSRetransmit {
	my $self = shift;
	my $id = shift;
	my $retransmit = shift;
	
	if (($self->name eq 'DES-3528') or ($self->name =~ 'DES-3200-[12]8F?/C1')) {
		$self->_telnet_cmd("config radius $id retransmit $retransmit");
	} else {
		$self->_telnet_cmd("config radius parameter retransmit $retransmit");
	}
	
	if ($self->{telnet}->errmsg) {
		return undef;
	} else {
		return 1;
	}
}

sub setRADIUSTimeOut {
	my $self = shift;
	my $id = shift;
	my $timeout = shift;
	
	if (($self->name eq 'DES-3528') or ($self->name =~ 'DES-3200-[12]8F?/C1')) {
		$self->_telnet_cmd("config radius $id timeout $timeout");
	} else {
		$self->_telnet_cmd("config radius parameter timeout $timeout");
	}
	
	if ($self->{telnet}->errmsg) {
		return undef;
	} else {
		return 1;
	}
}

1;
