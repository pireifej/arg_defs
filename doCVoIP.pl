#!/opt/app/d1fnc1c1/perl/bin/perl -w
# File Name: doCVoIP.pl.mold

# Must be executed from $ELEAT_HOME directory.
use strict;

##############################################################
##
##  Please note: we use two scripts: this script
##  is used to map all values from the scheduler
##  name values to the native name values for your
##  interface script. Parameter checking and logging are also
##  done here.
##
##############################################################

######################################################################
## Sample invocations (always from $ELEAT_HOME):
##
## Activation:
##  scripts/doCVoIP.pl NODEID=sample_node_ID LOGFILE=tmp/CVOIP.log ACTIONTYPENUM=0 MDN=9736101066 MUID=0 MIN=310410346902210 SURVTYPE=DATA SMS=NONE CISS=NONE SO_ENCRYPTION=NONE SERVTYPE=URI
##  scripts/doCVoIP.pl NODEID=LabCLIMs LOGFILE=tmp/CVOIP.log ACTIONTYPENUM=0 MDN=9736101066 MUID=0 MIN=310410346902210 SURVTYPE=DATA SMS=NONE CISS=NONE SO_ENCRYPTION=NONE SERVTYPE=URI
##	
## Deactivation:
##	scripts/doCVoIP.pl NODEID=sample_node_ID LOGFILE=tmp/CVOIP.log ACTIONTYPENUM=1 MDN=9736101066 MUID=0 MIN=310410346902210 SURVTYPE=DATA SMS=NONE CISS=NONE SO_ENCRYPTION=NONE SERVTYPE=URI
##  scripts/doCVoIP.pl NODEID=LabCLIMs LOGFILE=tmp/CVOIP.log ACTIONTYPENUM=1 MDN=9736101066 MUID=0 MIN=310410346902210 SURVTYPE=DATA SMS=NONE CISS=NONE SO_ENCRYPTION=NONE SERVTYPE=URI
##
## List all new (REACTIVATION):
##	scripts/doCVoIP.pl LOGFILE=tmp/CVOIP.log ACTIONTYPENUM=16 NODEID=sample_node_ID DSPFMT=PIPE
##	scripts/doCVoIP.pl LOGFILE=tmp/CVOIP.log ACTIONTYPENUM=16 NODEID=LabCLIMs DSPFMT=PIPE
##
## List all (LIST):
##	scripts/doCVoIP.pl LOGFILE=tmp/CVOIP.log ACTIONTYPENUM=18 NODEID=sample_node_ID DSPFMT=PIPE
##	scripts/doCVoIP.pl LOGFILE=tmp/CVOIP.log ACTIONTYPENUM=18 NODEID=LabCLIMs DSPFMT=PIPE
##
## List all new (REACTIVATION):
##	scripts/doCVoIP.pl LOGFILE=tmp/CVOIP.log ACTIONTYPENUM=16 NODEID=sample_node_ID
##	scripts/doCVoIP.pl LOGFILE=tmp/CVOIP.log ACTIONTYPENUM=16 NODEID=LabCLIMs
##
## List one (DUMP_ITN):
## scripts/doCVoIP.pl NODEID=sample_node_ID LOGFILE=tmp/CVOIP.log ACTIONTYPENUM=9 MDN=9736101066 MUID=0 object=co DSPFMT=PIPE
##
##
######################################################################

######################################################################
## global variables, to be shared with libArgs.pm
######################################################################
our $DEBUG = 10;	# set to zero, the code works in production manner
our $tmp_file_name = "CVOIP";
our $node_ID_root = "CVoIP";
our $node_type_ID = "CVoIP";
our %flags = ();			# a hash of the command line args with which we were invoked
our %node_config = ();   	# a hash of the configuration for our node
our %args = ();			# a HASH (and not array!) of the valid args and their respective values
our @invalid_args = ();
our %arg_defs = (
	# action-independent args
	'*' => [
		[ "action", \%flags, "req", "ACTIONTYPENUM", \&libArgs::ensure_action, &libAux::action_note ],
		[ "tmp", \%flags, "opt", "TEMPFILE", \&libArgs::ensure_tmp, &libAux::transcript_note ],
		[ "requestor", \%flags, "opt", "requestorID", \&libArgs::ensure_requestor, &libAux::requestor_note ],
		[ "source", \%flags, "opt", "SOURCE", 0, &libAux::source_note ],
		[ "DEBUG", \%flags, "opt", "DEBUG", 0, &libAux::DEBUG_note ],
		[ "accesstype", \%node_config, "opt", "ACCESSTYPE", \&libArgs::ensure_access_type, &libAux::access_type_note ],
		[ "user", \%node_config, "req", "PRILOGON", 0, &libAux::user_note ],
		[ "password", \%node_config, "req", "PRIPASS", 0, &libAux::password_note ],
		[ "success", \%node_config, "req", "SUCC_STRING", 0, &libAux::success_note ],
		[ "failure", \%node_config, "req", "FAIL_STRING", 0, &libAux::failure_note ],
		[ "CF_name", \%flags, "opt", "CF_name", 0, &libAux::CF_name_note, "", "VDNAPenlink" ],
		[ "cmd_wait", \%node_config, "req", "CMD_WAIT", \&libArgs::ensure_cmd_wait, &libAux::cmd_wait_note ],
		[ "command", \%flags, "req", "command", \&libArgs::ensure_command, &libAux::command_note ],
		[ "object", \%flags, "opt", "object", \&ensure_object, &libAux::object_note ],
		[ "MML_prompt", \%flags, "opt", "MML_prompt", 0, &libAux::MML_prompt_note, "", "MML_lis>" ],
		[ "PRIIP", \%node_config, "req", "PRIIP", 0, &libAux::PRIPORT_note ],
	],
	'ACTIVATION' => [
		[ "MDN", \%flags, "opt", "MDN", \&libArgs::ensure_MDN, &libAux::MDN_note ],
		[ "MIN", \%flags, "opt", "MIN", \&libArgs::ensure_MIN, &libAux::MIN_note ],
		[ "MUID", \%flags, "opt", "MUID", \&libArgs::ensure_MUID, &libAux::MUID_note ],
		[ "caseid", \%flags, "opt", "caseid", \&libArgs::ensure_case_ID, &libAux::case_ID_note ],
		[ "coid", \%flags, "req", "coid", \&ensure_coid_for_CVoIP, &libAux::COID_note ],
		[ "location", \%flags, "opt", "location", \&libArgs::ensure_location, &libAux::location_note ],
		[ "servtype", \%flags, "opt", "SERVTYPE", \&ensure_service_type, &libAux::service_type_note ],
		[ "services", \%flags, "opt", "services", \&libArgs::ensure_services, &libAux::services_note ],
		[ "servid", \%flags, "opt", "serviceid",  \&ensure_serv_ID, &libAux::service_ID_note ],
		[ "survtype", \%flags, "opt", "SURVTYPE", \&ensure_surv_type_CVoIP, &libAux::surveillance_type_note ],
		[ "trclvl", \%flags, "opt", "trclvl", \&libArgs::ensure_trace_level, &libAux::trace_level_note ],
		[ "CLLI", \%node_config, "opt", "CLLI", \&libArgs::ensure_CLLI_for_VoIP, &libAux::CLLI_note ],
		[ "afid", \%flags, "opt", "afid", \&libArgs::ensure_af_ID_for_VoIP, &libAux::AFID_note ],
		[ "ecpid", \%flags, "opt", "ecpid", \&libArgs::ensure_ecp_ID, &libAux::ECPID_note ],
		[ "immbill", \%flags, "opt", "immbill", \&libArgs::ensure_immbill, &libAux::IMMBILL_note ],
		[ "cnum", \%flags, "opt", "CNUM", \&libArgs::ensure_CNUM, &libAux::CNUM_note ],
		[ "numcalls", \%flags, "opt", "numcalls", \&libArgs::ensure_numcalls, &libAux::NUMCALLS_note ],
		[ "dcsid", \%flags, "req", "dcsid", \&libArgs::ensure_dcs_ID, &libAux::DCSID_note ],
		[ "grpid", \%flags, "opt", "grpid", \&libArgs::ensure_grp_ID, &libAux::GRPID_note ],
		[ "rcvtime", \%flags, "opt", "rcvtime", \&libArgs::ensure_rcv_time, &libAux::received_time_note ],
		[ "city", \%flags, "opt", "CITY", \&libArgs::ensure_city, &libAux::city_note ],
		[ "startdate", \%flags, "opt", "SV_STARTDATE", 0, &libAux::start_date_note ],
		[ "stopdate", \%flags, "opt", "SV_STOPDATE", \&libArgs::ensure_stop_date, &libAux::stop_date_note ],
		[ "starttime", \%flags, "opt", "SV_STARTTIME", 0, &libAux::start_time_note ],
		[ "stoptime", \%flags, "opt", "SV_STOPTIME", \&libArgs::ensure_stop_time, &libAux::stop_time_note ],
		[ "tz", \%flags, "opt", "tz", 0, &libAux::time_zone_note ],
		[ "judge", \%flags, "opt", "judge", 0, &libAux::judge_note ],
		[ "orderdate", \%flags, "opt", "orderdate", 0, &libAux::order_date_note ],
		[ "contact", \%flags, "opt", "contact", 0, &libAux::contact_note ],
		[ "rcvdate", \%flags, "opt", "rcvdate", 0, &libAux::received_date_note ],
		[ "region", \%flags, "opt", "region", 0, &libAux::region_note ],
		[ "comments", \%flags, "opt", "comments", 0, &libAux::comments_note ],
		[ "access", \%flags, "opt", "access", 0, &libAux::access_note ],
		[ "cishowtarget", \%flags, "opt", "CISHOWTARGET", 0, &libAux::CI_show_target_note ],
		[ "ccshowtarget", \%flags, "opt", "CCSHOWTARGET", 0, &libAux::CC_show_target_note ],
		[ "sms", \%flags, "opt", "SMS", \&libArgs::ensure_sms, &libAux::SMS_note ],
		[ "ciss", \%flags, "opt", "CISS", \&libArgs::ensure_ciss, &libAux::CISS_note ],
		[ "combined", \%flags, "opt", "COMBINED", \&libArgs::ensure_combined, &libAux::combined_note ],
		[ "encryption", \%flags, "opt", "SO_ENCRYPTION", 0, &libAux::ENCRYPTION_note ],
		[ "key", \%flags, "opt", "SO_KEY", \&libArgs::ensure_key, &libAux::key_note ],
		[ "state", \%flags, "opt", "state", 0, &libAux::state_note ],
		[ "action", \%flags, "opt", "ACTION", 0, &libAux::action_note ],
		[ "MRP", \%flags, "opt", "MRP", 0, &libAux::MRP_note ],
		[ "CPND", \%flags, "opt", "CPND", 0, &libAux::CPND_note ],
		[ "PKTENV", \%flags, "opt", "PKTENV", 0, &libAux::PKTENV_note ],
		[ "PKTCONT", \%flags, "opt", "PKTCONT", 0, &libAux::PKTCONT_note ],
		[ "BILL_NUM", \%flags, "opt", "BILL_NUM", 0, &libAux::BILL_NUM_note ],
		[ "IOBS", \%flags, "opt", "IOBS", 0, &libAux::IOBS_note ],
		[ "CRSS", \%flags, "opt", "CRSS", 0, &libAux::CRSS_note ],
		[ "NCIS", \%flags, "opt", "NCIS", 0, &libAux::NCIS_note ],
		[ "NCRS", \%flags, "opt", "NCRS", 0, &libAux::NCRS_note ],
		[ "DDE", \%flags, "opt", "DDE", 0, &libAux::DDE_note ],
		[ "group", \%flags, "opt", "group", 0, &libAux::group_note ],
		[ "owner", \%flags, "opt", "owner", 0, &libAux::owner_note ],
		[ "cccid", \%flags, "opt", "cccid", \&libArgs::ensure_ccc_ID, &libAux::CCC_ID_note ],
		[ "status", \%flags, "opt", "status", 0, &libAux::status_note ],
		[ "CDPNAI", \%flags, "opt", "CDPNAI", 0, &libAux::CDPNAI_note ],
		[ "CDPPLAN", \%flags, "opt", "CDPPLAN", 0, &libAux::CDPPLAN_note ],
		[ "CGPNUM", \%flags, "opt", "CGPNUM", 0, &libAux::CGPNUM_note ],
		[ "CGPNAI", \%flags, "opt", "CGPNAI", 0, &libAux::CGPNAI_note ],
		[ "CGPPLAN", \%flags, "opt", "CGPPLAN", 0, &libAux::CGPPLAN_note ],
		[ "CHRGNUM", \%flags, "opt", "CHRGNUM", 0, &libAux::CHRGNUM_note ],
		[ "CHRGNAI", \%flags, "opt", "CHRGNAI", 0, &libAux::CHRGNAI_note ],
		[ "CHRGPLAN", \%flags, "opt", "CHRGPLAN", 0, &libAux::CHRGPLAN_note ],
		[ "OLI", \%flags, "opt", "OLI", 0, &libAux::OLI_note ],
		[ "member", \%flags, "opt", "member", 0, &libAux::member_note ],
		[ "NUMCCC", \%flags, "opt", "NUMCCC", 0, &libAux::NUMCCC_note ],
		[ "tid", \%flags, "opt", "TID", \&libArgs::ensure_tid, &libAux::TID_note ],
		[ "JAREAID", \%flags, "opt", "JAREAID", 0, &libAux::JAREAID_note ],
		[ "priority", \%flags, "opt", "priority", \&libArgs::ensure_priority, &libAux::priority_note ],
		[ "ifid", \%flags, "opt", "if_ID", \&libArgs::ensure_if_ID, &libAux::if_ID_note ],
		[ "destip", \%flags, "opt", "destip", \&libArgs::ensure_dest_IP, &libAux::dest_IP_note ],
		[ "destport", \%flags, "opt", "destport", \&libArgs::ensure_dest_port, &libAux::dest_port_note ],
		[ "ownip", \%flags, "opt", "ownip", \&libArgs::ensure_dest_IP, &libAux::own_IP_note ],
		[ "ownport", \%flags, "opt", "ownport", \&libArgs::ensure_dest_port, &libAux::own_port_note ],
		[ "transport", \%flags, "opt", "transport", \&libArgs::ensure_transport, "" ],
		[ "reqstate", \%flags, "opt", "reqstate", \&libArgs::ensure_req_state, "" ],
		[ "filter", \%flags, "opt", "filter", \&libArgs::ensure_filter, "" ],
		[ "version", \%flags, "opt", "version", \&libArgs::ensure_version, "" ],
		[ "cfid", \%flags, "opt", "CFID", \&libArgs::ensure_CFID, &libAux::LEA_CFID_note ],
		[ "ITN", \%flags, "opt", "ITN", \&libArgs::ensure_ITN,  &libAux::ITN_note]
	],
	'DEACTIVATION' => [
		[ "MDN", \%flags, "opt", "MDN", \&libArgs::ensure_MDN, &libAux::MDN_note ],
		[ "MIN", \%flags, "opt", "MIN", \&libArgs::ensure_MIN, &libAux::MIN_note ],
		[ "MUID", \%flags, "opt", "MUID", \&libArgs::ensure_MUID, &libAux::MUID_note ],
		[ "cccid", \%flags, "opt", "cccid", \&libArgs::ensure_ccc_ID, "" ],
		[ "coid", \%flags, "req", "coid", \&ensure_coid_for_CVoIP,  &libAux::COID_note ],
		[ "services", \%flags, "opt", "services", \&libArgs::ensure_services,  &libAux::services_note ],
		[ "servtype", \%flags, "opt", "SERVTYPE", \&ensure_service_type,  &libAux::surveillance_type_note ],
		[ "servid", \%flags, "opt", "serviceid",  \&ensure_serv_ID, &libAux::service_ID_note ],
		[ "survtype", \%flags, "opt", "SURVTYPE", \&ensure_surv_type_CVoIP, &libAux::surveillance_type_note ],
		[ "cnum", \%flags, "opt", "CNUM", \&libArgs::ensure_CNUM, &libAux::CNUM_note ],
		[ "numcalls", \%flags, "opt", "numcalls", \&libArgs::ensure_numcalls, &libAux::NUMCALLS_note ],
		[ "dcsid", \%flags, "req", "dcsid", \&libArgs::ensure_dcs_ID, &libAux::DCSID_note ],
		[ "CLLI", \%node_config, "opt", "CLLI", 0, &libAux::CLLI_note ],
		[ "afid", \%flags, "opt", "afid", \&libArgs::ensure_af_ID_for_VoIP, &libAux::AFID_note ],
		[ "ecpid", \%flags, "opt", "ecpid", \&libArgs::ensure_ecp_ID, &libAux::ECPID_note ],
		[ "tid", \%flags, "opt", "TID", \&libArgs::ensure_tid, &libAux::TID_note ],
		[ "ifid", \%flags, "opt", "if_ID", \&libArgs::ensure_if_ID, &libAux::if_ID_note ],
		[ "destip", \%flags, "opt", "dest_IP", \&libArgs::ensure_dest_IP, &libAux::dest_IP_note ],
		[ "destport", \%flags, "opt", "dest_port", \&libArgs::ensure_dest_port, &libAux::dest_port_note ],
		[ "cfid", \%flags, "opt", "CFID", \&libArgs::ensure_CFID, &libAux::LEA_CFID_note ]
	],
	'LIST' => [
		[ "display_fmt", \%flags, "req", "DSPFMT", \&libArgs::ensure_display_fmt, "display format" ],
		[ "NODEID", \%flags, "req", "NODEID", 0, "Node ID" ],
	],
	'REACTIVATION' => [
		[ "display_fmt", \%flags, "req", "DSPFMT", \&libArgs::ensure_display_fmt, "display format", "", "ERPIPE" ],
		[ "NODEID", \%flags, "req", "NODEID", 0, "Node ID" ],
		[ "NODECLASS", \%node_config, "req", "NODECLASS", 0, "Node class" ],
		[ "CLLI", \%node_config, "opt", "CLLI", \&libArgs::ensure_CLLI_for_VoIP, &libAux::CLLI_note ],
	],
	'DUMP_ITN' => [
		[ "coid", \%flags, "opt", "coid", \&libArgs::ensure_coid, "" ],
		[ "servid", \%flags, "opt", "serviceid", \&ensure_serv_ID, "" ],
		[ "display_fmt", \%flags, "req", "DSPFMT", \&libArgs::ensure_display_fmt, "display format" ],
		[ "CLLI", \%node_config, "opt", "CLLI", \&libArgs::ensure_CLLI_for_VoIP, &libAux::CLLI_note ],
	]
);

sub ensure_coid_for_CVoIP($$) {
	my ($coid, $criticality) = ($_[0], $_[1]);

	if (libAux::empty($main::args{'source'})) {
		return (libArgs::ensure_coid($coid, $criticality));
	}

	my $source = $main::args{'source'};

	# CVoIP is landline and thus does not use IMSI, so
	# clear out the MIN/IMSI so that MDN/MSIDN + MUID is used instead
	if ($source eq "TAPSS") {
		$main::args{'MIN'} = "";
		return (libArgs::ensure_coid($coid, $criticality));
	}

	return (libArgs::ensure_coid($coid, $criticality));
}

sub ensure_surv_type_CVoIP($$) {
	my ($surveillance_type, $criticality) = ($_[0], $_[1]);

	if (libAux::empty($main::args{'source'})) {
		return (libArgs::ensure_surv_type($surveillance_type, $criticality));
	}

	my $source = $main::args{'source'};

	# if Content + Location is selected from TAPSS, 
	# change it to just Content so that the SURVTYPE ends up as ALL
	# because SURVTYPE = CC will always fail
	if ($source eq "TAPSS" && $surveillance_type eq "CWLOC") {
		return (libArgs::ensure_surv_type("CONTENT", $criticality));
	}

	return (libArgs::ensure_surv_type($surveillance_type, $criticality));
}

sub ensure_service_type($$) {
	my ($service_type, $criticality) = ($_[0], $_[1]);

	if (libAux::empty($main::args{'source'})) {
		return (libArgs::ensure_service_type($service_type, $criticality));
	}

	my $source = $main::args{'source'};

	# the TAPSS page always sends a service type of IMSI,
	# but CVoIP requires a service type of MSISDN
	if ($source eq "TAPSS") {
		return("URI", "");
	}

	 return (libArgs::ensure_service_type($service_type, $criticality));
}

sub ensure_serv_ID($$) {
	my ($serv_ID, $criticality) = ($_[0], $_[1]);

	if ($serv_ID ne "") {
		return ($serv_ID, "");
	}

	if (libAux::empty($main::args{'MDN'})) {
		my $err_msg = ($criticality eq "req") ? "error creating serv_ID: missing MDN" : "";
		return ("", $err_msg);
	}

	return("sip:+1" . $main::args{'MDN'} . "\@ims.sbc.com", "");
}

sub ensure_object($$) {
	my $object = $_[0];

	my @node_objects = ( "afwt", "co", "surveillance", "survopt", "target", "t1678cfci", "");
	for my $node_object (@node_objects) {
		if ($node_object eq $object) {
			return $object;
		}
	}

	return ("", "Unknown object '$object'");
}

## Load all the the generic ELEAT libraries
use libs::libArgs;
use libs::libAux;
use libs::libConfigN;
use libs::libFileUtilsN;
my $ELEATROOT = libConfig::getEleatCfgVal("ELEATROOT");

# initialize arrays and hashes & misc. globals
my %valid_cmds = ();
my @validArgs = ();
my @inValidCfgs = ();
my $time = "";
my $fromTAPSS = 0;
my $isAutomated = 0;
my $aFlag = 0;	# determines which access type to use (ssh vs. telnet)
my $userName = "";	# user name for ssh/telnet session
my $hostIP = "";	# IP addres for ssh/telnet session
my $tmpFile = "";
my $valid_LOG = 0;		# do we have a valid logfile open on the LOG file handle?
my $log_file = "";	# the log_file name calculated for us by libFileUtils:procDoArgs()
my $FAILED = "FAILED";
my $DBG_file = "$ELEATROOT/tmp/do" . $node_ID_root . ".DBG";
my $now = libAux::now();

######################################################################
## This is the name of the actual interface script.
## You would replace "new.pl" with the name of your interface script
## and the node type for this interface.
######################################################################
my $exec_script = "$ELEATROOT/scripts/$node_ID_root.pl";	# the actual interface script we call

######################################################################
## Global flags
######################################################################
my $ISDF = 0; # whether or not this is called for a delivery function
my $ISDFSTR = ""; # SGSN or CSI provisioning

# The validArgs array is the array that will be
# passed as arguments to your interface script.
# We use this to map the scheduler parameters to native
# parameter names for the interface you are building.
push(@validArgs, "log=$log_file");

# Main section - directly executed code starts here

# start fresh on each run
unlink $DBG_file;

libAux::debug_init($DBG_file);

# turn off and flush buffering
$| = 1;

# Load all the incoming arguments from the scheduler or troubleshooting page into the %flags hash.
# Also get the log_file and response files defined.
($valid_LOG, $log_file, my $flags_ptr) = libFileUtils::procDoArgs($node_type_ID, $FAILED);

if (! $valid_LOG) {
	libAux::croak(1, "LOG file '$log_file' for node_type_ID '$node_type_ID' not valid!");
	# not reached #
}

$|=1;
%flags = %{$flags_ptr};
$args{'log_file'} = $log_file;

# Get node config
if (! defined($flags{'NODEID'})) {
	libAux::croak(1, "GACK: no node ID given! Aborting.");
	# not reached #
}

my $node_ID = $flags{'NODEID'};
%node_config = libConfig::getNodeCfgById($node_ID);
if (keys %node_config == 0) {
	libAux::croak(1, "GACK: node ID '$node_ID' not found!  Aborting.");
	# not reached #
}

# start fresh on each run
unlink $log_file;
libAux::log_init($log_file, $node_config{'FAIL_STRING'});

## harmless debugging - all of these are silent unless $DEBUG != 0
libArgs::dump_node_config($node_ID);
libArgs::dump_flags("doCVoIP", %flags);
#libArgs::dump_arg_defs($DBG_file);

## Step through each argument that we need to make our interface work (from %arg_defs).
## Note that our invocation arguments (%flags) include ones that we don't need.
## These are not an error and are simply ignored.

libArgs::get_args('*', @invalid_args);		# process required & optional args that are independent of the action we are to perform

if ($args{"action"} ne "") {
	libArgs::get_args($args{"action"}, @invalid_args);	# process required & optional args for this specific action
}

if (@invalid_args > 0) {
	libAux::debug_print("Invalid params='@invalid_args'\n");
	libAux::log_print($FAILED, "Invalid params='@invalid_args'");
	libAux::croak(1, "Exiting due to invalid parameters");
}

libAux::log_print_if(10, 'PARAMS', "user = $args{'user'}");

## Set up plumbing for an SSH session to the remote node
my $PTYWRAP = libConfig::getEleatCfgVal("PTYWRAP");	# wrapper for remotely-driven ssh and telnet sessions
my $convar="${PTYWRAP} ssh -t -t -2 $node_config{'PRILOGON'}\@$node_config{'PRIIP'}";

## if in DEBUG mode, then display the tmp_file as we write it
my $tmp_file = $args{'tmp'};
my $tmp = ($DEBUG) ? "| tee -a '$tmp_file'" : ">> '$tmp_file'";

my $args = join(" ", map { "$_='$args{$_}'" } keys %args);		# marshal into single string to pass on cmd line to interface script
my $status_file = "$ELEATROOT/tmp/$node_ID_root.$$.status";
my $full_cmd = "(rm -f $status_file; $exec_script $args; echo \$\? > $status_file) | ${convar} $tmp 2>&1";
my $retry_status = 98;		# exit status from interface script that means we should retry immediately

libAux::debug_print("Executable: $exec_script\n");
libAux::debug_print("Arguments: $args\n");
libAux::debug_print("Command: $full_cmd\n");

## Initiate the actual call to the remote node & our interface script to talk with it.
##
## The trick here is to get the exit status of our helper $exec_script.
## But UNIX shell defines the exit status of a pipeline to be the status of the *last* element in that pipeline.
## So instead we capture it on the side & pull it out of a file.
my $status = $retry_status;
my $max_cmd_attempts = 10;
my $max_status_attempts = 5;
for (my $cmd_count = 0; $status == $retry_status && $cmd_count < $max_cmd_attempts; $cmd_count++) {
	libAux::debug_print("Retry #$cmd_count of $max_cmd_attempts\n") if $cmd_count > 1;
	libAux::debug_print($full_cmd);
	system($full_cmd);
	$status = -1;
	sleep 1;	# the $status_file shows up with vaiable latency
	for (my $status_count = 0; $status < 0 && $status_count < $max_status_attempts; $status_count++) {
		if (open(STATUS, "< $status_file")) {
			read STATUS, $status, 5;
			close STATUS;
		} else {
			if ($! !~ m/^No such file or directory$/) {
				print STDERR "open of $status_file failed: $!\n";
			}
			sleep 1;
		}
	}
}
unlink $status_file;
 
libAux::debug_print("Exit $status\n");
exit $status;	# 0 => success, 1=> error, $retry_status=> transient error, retry
