#!/opt/app/d1fnc1c1/perl/bin/perl -w

# File Name: CVoIP.pl -- Paul Ireifej -- 08/01/2013 (copied from BVoIP)
use IO::Handle;
use libs::libConfigN;
use libs::libArgs;
use libs::libAux;
use libs::libWebUtils;
use feature "switch";
use strict;

$| = 1;

# global variables, to be shared with lib files
our $ELEATROOT = libConfig::getEleatCfgVal("ELEATROOT");
our $DBG_file = "$ELEATROOT/tmp/doCVoIP.DBG";
our $LOCK_DIR = "$ELEATROOT/data/VoIP";
our $production_slow_down = 0;
our %flags = ();
our $hard_failure_status = 99;	# exit status for errors known to be persistent - NO retry
our $DEBUG = 10;

my $now = libAux::now();
my $cmd_wait = 0;
my @coids = ();
my @commands = ();	# list of commands used for provisioning (or de-provisioning) during this session
my $ERR_UNKNOWN_ERROR = "Unknown error:";
my $ERR_BACKOUT = "Provisioning not successful - back out of all previous commands complete";

# strings that wait_for looks for when checking for a dialog response (value is set in "initiate" subroutine)
my $SUCCESS = "";
my $FAILURE = "";
my $succ_or_fail = "";

# add-co, delete-co or display-co
# param1 - add, delete or display
sub do_co {
	my $action = $_[0];
	my @tmp  = ();
	my $cmd_prefix = "${action}-co:";
	my $command = $cmd_prefix;
	my @params = ("coid", "judge", "orderdate", "contact", "rcvdate", "rcvtime", "city", "comments", "access", "region", "state", "group");

	for my $param (@params) {
		if (!libAux::empty($flags{$param})) {
			 push(@tmp, "$param=\"$flags{$param}\"")
		}
	}

	$command .= join(",", @tmp);
	$command = $command . ";\n";
	print $command;
	push(@commands, $command);

	return libAux::handle_response($command, "$action co");
}

# add-surveillance, delete-surveillance or display-surveillance
# param1 - add, delete or display
sub do_surveillance($) {
	my $action = $_[0];
	my @tmp  = ();
	my $cmd_prefix = "${action}-surveillance:";
	my @params = ("coid", "cfid", "caseid", "stopdate", "stoptime", "starttime", "startdate", "starttime", "tz", "survtype", "access", "owner", "trclvl", "group");
	my $command = $cmd_prefix;

	for my $param (@params) {
		if (!libAux::empty($flags{$param})) {
			 push(@tmp, "$param=\"$flags{$param}\"")
		}
	}

	$command .= join(",", @tmp);
	$command = $command . ";\n";
	print $command;
	push(@commands, $command);

	return libAux::handle_response($command, "$action surveillance");
}

# add-survopt, delete-survopt or display-survopt
# param1 - add, delete or display
sub do_survopt {
	my $action = $_[0];
	my @tmp  = ();
	my $cmd_prefix = "${action}-survopt:";
	my @params = ("coid", "location", "cishowtarget", "sms", "ccshowtarget", "ciss", "combined", "encryption", "key", "access", "MRP", "CPND", "PKTENV", "PKTCONT", "DDE", "BILL_NUM", "group");
	my $command = $cmd_prefix;

	for my $param (@params) {
	  if (!libAux::empty($flags{$param})) {
			 push(@tmp, "$param=\"$flags{$param}\"")
		}
	}

	$command .= join(",", @tmp);
	$command = $command . ";\n";
	print $command;
	push(@commands, $command);

	return libAux::handle_response($command, "$action survopt");
}

# add-target, delete-target or display-target
# param1 - add, delete or display
sub do_target {
	my $action = $_[0];
	my @tmp  = ();
	my $cmd_prefix = "${action}-target:";
	my @params = ("coid", "tid", "servtype", "servid", "group", "owner", "access");
	my $command = $cmd_prefix;

	for my $param (@params) {
	  if (!libAux::empty($flags{$param})) {
			 push(@tmp, "$param=\"$flags{$param}\"")
		}
	}

	$command .= join(",", @tmp);
	$command = $command . ";\n";
	print $command;
	push(@commands, $command);

	return libAux::handle_response($command, "$action target");
}

# add-t1678cfci, delete-t1678cfci or display-t1678cfci
# param1 - add, delete or display
sub do_t1678cfci {
	my $action = $_[0];
	my @tmp  = ();
	my $cmd_prefix = "${action}-t1678cfci:";
	my @params = ("coid", "ifid", "destip", "destport", "version", "reqstate", "ownip", "ownport", "trclvl", "filter", "comments", "transport");
	my $command = $cmd_prefix;

	if (skip_t1678cfci()) {
		return("");
	}

	for my $param (@params) {
	 if (!libAux::empty($flags{$param})) {
			 push(@tmp, "$param=\"$flags{$param}\"")
		}
	}

	# there is a conflict with the 'state' parameter
	# both the co and t1678cfci have a state parameter
	# meaning different things in each context
	# state is read-only for this command, so it will never be used for now
	if (!libAux::empty($flags{'connect_state'})) {
		push(@tmp, "state=\"$flags{'connect_state'}\"")
	}

	$command .= join(",", @tmp);
	$command = $command . ";\n";
	print $command;
	push(@commands, $command);

	return libAux::handle_response($command, "$action t1678cfci");
}

# business rule: we don't bother with t1678cfci at all if the surveillance type is data-related
sub skip_t1678cfci() {
	return (!libAux::empty($flags{'source'}) && $flags{'source'} eq 'TAPSS' &&
			!libAux::empty($flags{'survtype'}) && $flags{'survtype'} eq "CD");
}

# activates surveillance for the gateway
sub activate_primary_node {
	# 1.) add-co
	if (do_co(&libAux::add) ne "") {
		return 1;
	}

	# 2.) add-surveillance
	my ($min_port, $max_port) = libAux::set_CFID();

	if (do_surveillance(&libAux::add) ne "") {
		do_co(&libAux::del);
		libAux::log_print("$FAILURE", "$ERR_BACKOUT");
		return 1;
	}

	# 3.) add-survopt
	if (do_survopt(&libAux::add) ne "") {
		do_surveillance(&libAux::del);
		do_co(&libAux::del);
		libAux::log_print("$FAILURE", "$ERR_BACKOUT");
		return 1;
	}

	# 4.) add-target
	if (do_target(&libAux::add) ne "") {
		do_survopt(&libAux::del);
		do_surveillance(&libAux::del);
		do_co(&libAux::del);
		libAux::log_print("$FAILURE", "$ERR_BACKOUT");
		return 1;
	}

	if (set_dest_IP_and_port($min_port, $max_port) ne "") {
		do_target(&libAux::del);
		do_survopt(&libAux::del);
		do_surveillance(&libAux::del);
		do_co(&libAux::del);
		libAux::unlock("$LOCK_DIR", "$flags{'MDN'}:$flags{'ITN'}:$flags{'cfid'}:$flags{'PRIIP'}:CVoIP");
		libAux::log_print("$FAILURE", "$ERR_BACKOUT");
		return 1;
	}

	# 5.) add-t1678cfci
	if (do_t1678cfci(&libAux::add) ne "") {
		do_target(&libAux::del);
		do_survopt(&libAux::del);
		do_surveillance(&libAux::del);
		do_co(&libAux::del);
		libAux::log_print("$FAILURE", "$ERR_BACKOUT");
		return 1;
	}

	libAux::log_print("$SUCCESS", "Primary node succesfully provisioned");

	return 0;
}

# deletes surveillance for the primary node
sub deactivate_primary_node {
	libAux::set_CFID();
	my $lock_name = "";
	if (!skip_t1678cfci()) {
		$lock_name = get_lock_name();
		if (do_t1678cfci(&libAux::del) eq "") {
			my ($anchor_file, $lock_file, $IP_addr, $CFID, $port_nbr) = libAux::read_lock("$LOCK_DIR", $lock_name);
			# if it is a Type 1 LEA, there is no lock file
			if ($anchor_file ne "") {
				libAux::debug_print("my anchor file = $anchor_file\n");
				libAux::debug_print("my lock file = $lock_file\n");
				libAux::debug_print("my IP addr = $IP_addr\n");
				libAux::debug_print("my CFID = $CFID\n");
				libAux::debug_print("my port nbr = $port_nbr\n");
				my ($err_code, $err_msg) = libAux::unlock("$LOCK_DIR", $anchor_file);
				if ($err_code eq "") {
					libAux::debug_print($err_msg);
					libAux::print_comment($err_msg);
				}
				libAux::print_comment("Removed lockfile $err_code");
			}
		}
	}

	do_target(&libAux::del);
	do_survopt(&libAux::del);
	do_surveillance(&libAux::del);
	do_co(&libAux::del);

	libAux::log_print("$SUCCESS", "Primary node succesfully de-provisioned");

	return 0;
}

# deletes surveillance for the access function
sub deactivate_secondary_node {
	set_AFID();

	do_afwt(&libAux::del);

	libAux::log_print("$SUCCESS", "Secondary node succesfully de-provisioned");

	return 0;
}

# This function accounts for three scenarios (in this priority):
#	1.) We were given a destport (i.e., from Node Trbsh)
#	2.) We parsed a port range from the display-cf command (set_CFID() subroutine)
#		2.1) If min port == max port, we have Type 1 LEA
#		2.2) If min port <  max port, we have Type 2 LEA
#	3.) We don't have a port range and were not given destport
#
# If we were not given destip, we parse it from the display-t1678cfci command
#
# Output: set $flags{'destip'} and $flags{'destport'}
#
sub set_dest_IP_and_port($$) {
	my ($min_port, $max_port) = ($_[0], $_[1]);
	my $err_msg = "";

	if (skip_t1678cfci()) {
		return("");
	}

	# 1.) if both destport and destip are given to us, we quit (i.e., from Node Trbsh page)
	if (!libAux::empty($flags{'destport'}) && !libAux::empty($flags{'destip'})) {
		$err_msg = set_lock($flags{'destport'}, $flags{'destport'});
		libAux::print_comment($err_msg);
		return $err_msg;
	}

	# 2.) if we have a min port and max port value, from the display-cf command (set_CFID function),
	# calculate destport value ourselves
	if ($min_port > 0 && $max_port > 0) {
		$err_msg = set_lock($min_port, $max_port);
		# if both destport and destip have values now, we quit
		if (!libAux::empty($flags{'destip'})) {
			libAux::print_comment($err_msg);
			return $err_msg;
		}
	}

	# 3.) if we don't have a port range and/or were not given destport/destip value,
	# parse it from the display-t1678cfci command
	# NOTE: this is a Type 1 LEA and thus, we do NOT lock the port
	my $cf_ID = $flags{'cfid'};
	my $command = "display-t1678cfdi:cfid=$cf_ID;\n";
	my $own_IP = "";
	my $dest_IP = "";
	my $dest_port = "";

	print $command;

	if (&libAux::wait_for($succ_or_fail, $cmd_wait) >= 0) {
		for my $line (@libAux::session_window) {
			$line =~ tr/a-z/A-Z/;
			chomp($line);

			if ($line =~ m/(\d+)\.(\d+)\.(\d+)\.(\d+)\s+(\d+)\s+(\d+)\.(\d+)\.(\d+)\.(\d+)\s+(\d+)/) {
				$own_IP = "$1.$2.$3.$4";
				if (libAux::empty($flags{'destip'})) {
					$flags{'destip'} = "$6.$7.$8.$9";
				}
				if (libAux::empty($flags{'destport'})) {
					$flags{'destport'} = $10 + 1;	# each warrant consumes a unique port for Type 1 LEA
				}
			}
		}
	}

	libAux::print_comment($err_msg);
	return $err_msg;
}

# subroutines related to port allocation/deallocation

sub get_lock_name() {
	if (libAux::empty($flags{'coid'})) {
		return("");
	}

	print "display-t1678cfci:coid=$flags{'coid'};\n";

	$flags{'destport'} = "";
	if (&libAux::wait_for($succ_or_fail, $cmd_wait) >= 0) {
		for my $line (@libAux::session_window) {
			chomp($line);
			if ($line =~ m/(\d+)\s+(\d+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\d+).(\d+).(\d+).(\d+)\s+(\d+)\s+(\d+).(\d+).(\d+).(\d+)\s+(\d+)/) {
				$flags{'destport'} = $15;
				last;
			}
		}
	}

	return "$flags{'PRIIP'}:$flags{'cfid'}:$flags{'destport'}";
}

sub set_lock($$) {
	my ($min_port, $max_port) = ($_[0], $_[1]);
	if (libAux::empty($flags{'cfid'})) {
		return("Error: CFID not defined for port allocation. Lock NOT set.\n");
	}
	if (libAux::empty($flags{'MDN'})) {
		libAux::debug_print("Warning: MDN not defined for port allocation. MDN will not appear in anchor file name.\n");
		$flags{'MDN'} = "";
	}
	if (libAux::empty($flags{'ITN'})) {
		libAux::debug_print("Warning: ITN not defined for port allocation. ITN will not appear in anchor file name.\n");
		$flags{'ITN'} = "";
	}
	my $anchor = "$flags{'MDN'}:$flags{'ITN'}:$flags{'cfid'}:$flags{'PRIIP'}:BVoIP";
	my ($return_str, @candidates) = libAux::get_candidates_range("$min_port", "$max_port", "$flags{'PRIIP'}:$flags{'cfid'}");
	if ($return_str ne "") {
		libAux::print_comment($return_str);
		return $return_str;
	}
	my ($err_code, $err_msg) = libAux::lock("$LOCK_DIR", @candidates, $anchor);
	my ($anchor_file, $lock_file, $IP_addr, $CFID, $port_nbr) = libAux::read_lock("$LOCK_DIR", $anchor);
	if ($lock_file ne "") {
		libAux::print_comment("Allocated $lock_file for this case.\n");
	}
	$flags{'destport'} = $port_nbr;
	return $err_msg;
}

# set the $flags{'afid'}, given the name
sub set_AFID {
	if (!libAux::empty($flags{'afid'})) {
		return;
	}
 
	my $name = $flags{'CLLI'};
	my $command = "display-af:name=$name;\n";

	print $command;

	if (&libAux::wait_for($succ_or_fail, $cmd_wait) >= 0) {
		for my $line (@libAux::session_window) {
			chomp($line);
			my ($lineafid, $linename, $linetype, $linetz) = split ' ', $line, 4;
				if ($name eq $linename) {
					$flags{'afid'} = $lineafid;
					last;	
			}
		}
	}

	# BUSINESS RULE: We expose the primary AF names to the NCC (via CFG_NODE.cfg), but provision using only the secondary AFID.
	# By convention, the primary AFID has a 'p' as the last character and the secondary AFID has an 's' as the last character.
	# So, we simply swap the 'p' with an 's'.
	my $afid = $flags{'afid'};
	if (defined($flags{'source'}) && $flags{'source'} eq "TAPSS") {
		if (substr($afid, -1, 1) eq 'p') {
			substr($afid, -1) = 's';
		}
	}
	$flags{'afid'} = $afid;
	return $command;
}

# add-afwt, delete-afwt or display-afwt
# param1 - add, delete or display
sub do_afwt {
	my $action = $_[0];
	my @tmp = ();
	my $cmd_prefix = "${action}-afwt:";
	my @params = ("coid", "afid", "tid", "JAREAID", "comments", "group", "owner", "access");
	my $command = $cmd_prefix;

	for my $param (@params) {
		if (!libAux::empty($flags{$param})) {
			push(@tmp, "$param=\"$flags{$param}\"");
		}
	}

	$command .= join(",", @tmp) . ";\n";
	print $command;
	push(@commands, $command);

	return libAux::handle_response($command, "$action afwt");
}

# activates surveillance for access function
sub activate_secondary_node {
	set_AFID();

	# 2.) add-afwt
	if (do_afwt(&libAux::add) ne "") {
		libAux::log_print("$FAILURE", "$ERR_BACKOUT");
		return 1;
	}

	libAux::log_print("$SUCCESS", "Secondary node succesfully provisioned");

	return 0;
}

# start Main program here

libAux::debug_init($DBG_file);
libAux::debug_print("\n\nEnter CVoIP.pl at $now\n\n");

# FIXME: we should be smarter about responding to a SIGPIPE, and force a clean exit
$SIG{'PIPE'} = 'IGNORE';	# let's finish up on our own, even if the ssh dies out from under us.

($SUCCESS, $FAILURE, $succ_or_fail) = libAux::initiate();
libAux::log_init($flags{'log_file'}, $FAILURE);
libAux::set_node_line_term("\n");

my $retry_status = 98;
my $result = $retry_status;
for (my $login_count = 0; $login_count < 3 && $result == $retry_status; $login_count++) {
	# the node *sometimes* isn't ready for us in time, so a simple local retry might help
	$result = libAux::login($flags{'user'}, $flags{'password'}, "siltx01llg:~|psltx01llg:~", 10, $retry_status);
}

if ($result) {
	libAux::croak(1, "HOST|Login failed - aborting.");
	# not reached #
}

my $local_action = "";

given($flags{'action'}) {
	when ("ACTIVATION") {
		$local_action = &libAux::add;
	}

	when ("DEACTIVATION") {
		$local_action = &libAux::del;
	}

	when ("DUMP_ITN") {
		$local_action = &libAux::dsp;
	}
}

given($flags{'command'}) {
	when ("ADD_SET") {
		$result = activate_primary_node();
	}

	when ("DELETE_SET") {
		$result = deactivate_primary_node();
	}

	when ("ADD_ASS_ACT_SURV") {
		$result = activate_secondary_node();
	}

	when ("DELETE_ASS_ACT_SURV") {
		$result = deactivate_secondary_node();
	}

	when ("DISPLAY_ALL") {
		my $display_fmt = $flags{'display_fmt'};
		my @columns = ($display_fmt eq 'ERPIPE') ? qw(EXCEPTION_REPORT MSISDN NODEID ID3 ID4 ID5 MIN ESN requestorID MUID ) : qw(MDN MUID NODENAME);
		my $node_ID = $flags{'NODEID'};
		my $node_class = $flags{'NODECLASS'};
		my @displays = ();	# list of display arrays of hashrefs
		my @tmp_display = ();	# return value from handle_display function
		my $table = "";
		my $msg = "";

		if ($node_class eq "DDF") {
			if (do_co(&libAux::dsp) eq "") {
				@tmp_display = libAux::handle_display();
				push(@displays, @tmp_display);
			}

			if (do_surveillance(&libAux::dsp) eq "") {
				@tmp_display = libAux::handle_display();
				push(@displays, @tmp_display);
			}

			if (do_survopt(&libAux::dsp) eq "") {
				@tmp_display = libAux::handle_display();
				push(@displays, @tmp_display);
			}

			if (do_target(&libAux::dsp) eq "") {
				@tmp_display = libAux::handle_display();
				push(@displays, @tmp_display);
			}

			if (do_t1678cfci(&libAux::dsp) eq "") {
				@tmp_display = libAux::handle_display();
				push(@displays, @tmp_display);
			}
		}

		if ($node_class eq "SWITCH") {
			set_AFID();
			&libAux::wait_for("$flags{'MML_prompt'}", $cmd_wait);

			if (do_afwt(&libAux::dsp) eq "") {
				@tmp_display = libAux::handle_display();
				push(@displays, @tmp_display);
			}
		}

		my @targets = libAux::list_all($node_ID, @displays);
		my @merged_targets = libAux::merge_targets(@targets);

		($table, $msg) = libAux::gen_display($display_fmt, @merged_targets, @columns);
		libAux::log_print_list("$SUCCESS|LIST", @$table);
		libAux::audit_print($node_ID, @$table);
		for my $line (@$table) {
			libAux::debug_print("$line\n");
		}
	}

	when ("co") {
		$result = do_co("$local_action") eq "" ? 0 : 1;
	}

	when ("surveillance") {
		if ($local_action ne &libAux::dsp) {
			libAux::set_CFID();
		}
		$result = do_surveillance("$local_action") eq "" ? 0 : 1;
	}

	when ("survopt") {
		$result = do_survopt("$local_action") eq "" ? 0 : 1;
	}

	when ("target") {
		$result = do_target("$local_action") eq "" ? 0 : 1;
	}

	when ("t1678cfci") {
		$result = do_t1678cfci("$local_action") eq "" ? 0 : 1;
	}

	when ("afwt") {
		set_AFID();
		$result = do_afwt("$local_action") eq "" ? 0 : 1;
	}

	default {
		libAux::croak(1, "Unknown action: $flags{'action'} - aborting");
		# not reached #
	}
}

libAux::logout();
exit ($result);
