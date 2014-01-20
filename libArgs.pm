# libArgs.pm
# Library for routines that perform validation on the command line arguments provided to the various interfaces.
# Usage: use libs::libArgs;
# Created by Paul Ireifej 12/05/2012
#

package libArgs;
use strict;
use warnings;
use feature "switch";
use libs::libAux qw(empty);		# FIXME: get the function import to work!!
use libs::libConfigN;	# FIXME: a slightly cleaner version of libConfig - to be reintegrated when fully tested
use IO::Handle;		# for "sysopen()"
use Fcntl;	# for sysopen's modes

# Note: The following parameters are assumed to be used by the node-specific file (known here as "main")
# (and, thus, should be declared using 'our'):
#		- %args
#			- $args{'failure'}
#		- %arg_defs
#		- %assoc_node_config
#		- $DEBUG
#		- $log_file
#		- %node_config
#		- $valid_LOG

#
# %arg_defs
#
# Describe all the command line args that we can provide to a given interface script.
# The structure of arg_defs is defined HERE, and common across everyone who uses it
# (including the below functions), but it is actually defined in each top-level node interface script.
# The goal of arg_defs is to guide (well, define) how to populate the %args hash.
#
# The presence of and values for each arg is derived from various sources, including:
#	- the flags with which we were invoked
#	- the attributes of our node-type & node config entries
#	- default values
# Each interface defines a master %arg_defs, as a single associative array, each of whose keys is an action code (or "*" for action-independent).
# 	- The value of each of *those* action keys is an array, where each element describes a single arg to the interface script.
#		- Each of those arg descriptions is a consistently-structured array, whose fields are as follows:
#			0:	The name of the arg in the %args hash (and as seen by the interface script)
#			1: A pointer to the hash serving as the source of the (starting) value of that arg (or else 0 if a purely synthesized value)
#			2:	A "criticality code" ("opt" or "req"), indicating whether that arg MUST appear in a (non-synth) source
#			3:	The name of the source attribute (for non-synth sources)
#			4: A pointer to a function ("ensure_xxx" for the xxx arg) that validates or derives the value (or else 0 if no function).
#				- A validation function takes two scalar arguments, those being the given arg value & that arg's "criticality code".
#				- It returns a pair of scalars (exactly one of which is "" on any given invocation):
#					- The value to be used (or "", if no value is to be used).
#					- An error message (or "", if successful)
#				- If defined, the fn is ALWAYS called (even if the identified source is missing), and thus can provide a default value.
#				- The function does NOT do any logging on its own (instead using the error msg return value).
#				- Dependencies can trigger an error *message* IFF that arg is "req".
#			5. A brief free-form text string describing this arg
#			6. The maximum length for the arg
#			7. The default value provided for the arg if no value is given
# Note that the order of arg descriptions within an action-code block MATTERS (when one depends on ealier ones)!

#
# Marshal the %main::args hash of arguments that can/must be provided to the interface script for the specified action.
# Guided by main::%arg_defs.
#
# Params:
#	$_[0]:	The code for a particular action. A '*' identifies args that apply independent of action.
#	$_[1]:	A ptr to the caller's invalid_args array (to which we might add entries)
#
# For each arg, see if it's in the specified source hash or can otherwise be generated (via its "ensure" function).
# 	- If not, but it is required, then add it to the global @invalid_args list.
#	- If we have a legitimate value, add the key-value pair to the global %args hash.
# The %args hash thus contains the args and values that will be passed as arguments to our interface script.
# We use this to map the scheduler parameters to native parameter names for the interface.
# Returns: nothing.
#
sub get_args($\@) {
	my $action = $_[0];
	libAux::debug_print("get_args($action)\n");
	if (! defined($main::arg_defs{$action})) {
		libAux::croak(1, "libArgs::getargs: no main::arg_defs for action '$action'");
	}
	my @action_args = @{$main::arg_defs{$action}};		# args specific to the given action
	my $err_msgs_ref = $_[1];

ARG:
	foreach my $arg_spec_ptr (@action_args) {
		my ($arg_name, $src_ptr, $criticality, $src_name, $ensure_fn, $comment, $max_length, $default, $mistake) = @{$arg_spec_ptr};
		if (! defined($comment)) {
			libAux::croak(1, "libArgs::getargs: malformed entry in main::arg_defs for '$action' => '$arg_name' (too few fields)");
		}
		if (defined($mistake)) {
			libAux::croak(1, "libArgs::getargs: malformed entry in main::arg_defs for '$action' => '$arg_name' (too many fields)");
		}
		my $arg_value = "";
		my $err_msg = "";
		if ($src_ptr != 0 && defined($src_ptr->{$src_name})) {
			$arg_value = $src_ptr->{$src_name};
		}
		if ($arg_value eq "" && !libAux::empty($default)) {
			$arg_value = $default;
		}
		if ($ensure_fn != 0) {
			($arg_value, $err_msg) = &$ensure_fn($arg_value, $criticality);
		}
		if ($arg_value eq "") {
			if (! libAux::empty($err_msg)) {
				push(@$err_msgs_ref, "$arg_name ($comment): $err_msg");
			} elsif ($criticality eq "req") {
				push(@$err_msgs_ref, "$arg_name ($comment): required but null");
			}
			next ARG;
		}
		if (! libAux::empty($max_length)) {
			my $arg_length = length($arg_value);
			if ($arg_length > $max_length) {
				libAux::croak(1, "libArgs::getargs: malformed entry in main::arg_defs for '$action' => '$arg_name' ($arg_value exceeds max length of $max_length)");
			}
		}
		$main::args{$arg_name} = $arg_value;
		# libAux::debug_print("parsed: $arg_name => $arg_value\n");
	}
} # end get_args()

#
# Debug routine to dump the %arg_defs table
# Args:
#		$_[0]: pathname of debug file to use
#
sub dump_arg_defs($) {
	if (! $main::DEBUG) {
		return;
	}
	my $DBG_file = $_[0];
	open DBG, ">> $DBG_file" or libAux::croak(1, "Open my debug file '$DBG_file' failed: $!");
	print DBG "** DBG $0: arg_defs\n";
	print STDERR "** DBG $0: arg_defs\n";
	foreach my $action_code (keys %main::arg_defs) {
		my @action_args = @{$main::arg_defs{$action_code}};
		print DBG "**\tAction Code $action_code\n";
		print STDERR "**\tAction Code $action_code\n";
		foreach my $arg_spec_ptr (@action_args) {
			my @arg_spec = @{$arg_spec_ptr};
			my $arg_spec = join(", ", @arg_spec[1 .. 4]);
			print DBG "**\t    $arg_spec[0] => [ $arg_spec ]\n";
			print STDERR "**\t    $arg_spec[0] => [ $arg_spec ]\n";
		}
	}
	close DBG;
} # end dump_arg_defs()

#
# Debug routine to display all the incoming arguments from the calling script.
# Just tail that "DBG" file and run the code!
# Args:
#	- $_[0]: the name of the node
#	- $_[1]: a ptr to the the flags hash
sub dump_flags($\%) {
	my $flags_ptr = $_[1];
	my %flags = %$flags_ptr;
	libAux::debug_print("Incoming parameters to $_[0]\n");
	foreach my $name (keys(%flags)) {
		libAux::debug_print("\t$name=$flags{$name}\n");
	}
} # end dump_flags()

#
# dump_node_config
# Args:
#	- $_[0]:	the name of the node
#
sub dump_node_config($) {
	libAux::debug_print("Node config for node $_[0]:\n");
	for (keys(%main::node_config)) {
		libAux::debug_print("    $_ = $main::node_config{$_}\n ");
	}
} # end dump_node_config()

#
# get_user_pass()
# Given a NODEID (arg0), look up and lock the least-recently-used user ID
# for that node, along with its associated password.
# We lock by the IP address of that node, rather than the NODEID itself,
# in case a given box has multiple persona as seen by ELEAT.
# Args:
#		- 0: a NODEID that uses mulltiple user IDs
#		- 1: the IP address of that node
#		- 2: the lock dir we are to use (which can be shared across nodes - filenames will not collide)
# Returns a ref to a hash containing these elements:
#		- LOGON: the user ID
#		- PASS: the decrypted password
#		- LOCK_FH: the file handle holding the lock on the allocation of LOGON (caller should close this at end of session)
#		- LOCK_FILE: the pathname of the lockfile (caller should unlink this at end of session)
#		- err_msg: the error message describing why this invocation failed
#		- warnings (optional): if needed, a ref to a list of non-fatal warnings encounterd along the way
# A given return with have either err_msg XOR everything else defined.
#
# The LOCK_FH filehandle represents the lock on the returned (LOGON, PASS) pair.
# Caller must keep it open until the end of the session, at which point close & unlink it.
#
sub get_user_pass($$$) {
	my ($node_ID, $node_IP, $lock_dir) = ($_[0], $_[1], $_[2]);
	my @warnings = ();
	my $result = {};
	my @candidates = libConfig::getCfgListByType('USERID', 'NODEID', $node_ID);
	if (! @candidates) {
		$result->{'err_msg'} = "no supplemental user IDs found for NODEID '$node_ID'";
		return $result;
	}
	my $num_candidates = scalar @candidates;

	# use index of most-recently used candidate as $first_candidate
	my $last_file = $lock_dir . '/last_used_' . $node_IP;
	my $first_candidate = 0;		# default
	my $success = open(my $LAST, '<', $last_file);
	if (defined($success)) {
		read($LAST, my $indx, 10);
		chomp($indx);
		if (defined($candidates[$indx])) {
			$first_candidate = ($indx + 1) % $num_candidates;
		}
		close($LAST);
	}
	
	# For each candidate, beginning with the first, see if it's free by trying to claim it.
	# If that works, we're done.  If not, see if the lock is stale & if so remove it.
	my ($LOCK_FH, $LOCK_FILE, $LOGON, $PASS, $true_index);
	for (my $i = $first_candidate; $i < $first_candidate + $num_candidates; $i++) {
		$true_index = $i % $num_candidates;
		my $candi = $candidates[$true_index];
		($LOGON, $PASS) = ($candi->{'LOGON'}, $candi->{'PASS'});
		$LOCK_FILE = $lock_dir . '/' . $node_IP . '_' . $LOGON;
		$success = sysopen($LOCK_FH, $LOCK_FILE, O_RDWR|O_CREAT|O_EXCL);
		if ($success) {
			print $LOCK_FH "$$\n";
			last;
		}
		# sysopen failed => could not set the lock.
		if ($! ne 'File exists') {
			push(@warnings, "Unexpected failure in opening lockfile $LOCK_FILE: $! (ignored; trying next user ID candidate)");
			next;
		}
		# LOCK_FILE may be stale - let's check
		my $status = open($LOCK_FH, '<', $LOCK_FILE);
		if (! defined($status)) {
			push(@warnings, "Simple open of lockfile '$LOCK_FILE' failed: $! (ignored; trying next user ID candidate)");
			next;	# can't tell if lockfile is valid, so just move on to next candidate
		}
		read($LOCK_FH, my $pid, 10);
		chomp($pid);
		my $alive = kill(0, ($pid));	# send signal 0 to $pid as a benign "are you there?" poke
		if ($alive) {
			next;		# the lockfile is still good => try the next candidate
		}
		# there's no process with that PID (and our user ID) any more => stale lock, so clean it up & try again
		close($LOCK_FH);
		my $count = unlink($LOCK_FILE);
		if ($count == 0) {
			push(@warnings, "Failed to unlink stale lockfile '$LOCK_FILE': $! (ignored, trying next user ID candidate)");
			next;
		}
		push(@warnings, "Removed stale lockfile '$LOCK_FILE' (PID = $pid)");
		$success = sysopen($LOCK_FH, $LOCK_FILE, O_RDWR|O_CREAT|O_EXCL);
		if ($success) {
			print $LOCK_FH "$$\n";
			last;
		}
	}
	if (! $success) {
		$result->{'err_msg'} = "no logon currently available";
		return $result;
	}
	my $status = open($LAST, '>', $last_file);
	if (defined($status)) {
		print $LAST "$true_index\n";
		close($LAST);
	} else {
		push(@warnings, "Open of $last_file failed: $! (not updated)");	# our round-robin allocation is broken, but o/w till usable
	}
	$result->{'LOCK_FH'} = $LOCK_FH;
	$result->{'LOCK_FILE'} = $LOCK_FILE;
	$result->{'LOGON'} = $LOGON;
	$result->{'PASS'} = libConfig::passDecrypt($PASS);
	if (@warnings) {
		$result->{'warnings'} = \@warnings;
	}
	return $result;
} # end get_user_pass()

######################################################################
# Arg validation functions
# See the comments preceding get_args() (above) for the definition & usage.
#
# Please keep this section in alphabetical order, by function name!
#
######################################################################

# confirm we're supposed to use access type 7 (SSH level 2)
sub ensure_access_type($$) {
	my ($access_type, $criticality) = ($_[0], $_[1]);
	if ($access_type != 7) {
		my $err_msg = ($criticality eq "req") ? "invalid accesstype: '$access_type'" : "";
		return ("", $err_msg);
	}
	return ($access_type, "");	# we don't need to send to interface - we just had to check it was good
} # end ensure_access_type()

# confirm the access type is numeric
sub ensure_access_type_gen($$) {
	my ($access_type, $criticality) = ($_[0], $_[1]);
	if ($access_type !~ m/\d+/) {
		my $err_msg = ($criticality eq "req") ? "invalid accesstype: '$access_type'" : "";
		return ("", $err_msg);
	}
	return ($access_type, "");
} # end ensure_access_type()

sub ensure_action($$) {
	my ($action_ID, $criticality) = ($_[0], $_[1]);
	if ($action_ID !~ m/\d+/) {
		my $err_msg = ($criticality eq "req") ? "numeric value required; got '$action_ID'" : "";
		return ("", $err_msg);
	}
	return (libConfig::getActionType($action_ID), "");
} # end ensure_action()

sub ensure_af_ID($$) {
	my ($af_ID, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($af_ID, "AFID", 257, 384);
} # ensure_af_ID()

# af ID for BVoIP and CVoIP
sub ensure_af_ID_for_VoIP($$) {
	my ($af_ID, $criticality) = ($_[0], $_[1]);
	return libArgs::ensure_length($af_ID, 1, 16);
} # ensure_af_ID_for_VoIP()

# requires that the MDN & MUID args have been processed first
sub ensure_case_ID($$) {
	my ($case_ID, $criticality) = ($_[0], $_[1]);
	if ($case_ID ne "") {
		return ($case_ID, "");
	}

	if (libAux::empty($main::args{'MDN'})) {
		my $err_msg = ($criticality eq "req") ? "error creating case_ID: missing MDN" : "";
		return ("", $err_msg);
	}
	if (libAux::empty($main::args{'MUID'})) {
		my $err_msg = ($criticality eq "req") ? "error creating case_ID: missing MUID" : "";
		return ("", $err_msg);
	}
	return ($main::args{'MDN'} . $main::args{'MUID'}, "");
} # end ensure_case_ID()

sub ensure_ccc_ID($$) {
	my ($ccc_id, $criticality) = ($_[0], $_[1]);

	if ($ccc_id ne "") {
		return ($ccc_id, "");
	}

	return (1, "");
} # ensure_ccc_ID

# return any associated Xcipio node as the CDDF
sub ensure_cddf($$) {
	my $assoc_list = $_[0];
	my @assoc_nodes = split(/\+/, $assoc_list);
	foreach my $assoc_node (@assoc_nodes) {
		my %node_config = libConfig::getNodeCfgById($assoc_node);
		if (defined($node_config{'NODETYPEID'}) && $node_config{'NODETYPEID'} =~ /Xcipio/i) {
			if (defined(%main::assoc_node_config)) {
				%main::assoc_node_config = %node_config;
			}
			return ($assoc_node, "");
		}
	}
	return ("", "");
} # end ensure_cddf()

# confirm the CFID (collection function ID) is numeric & < 1000
sub ensure_CFID($$) {
	my ($CFID, $criticality) = ($_[0], $_[1]);
	if ($CFID !~ m/\d+/ || $CFID > 999) {
		my $err_msg = ($criticality eq "req") ? "invalid CFID: '$CFID'" : "";
		return ("", $err_msg);
	}
	return ($CFID, "");
} # end ensure_CFID()

sub ensure_ciss($$) {
	my $ciss = $_[0];
	
	if ($ciss eq "" || $ciss =~ m/NONE/i) {
		return ("N", "");
	}
	return ("Y", "");
} # end ensure_ciss()

sub ensure_city($$) {
	my $city = $_[0];
	if ($city eq "") {
		return ("none", "");	# default
	}
	return ($city, "");
} # end ensure_city()

# CLLI for BVoIP and CVoIP
sub ensure_CLLI_for_VoIP($$) {
	my ($CLLI, $criticality) = ($_[0], $_[1]);
	if ($CLLI eq "") {
		my $err_msg = ($criticality eq "req") ? "invalid CLLI: '$CLLI'" : "";
		return ("", $err_msg);
	}
	# Business Rule: expose primary AF namevia CFG_NODE.cfg, but use secondary
	$CLLI =~ s/PRI/SEC/g;
	return $CLLI;
} # end ensure_CLLI_for_VoIP

sub ensure_cmd_wait($$) {
	my $cmd_wait = $_[0];
	if ($cmd_wait ne "") {
		return ($cmd_wait, "");
	}
	if ($main::node_config{'CMD_WAIT'} eq "") {
		return (20, "");		# default
	}
	return ($main::node_config{'CMD_WAIT'}, "");
} # end ensure_cmd_wait()

# Canonicalize CNUM to 10 digit number. Remove leading 1 or +1 as well as interior punctuation (- (). )
sub ensure_CNUM($$) {
	my $CNUM = $_[0];
	if ($CNUM eq "") {
		return ("", "");
	}
	return canonicalize_tel($CNUM, 'CNUM', 1);
} # end ensure_CNUM()

sub ensure_coid($$) {
	my ($coid, $criticality) = ($_[0], $_[1]);
	if ($coid ne "") {
		return ($coid, "");
	}

	if (libAux::empty($main::args{'MUID'})) {
		my $err_msg = ($criticality eq "req") ? "error composing coid: missing MUID" : "";
		return ("", $err_msg);	# the remaining alternatives all depend on MUID
	}
	my $muid = $main::args{'MUID'};

	if (! libAux::empty($main::args{'MIN'})) {
		return ($main::args{'MIN'} . $muid, "");
	}

	if (! libAux::empty($main::args{'MDN'})) {
		return ($main::args{'MDN'} . $muid, "");
	}
	
	my $err_msg = ($criticality eq "req") ? "error composing coid: missing MDN & MIN" : "";
	return ("", $err_msg);
} # end ensure_coid()

sub ensure_combined($$) {
	my $combined = $_[0];
	
	if ($combined ne "") {
		return ($combined, "");
	}
	
	return ("Y", "");
} # end ensure_combined()

# requires that ACTIONTYPENUM & node config NODECLASS have been defined first
sub ensure_command($$) {
	my $node_class = $main::node_config{'NODECLASS'};
	my $object = $main::flags{'object'};
	my $action_type_num = $main::flags{'ACTIONTYPENUM'};
	my $gateway_node_class = "DDF";
	my $access_function_node_class = "SWITCH";

	if (defined($main::flags{'object'})) {
		return "$object";
	}

	if ($action_type_num == 0) {
		if ($node_class eq $access_function_node_class) {
			return "ADD_ASS_ACT_SURV";
		}
	  	if ($node_class eq $gateway_node_class) {
			return "ADD_SET";
		}
	}

	if ($action_type_num == 1) {
		if ($node_class eq $access_function_node_class) {
			return "DELETE_ASS_ACT_SURV";
		}
	  	if ($node_class eq $gateway_node_class) {
			return "DELETE_SET";
		}
	}

	if ($action_type_num == 9) {
		if ($node_class eq $access_function_node_class) {
			return "DISPLAY_ASS_ACT_SURV";
		}
	  	if ($node_class eq $gateway_node_class) {
			return "DISPLAY_SET";
		}
	}

	if ($action_type_num == 16) {
		return "DISPLAY_ALL";
	}

	if ($action_type_num == 18) {
		return "DISPLAY_ALL";
	}

	return "";
} # end ensure_command

# the connection state parameter is currently read-only
# just return with "" for now if this function is ever called
sub ensure_connect_state($$) {
	return ("", "");

	my $connect_state = $_[0];

	given ($connect_state) {
		when ([qw(ACTIVE INACTIVE FAILED)]) {
			return ($connect_state, "");
		}
		
		when ("") {
			return ("INACTIVE", "");	# default
		}
	}
	return ("", "unknown connect_state: '$connect_state'");
}

sub ensure_date_YYYY_MM_DD($$) {
	my $date = $_[0];
	
	# FIXME: the month & day checks here should be more precise - probably should be done separately
	if ($date ne "" && $date !~ m/2[01]\d\d-[0-1]\d-[0-3]\d/) {
		return ("", "invalid date: '$date' (should be YYYY-MM-DD)");
	}
	
	return ($date, "");
} # end ensure_date_YYYY_MM_DD()

sub ensure_dcs_ID($$) {
	my ($dcs_ID, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($dcs_ID, "DCSID", 1, 16, 1);
}

sub ensure_dest_IP($$) {
	my ($dest_IP, $criticality) = ($_[0], $_[1]);

	if ($dest_IP ne "") {
		return ($dest_IP, "");
	}

	return ("","");
} # ensure_dest_IP

sub ensure_dest_port($$) {
	my ($dest_port, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($dest_port, "dest_port", 1, 65535);
} # ensure_dest_port

#
# ensure_display_fmt()
# If it *has* a value, ensure it's one we can handle over in libAux::gen_display().
#
sub ensure_display_fmt($$) {
	my ($fmt, $criticality) = ($_[0], $_[1]);
	
	given ($fmt) {
		when ([qw(HTML PIPE ERPIPE)]) {
			return ($fmt, "");
		}
		
		when ("") {
			return ("", "");
		}
	}
	return ("", "unknow display format: '$fmt'");
} # end ensure_display_fmt()

sub ensure_ecp_ID($$) {
	my ($ecp_ID, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($ecp_ID, "ECPID", 1, 128, 1);
} # end ensure_ecp_ID()

sub ensure_filter($$) {
	my $filter = $_[0];

	given ($filter) {
		when ([qw(VO VI VV ALL)]) {
			return ($filter, "");
		}
		
		when ("") {
			return ("ALL", "");	# default
		}
	}
	return ("", "unknown filter: '$filter'");
}

sub ensure_grp_ID($$) {
	my ($grp_ID, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($grp_ID, "GRPID", 0, 265);
} # end ensure_grp_ID()

sub ensure_if_ID($$) {
	my ($if_ID, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($if_ID, "if_ID", 1, 5, 1);
} # ensure_if_ID

sub ensure_immbill($$) {
	my ($immbill, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($immbill, "IMMBILL", 0, 255, 0);
}

sub ensure_IMSI($$) {
	return ensure_MIN($_[0], $_[1], 'IMSI');
} # end ensure_IMSI()

sub ensure_ITN($$) {
	my $ITN = $_[0];
	if ($ITN eq "") {
		return ("", "");
	}
	if ($ITN !~ /^\d+$/ ) {
		return ("", "an ITN must be digits, not '$ITN'");
	}
	my $MAX_ITN_LENGTH = libConfig::getEleatCfgVal('MAX_ITN_LENGTH');
	my $ITN_len = length($ITN);
	if ($ITN_len > $MAX_ITN_LENGTH) {
		return ("", "an ITN must be no longer than $MAX_ITN_LENGTH digits, not $ITN_len");
	}
	return ($ITN, "");
} # end ensure_ITN

sub ensure_key($$) {
	my ($key, $criticality) = ($_[0], $_[1]);

	if (libAux::empty($main::args{'encryption'})) {
		my $err_msg = ($criticality eq 'req') ? 'error creating key: missing encryption' : "";
		return ("", $err_msg);
	}

	my $encryption = $main::args{'encryption'};
	
	if ($encryption ne 'NONE' && $key eq "") {
		return ("", "");
	}
	
	return ($key, "");
} # end ensure_key()

sub ensure_length($$) {
	my ($value, $min_length, $max_length) = ($_[0], $_[1], $_[2]);
	my $length = length($value);
	
	if ($value eq "") {
		return ("", "");
	}

	if ($length < $min_length) {
		return ("", "$value must be at least $min_length long, not $length long");
	}

	if ($length > $max_length) {
		return ("", "$value must be at most $max_length long, not $length long");
	}

	return ($value, "");
}

sub ensure_location($$) {
	my $criticality = $_[1];
	if (libAux::empty($main::flags{'SURVTYPE'})) {
		my $err_msg = ($criticality eq "req") ? "error creating location missing SURVTYPE" : "";
		return ("", $err_msg);
	}
	my $surv_type = $main::flags{'SURVTYPE'};
	
	if ($surv_type ne "" && $surv_type =~ m/WLOC/i) {
		return ("Y", "");
	}
	return ("N", "");
} # end ensure_location()

# override given LOGFILE flag with (global) value from libFileUtils:procDoArgs()
sub ensure_log($$) {
	my $log = $_[0];
	{
		no warnings 'once';		# get clean compilation. Remove if $main::valid_LOG ever used in multiple spots in this file.
		if ($main::valid_LOG && ! libAux::empty($main::log_file)) {
			$log = $main::log_file;
		}
	}
	return ($log, "");
} # end ensure_log()

# Canonicalize MDN to 10 digit number. Remove leading 1 or +1 as well as interior punctuation (- ().)
sub ensure_MDN($$) {
	my $MDN = $_[0];
	if ($MDN eq "") {
		return ("", "");
	}
	return canonicalize_tel($MDN, 'MDN', 0);
} # end ensure_MDN()

sub ensure_media_restrict($$) {
	my ($media_restrict, $criticality) = ($_[0], $_[1]);

	if ($media_restrict ne "") {
		return ($media_restrict, "");
	}

	return ("XGROUPCALLS", "");
} # end ensure_media_restrict

sub ensure_member($$) {
	my ($member, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($member, "member", 0, 1951);
}

# a.k.a. IMSI, so do double duty via optional 3rd arg (see ensure_IMSI())
sub ensure_MIN($$;$) {
	my ($MIN, $criticality) = ($_[0], $_[1]);
	my $name = (defined($_[2])) ? $_[2] : 'MIN';
	my $req_len = 15;
	
	if ($MIN eq "") {
		return ("", "");
	}

	if ($MIN !~ /^\d*$/) {
		return ("", "$name must be numeric, not '$MIN'");
	}

	my $min_len = length($MIN);
	if ($min_len != $req_len) {
		return ("", "$name must be $req_len digits long, not $min_len long");
	}
	return ($MIN, "");
} # end ensure_MIN()

# requires that the IMSI & Alpha MUID args have been processed first
sub ensure_MIN_case_ID($$) {
	my ($case_ID, $criticality) = ($_[0], $_[1]);
	if ($case_ID ne "") {
		return ($case_ID, "");
	}

	if (libAux::empty($main::args{'IMSI'})) {
		my $err_msg = ($criticality eq "req") ? "error creating case_ID: missing IMSI" : "";
		return ("", $err_msg);
	}

	if (libAux::empty($main::args{'MUID'})) {
		my $err_msg = ($criticality eq "req") ? "error creating case_ID: missing MUID" : "";
		return ("", $err_msg);
	}
	return ($main::args{'IMSI'} . $main::args{'MUID'}, "");
} # end Ensure_min_case_ID()

# explicitly allow an empty value (""), since it might be optional
sub ensure_MUID($$) {
	my $MUID = $_[0];
	if ($MUID !~ /^\d*$/) {
		return ("", "MUID must be numeric, not '$MUID'");
	}
	return ($MUID, "");
} # end ensure_MUID()

# explicitly allow an empty value (""), since it might be optional
sub ensure_MUID_alpha($$) {
	my $MUID = $_[0];
	$MUID = uc $MUID;
	if ($MUID !~ /^[a-zA-Z]*$/) {
		return ("", "MUID must be alpha, not '$MUID'");
	}
	return ($MUID, "");
} # end ensure_MUID_alpha()

# this assumes "cnum" has already been processed
sub ensure_numcalls($$) {
	my ($numcalls, $criticality) = ($_[0], $_[1]);

	if ($numcalls ne "") {
		return ($numcalls, "");
	}

	if (libAux::empty($main::args{'cnum'})) {
		my $err_msg = ($criticality eq "req") ? "error creating numcalls: missing cnum" : "";
		return ("", $err_msg);
	}

	my @cnum_list = split(/\+/, $main::args{'cnum'});	# calculate number of CNUMs, in case nothing passed in

	return ($#cnum_list + 2, "");
} # end ensure_numcalls()

sub ensure_num_CCC($$) {
	my ($num_CCC, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($num_CCC, "NUMCCC", 0, 30);
} # end ensure_num_CCC()

sub ensure_own_port($$) {
	my ($own_port, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($own_port, "own_port", 1000, 65535, 0);
} # ensure_own_port

sub ensure_priority($$) {
	my ($priority, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($priority, "priority", 1, 16);
} # end ensure_priority()

sub ensure_rcv_time($$) {
	my $rcv_time = $_[0];
	if ($rcv_time eq "") {
		return ("12:00", "");	# default
	}
	return ($rcv_time, "");
} # end ensure_rcv_time()

sub ensure_req_state($$) {
	my $req_state = $_[0];
	if ($req_state eq "") {
		return ("ACTIVE", "");	# default
	}
	given ($req_state) {
		when ([qw(ACTIVE INACTIVE)]) {
			return ($req_state, "");
		}
		
		when ("") {
			return ("", "");
		}
	}
	return ("", "unknown req_state: '$req_state'");
}

sub ensure_requestor($$) {
	my $ID = $_[0];
	if ($ID eq "") {
		return ("ELEAT", "");		# default
	}
	return ($ID, "");
} # end ensure_requestor()

# args{'services'} must already be defined
sub ensure_service_type($$) {
	my ($service_type, $criticality) = ($_[0], $_[1]);
	if ($service_type ne "") {
		if (defined($libAux::service_types{$service_type})) {
			return ($service_type, "");
		}
		return ($service_type, "error creating service_type: $service_type is invalid");
	}
	
	if (libAux::empty($main::args{'services'})) {
		my $err_msg = ($criticality eq "req") ? "error creating service_type: missing services" : "";
		return ("", $err_msg);
	}
	my $services = $main::args{'services'};
	
	foreach my $service_type ( keys %libAux::service_types ) {
		if ($services =~ m/$service_type/i) {
			return ($service_type, "");
		}
	}
	
	return ("", "");
} # end ensure_type()

sub ensure_services($$) {
	my $services = $_[0];
	if ($services eq "") {
		return ("IMSI", "");	# default
	}
	return ($services, "");
} # end ensure_services()

sub ensure_sms($$) {
	my $sms = $_[0];
	
	if ($sms eq "" || $sms =~ m/NONE/i) {
		return ("N", "");
	}
	return ("Y", "");
} # end ensure_sms()

sub ensure_stop_date($$) {
	my $stop_date = $_[0];
	if ($stop_date eq "") {
		return ("12/31/2037", "");	# default (end of UNIX time)
	}
	return ($stop_date, "");
} # end ensure_stop_date

# FIXME: the default for a stop_time should be 23:45 for true surveillance; 23:59 for mobile locate
sub ensure_stop_time($$) {
	my $stop_time = $_[0];
	if ($stop_time eq "") {
		return ("23:59", "");	# default
	}
	return ($stop_time, "");
} # end ensure_stop_time

sub ensure_surv_type($$) {
	my $surv_type = $_[0];

	if ($surv_type eq "") {
		return ("", "");
	}

	# return "CD" if the trace type is either Data or Data + Location
	# scheduler passes in values DATA or DWLOC
	if ($surv_type =~ m/^D/i) {
		return("CD","");
	# return "CC" if the trace type is either Content or Content + Location
	# scheduler passes in values CONTENT or CWLOC
	} elsif ($surv_type =~ m/^C/i) {
		# business rule: if they request "CONTENT" from the TAPSS page, they would also get "DATA" (thus, "ALL")
		if (defined($main::args{'source'}) && $main::args{'source'} eq 'TAPSS' && $surv_type eq "CONTENT") {
			return ("ALL","");
		}
		return ("CC","");
	} elsif ($surv_type =~ m/^ALL/i) {
		return("ALL","");
	}

	return ("", "Surveillance Type '$surv_type' unknown.");
} # end ensure_surv_type()

sub ensure_tmp($$) {
	my $tmp_file = $_[0];
	my $ELEATROOT = libConfig::getEleatCfgVal('ELEATROOT');
	if ($tmp_file eq "") {
		# ensure node_config{'NODETYPEID'} is there before accessing it!
		my $node_type = defined($main::node_config{'NODETYPEID'}) ? $main::node_config{'NODETYPEID'} : 'UNKNOWN_TYPE';
		$tmp_file = "$ELEATROOT/tmp/$node_type.$$.tmp";		# provide a default
	} elsif ($tmp_file =~ /^\/tmp\//) {
		$tmp_file = "$ELEATROOT" . $tmp_file;		# ensure we don't use /tmp
	}
	return ($tmp_file, "");
} # end ensure_tmp()

sub ensure_tid($$) {
	my ($tid_ID, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($tid_ID, "TID", 1, 10000, 1);
}

sub ensure_trace_level($$) {
	my ($trace_level, $criticality) = ($_[0], $_[1]);
	return ensure_int_range($trace_level, "Trace level", 0, 4);
} # end ensure_trace_level()

sub ensure_transport($$) {
	my $transport = $_[0];
	if ($transport eq "") {
		return ("TCP", "");	# default
	}
	given ($transport) {
		when ([qw(TCP UDP)]) {
			return ($transport, "");
		}
		
		when ("") {
			return ("", "");
		}
	}
	return ("", "unknown transport: '$transport'");
}

sub ensure_version($$) {
	my $version = $_[0];

	given ($version) {
		when ([qw(2 3 4 0700005V2)]) {
			return ($version, "");
		}
		
		when ("") {
			return ("2", "");
		}
	}
	return ("", "unknown version: '$version'");
}

# FIXME: put default value functionality into arg_defs logic
sub ensure_y_n($$) {
	my $boolean = $_[0];

	if ($boolean =~ m/y[es]/i || $boolean =~ m/y/i) {
		return "Y";
	}

	if ($boolean =~ m/n[o]/i || $boolean =~ m/n/i) {
		return "N";
	}

	return "Y";
} # end ensure_y_n()

#
# Ensure that the given value is an integer
# and falls within the given range
# Args:
#	- $_[0]: the value to be ensured
#	- $_[1]: name to be printed in the error messages
#	- $_[2]: minimum value in the range to be checked
#	- $_[3]: maximum value in the range to be checked
#	- $_[4]: (optional) default value to use if the given value eq ""
sub ensure_int_range($$$;$) {
	my $integer = $_[0];
	my $name = $_[1];
	my $min = $_[2];
	my $max = $_[3];
	my $default = (defined($_[4])) ? $_[4] : "";

	if ($default ne "" && $integer eq "") {
		return ($default, "");
	}
	if ($integer eq "") {
		return($integer, "");
	}
	if ($integer !~ /^\d*$/) {
		return ("", "$name must be numeric, not '$integer'");
	}
	if (($integer < $min) || ($integer > $max)) {
		return ("", "$name must be between $min and $max, not '$integer'");
	}
	return ($integer, "");
} # end ensure_int_range()

#
# canonicalize_tel
#
# Canonicalize a (NANP) telephone number to 10-digit number.
# Remove leading 1 or +1 as well as punctuation (- ().).
# Arg0 is the tel.
# Arg1 tells us what to call the tel in any error messages.
# Arg2 is 1 or 0, according to whether Arg0 is allowed to be a >list< of tels or not.
#		- Lists are separated by "+".
# Return pair, just as with ensure_* functions.
sub canonicalize_tel($$$) {
	my ($tel_src, $tel_name, $can_be_list) = ($_[0], $_[1], $_[2]);
	my $req_len = 10;

	my @tel_list = $can_be_list ? split(/\+/, $tel_src, -1) : ($tel_src);

	my $tel_str = "";
	foreach my $tel (@tel_list) {
		$tel =~ s/[\.\ \-\(\)]+//g;		# remove any punctuation
		if (length($tel) != 10) {		# for testing, an arbitrary telephone number with a leading 1 may be used, which is typically invalid
			$tel =~ s/^(1|\+1)//;		# strip any "1" or "+1" prefix
		}
		if ($tel !~ /^\d+$/ ) {
			return ("", "a $tel_name must be digits, not '$tel'");
		}
		my $tel_len = length($tel);
		if ($tel_len != $req_len) {
			return ("", "a $tel_name must be $req_len digits long, not '$tel' ($tel_len digits) from raw '$tel_src'");
		}
		$tel_str .= (($tel_str ne "") ? '+' : "") . $tel;
	}
	return ($tel_str, "");
} # end caconicalize_tel()

1;
