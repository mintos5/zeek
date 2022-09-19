# @TEST-DOC: Very basic testing of event groups with zeek_init / zeek_done.
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

event zeek_init()
	{
	print "zeek_init";

	# Disable the mydone group
	disable_event_group("mydone");
	}

# Disabled above and shouldn't show.
event zeek_done() &group="mydone"
	{
	print "zeek_done with group mydone";
	}

# This one isn't disabled.
event zeek_done()
	{
	print "zeek_done without group";
	}

event zeek_done() &group="mydone2"
	{
	print "zeek_done with group mydone2";
	}

# This isn't implemented, but maybe we should
event zeek_done() &group="mydone,mydone2"
	{
	print "zeek_done mydone,mydone2 (not implemented, shoudln't show)";
	}
