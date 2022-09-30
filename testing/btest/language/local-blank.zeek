# @TEST-DOC: Do not allow to use the blank identifier for locals.

# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
event zeek_init()
	{
	local _ = "1";
	}

#@TEST-START-NEXT
event zeek_init()
	{
	local _:string = "1";
	}

#@TEST-START-NEXT
event zeek_init()
	{
	local _:count= "1";
	}
