# @TEST-DOC: Do not allow using the blank identifier for strings.

# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
event zeek_init()
	{
	local s = "the string";
	local len = 0;
	for ( _ in s )
		len += 1;
	print len;
	}
