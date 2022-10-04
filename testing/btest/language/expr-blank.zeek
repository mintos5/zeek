# @TEST-DOC: Do not allow to reference tha blank identifier within.

# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
event zeek_init()
	{
	local vec = vector( "1", "2", "3" );
	for ( _, v in vec )
		print _;
	}
