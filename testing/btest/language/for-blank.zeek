# @TEST-DOC: Some blank identifier test iterating over vectors and tables.
# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output
event zeek_init()
	{
	# These are here as I am/was concerned about frame usage.
	local a = "a canary";
	local b = "b canary";

	local vec = vector("a", "b", "c");
	local t1 = table(["keya"] = "a", ["keyb"] = "b", ["keyc"] = "c");
	local t2 = table(["a",1,T] = "a1a", ["b",2,F] = "b2b", ["c",3,T] = "c3c");
	local s = "the string";

	print "== vec";
	for ( _, v in vec )
		print v;
	print "canaries", a, b;

	print "== t1";
	for ( _, v in t1 )
		print v;
	print "canaries", a, b;

	print "== t2";
	for ( [_,c,_], v in t2 )
		print c, v;
	print "canaries", a, b;

	print "== t2";
	for ( _, v in t2 )
		print c, v;
	print "canaries", a, b;

	print "== s";
	local i = 0;
	for ( _ in s )
		++i;
	print "strlen(s)", i;
	print "canaries", a, b;
	}
