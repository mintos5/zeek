// See the file "COPYING" in the main distribution directory for copyright.

// Auxiliary information associated with identifiers to aid script
// optimization.

#pragma once

#include <set>

#include "zeek/IntrusivePtr.h"

namespace zeek::detail {

class Expr;
class Stmt;

using ExprPtr = IntrusivePtr<Expr>;

#define NO_DEF -1

class IDDefRegion {
public:
	IDDefRegion(const Stmt* s, bool maybe, int def);
	IDDefRegion(int stmt_num, int level, bool maybe, int def);
	IDDefRegion(const Stmt* s, const IDDefRegion& ur);

	void Init(bool maybe, int def)
		{
		if ( def != NO_DEF )
			maybe_defined = true;
		else
			maybe_defined = maybe;

		defined = def;

		ASSERT(defined < 50000 && defined > -50000);
		}

	void Dump() const;

	// Number of the statement for which this region applies *after*
	// its execution.
	int start_stmt;

	// Number of the statement that this region applies to, *after*
	// its execution.
	int end_stmt = NO_DEF;	// means the region hasn't ended yet

	// Degree of confluence nesting associated with this region.
	int block_level;

	// Identifier might be defined in this region.
	bool maybe_defined;

	// If not NO_DEF, then the statement number of either the identifier's
	// definition, or its confluence point if multiple, differing
	// definitions come together.
	int defined;
};

class IDOptInfo {
public:
	IDOptInfo(const ID* id)	{ my_id = id; }

	void Clear();

	void AddInitExpr(ExprPtr init_expr);
	const std::vector<ExprPtr>& GetInitExprs() const
		{ return init_exprs; }

	bool IsTemp() const	{ return is_temp; }
	void SetTemp()		{ is_temp = true; }

	// Called when the identifier is defined via execution of the
	// given statement.  "conf_blocks" gives the full set of
	// surrounding confluence statements.  It should be processed
	// starting at conf_start (note that conf_blocks may be empty).
	void DefinedAt(const Stmt* s,
	               const std::vector<const Stmt*>& conf_blocks,
	               int conf_start);

	// Called upon encountering a "return" statement.
	void ReturnAt(const Stmt* s);

	// Called when the current region ends with a backwards branch,
	// possibly across multiple block levels, occurring at "from"
	// and going into the block "to".
	void BranchBackTo(const Stmt* from, const Stmt* to);

	// Called when the current region ends at statement end_s with a
	// forwards branch, possibly across multiple block levels, to
	// the statement that comes right after the execution of "block".
	void BranchBeyond(const Stmt* end_s, const Stmt* block);

	// Start tracking block that begins with the body of s (not s itself).
	void StartConfluenceBlock(const Stmt* s);

	// Finish tracking confluence; s is the last point of execution
	// prior to leaving a block.  If no_orig_flow is true, then
	// the region for 's' itself does not continue to the end of
	// the block.
	void ConfluenceBlockEndsAt(const Stmt* s, bool no_orig_flow);

	// All of these regarding the identifer's state just prior to
	// executing the given statement.
	bool IsPossiblyDefinedAt(const Stmt* s);
	bool IsDefinedAt(const Stmt* s);
	int DefinitionAt(const Stmt* s);

	bool IsPossiblyDefinedAt(int stmt_num);
	bool IsDefinedAt(int stmt_num);
	int DefinitionAt(int stmt_num);

	bool DidUndefinedWarning() const
		{ return did_undefined_warning; }
	bool DidPossiblyUndefinedWarning() const
		{ return did_possibly_undefined_warning; }

	void SetDidUndefinedWarning()
		{ did_undefined_warning = true; }
	void SetDidPossiblyUndefinedWarning()
		{ did_possibly_undefined_warning = true; }

private:
	// End the active region after execution of the given statement.
	void EndRegionAt(const Stmt* s);
	void EndRegionAt(int stmt_num, int level);

	// Find the region that applies *prior* to executing the
	// given statement.  There should always be such a region.
	IDDefRegion& FindRegion(int stmt_num)
		{ return usage_regions[FindRegionIndex(stmt_num)]; }
	int FindRegionIndex(int stmt_num);

	IDDefRegion* ActiveRegion()
		{
		auto ind = ActiveRegionIndex();
		return ind >= 0 ? &usage_regions[ind] : nullptr;
		}
	int ActiveRegionIndex();

	void DumpBlocks() const;

	// Expressions used to initialize the identifier, for use by
	// the scripts-to-C++ compiler.  We need to track all of them
	// because it's possible that a global value gets created using
	// one of the earlier instances rather than the last one.
	std::vector<ExprPtr> init_exprs;

	std::vector<IDDefRegion> usage_regions;

	// A type for collecting the indices of usage_regions that will
	// all have confluence together at one point.
	using ConfluenceSet = std::set<int>;

	// Maps loops/switches/catch-returns to their associated
	// confluence sets.
	std::map<const Stmt*, ConfluenceSet> pending_confluences;

	// A stack of confluence statements, so we can always find
	// the innermost when ending a confluence block.
	std::vector<const Stmt*> confluence_stmts;

	// Parallel vector that tracks whether, upon creating the
	// confluence block, there had already been observed internal
	// flow going beyond it.  If so, then we can ignore no_orig_flow
	// when ending the block, because in fact there *was* original
	// flow.
	std::vector<bool> block_has_orig_flow;

	// Whether the identifier is a temporary variable.
	bool is_temp = false;

	// Only needed for debugging purposes.
	const ID* my_id;

	bool did_undefined_warning = false;
	bool did_possibly_undefined_warning = false;
};

extern const char* trace_ID;

} // namespace zeek::detail