// Registry to track event groups.
//
// Implementation sketch:
//
// One or more groups can be attached to Func::Body instances.
//
// XXX/TODO: We use detail::Stmt currently, but maybe should lift to Func::Body,
// it's just that it's hard to get a handle of to them without changing
// things around much.
//
// Zeek starts with all groups enabled. When any of the groups is disabled,
// it propagates a "disable_count" to the involved bodies. Function bodies
// with a disabled_count > 0 are skipped.
//
// Summary:
// * StmtPtr becomes a disabled_count flag
// * Enabling/Disabling mutates the disabled_count
// * Disabling overrides enabling: If any group a body is part of is disabled,
//   the body is disabled. This may be okay.
//
#pragma once

#include "zeek/zeek-config.h"

#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"

namespace zeek::detail
	{

class Stmt;
using StmtPtr = zeek::IntrusivePtr<Stmt>;
using BodyPtr = StmtPtr;

class EventGroup
	{
public:
	EventGroup(std::string_view name);
	~EventGroup() noexcept;
	// Enable this event group.
	//
	// If disabled, go through all function bodies and decrement their
	// disabled_count.
	void Enable();

	// Disable this event group
	void Disable();

	void AddBody(zeek::detail::BodyPtr b);

private:
	std::string name;
	bool enabled = true;

	std::vector<zeek::detail::BodyPtr> bodies;
	};

class EventGroupRegistry
	{
public:
	EventGroupRegistry();
	~EventGroupRegistry() noexcept;

	/**
	 * Performs a lookup for an existing group or registers a new one
	 * and returns a reference to it.
	 *
	 * @param name  The name of the group.
	 *
	 * @returns A reference to the new group (XXX: Should this also return a pointer?)
	 */
	EventGroup& Register(std::string_view name);
	/**
	 * Lookup an event group.
	 *
	 * @param name  The name of the group.
	 *
	 * @returns A pointer to the group or a nullptr if the group does not exist.
	 */
	EventGroup* Lookup(std::string_view name);

private:
	std::map<std::string, EventGroup, std::less<>> event_groups;
	};

extern EventGroupRegistry* event_group_registry;
	}
