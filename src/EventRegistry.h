// Each event raised/handled by Zeek is registered in the EventRegistry.

#pragma once

#include "zeek/zeek-config.h"

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "zeek/IntrusivePtr.h"

namespace zeek
	{

class EventGroup;
class EventHandler;
class EventHandlerPtr;
class RE_Matcher;

namespace detail
	{
class Stmt;
using StmtPtr = zeek::IntrusivePtr<Stmt>;
using BodyPtr = StmtPtr;
	}

// The registry keeps track of all events that we provide or handle.
class EventRegistry
	{
public:
	EventRegistry();
	~EventRegistry() noexcept;

	/**
	 * Performs a lookup for an existing event handler and returns it
	 * if one exists, or else creates one, registers it, and returns it.
	 * @param name  The name of the event handler to lookup/register.
	 * @param name  Whether the registration is coming from a script element.
	 * @return  The event handler.
	 */
	EventHandlerPtr Register(std::string_view name, bool is_from_script = false);

	void Register(EventHandlerPtr handler, bool is_from_script = false);

	// Return nil if unknown.
	EventHandler* Lookup(std::string_view name);

	// True if the given event handler (1) exists, and (2) was registered
	// in a non-script context (even if perhaps also registered in a script
	// context).
	bool NotOnlyRegisteredFromScript(std::string_view name);

	// Returns a list of all local handlers that match the given pattern.
	// Passes ownership of list.
	using string_list = std::vector<std::string>;
	string_list Match(RE_Matcher* pattern);

	// Marks a handler as handling errors. Error handler will not be called
	// recursively to avoid infinite loops in case they trigger an error
	// themselves.
	void SetErrorHandler(std::string_view name);

	string_list UnusedHandlers();
	string_list UsedHandlers();
	string_list AllHandlers();

	void PrintDebug();

	/**
	 * Marks all event handlers as active.
	 *
	 * By default, zeek does not generate (raise) events that have not handled by
	 * any scripts. This means that these events will be invisible to a lot of other
	 * event handlers - and will not raise :zeek:id:`new_event`. Calling this
	 * function will cause all event handlers to be raised. This is likely only
	 * useful for debugging and fuzzing, and likely causes reduced performance.
	 */
	void ActivateAllHandlers();

	/**
	 * Lookup or register a new event group and return a reference to it.
	 *
	 * @return The event group.
	 */
	EventGroup& RegisterGroup(std::string_view name);

	/**
	 * Lookup an event group.
	 *
	 * @return Pointer to the group or nullptr if the group does not exist.
	 */
	EventGroup* LookupGroup(std::string_view name);

private:
	std::map<std::string, std::unique_ptr<EventHandler>, std::less<>> handlers;
	// Tracks whether a given event handler was registered in a
	// non-script context.
	std::unordered_set<std::string> not_only_from_script;

	// Maps event group names to their instances.
	std::map<std::string, EventGroup, std::less<>> event_groups;
	};

class EventGroup
	{
public:
	EventGroup(std::string_view name);
	~EventGroup() noexcept;

	/**
	 * Enable this event group.
	 *
	 * Function bodies are enabled if all the groups they are part of
	 * have been enabled.
	 */
	void Enable();

	/**
	 * Disable this event group.
	 *
	 * Function bodies are enabled if any of the groups they are part of
	 * have been disabled.
	 */
	void Disable();

	/**
	 * Associate a function body with this group.
	 */
	void AddBody(zeek::detail::BodyPtr b);

private:
	std::string name;
	bool enabled = true;

	std::vector<zeek::detail::BodyPtr> bodies;
	};

extern EventRegistry* event_registry;

	} // namespace zeek
