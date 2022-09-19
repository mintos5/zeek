#include "zeek/EventGroupRegistry.h"

#include "zeek/Stmt.h"

namespace zeek::detail
	{

EventGroup::EventGroup(std::string_view name) : name(name) { }
EventGroup::~EventGroup() noexcept { }
void EventGroup::Enable()
	{
	if ( enabled )
		return;

	// Go through all bodies Decrement their disabled count
	for ( const auto& b : bodies )
		b->DecrementDisabled();

	enabled = true;
	}
void EventGroup::Disable()
	{

	if ( ! enabled )
		return;

	// Go through all bodies Increment their disabled count
	for ( const auto& b : bodies )
		b->IncrementDisabled();

	enabled = false;
	}
void EventGroup::AddBody(zeek::detail::BodyPtr b)
	{
	bodies.push_back(b);
	}

EventGroupRegistry::EventGroupRegistry() { }
EventGroupRegistry::~EventGroupRegistry() noexcept { }
EventGroup& EventGroupRegistry::Register(const std::string_view name)
	{

	if ( const auto& it = event_groups.find(name); it != event_groups.end() )
		return it->second;

	return event_groups.emplace(name, name).first->second;
	}
EventGroup* EventGroupRegistry::Lookup(const std::string_view name)
	{
	if ( const auto& it = event_groups.find(name); it != event_groups.end() )
		return &(it->second);

	return nullptr;
	}
	}
