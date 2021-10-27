// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZeekString.h"
#include "zeek/Desc.h"
#include "zeek/File.h"
#include "zeek/RE.h"
#include "zeek/script_opt/CPP/RunTimeGlobals.h"
#include "zeek/script_opt/CPP/RunTimeInit.h"

using namespace std;

namespace zeek::detail
	{


template <class T>
CPP_IndexedGlobals<T>::CPP_IndexedGlobals(std::vector<T>& _global_vec, int _offsets_set, std::vector<std::vector<ValElemVec>> _inits)
	: global_vec(_global_vec), offsets_set(_offsets_set), inits(std::move(_inits))
	{
	int num_globals = 0;

	for ( const auto& cohort : inits )
		num_globals += cohort.size();

	global_vec.resize(num_globals);
	}

template <class T>
void CPP_IndexedGlobals<T>::InitializeCohort(InitsManager* im, int cohort)
	{
	if ( cohort == 0 )
		PreInit(im);

	auto& offsets_vec = im->Indices(offsets_set);
	auto& co = inits[cohort];
	auto& cohort_offsets = im->Indices(offsets_vec[cohort]);
	for ( auto i = 0U; i < co.size(); ++i )
		Generate(im, global_vec, cohort_offsets[i], co[i]);
	}

template <class T>
void CPP_IndexedGlobals<T>::Generate(InitsManager* im, std::vector<EnumValPtr>& gvec, int offset, ValElemVec& init_vals)
	{
	auto& e_type = im->Types(init_vals[0]);
	int val = init_vals[1];
	gvec[offset] = make_enum__CPP(e_type, val);
	}

template <class T>
void CPP_IndexedGlobals<T>::Generate(InitsManager* im, std::vector<StringValPtr>& gvec, int offset, ValElemVec& init_vals)
	{
	auto chars = im->Strings(init_vals[0]);
	int len = init_vals[1];
	gvec[offset] = make_intrusive<StringVal>(len, chars);
	}

template <class T>
void CPP_IndexedGlobals<T>::Generate(InitsManager* im, std::vector<PatternValPtr>& gvec, int offset, ValElemVec& init_vals)
	{
	auto re = new RE_Matcher(im->Strings(init_vals[0]));
	if ( init_vals[1] )
		re->MakeCaseInsensitive();

	re->Compile();

	gvec[offset] = make_intrusive<PatternVal>(re);
	}

template <class T>
void CPP_IndexedGlobals<T>::Generate(InitsManager* im, std::vector<ListValPtr>& gvec, int offset, ValElemVec& init_vals) const
	{
	auto n = init_vals.size();
	auto i = 0U;

	auto l = make_intrusive<ListVal>(TYPE_ANY);

	while ( i < n )
		l->Append(im->ConstVals(init_vals[i++]));

	gvec[offset] = l;
	}

template <class T>
void CPP_IndexedGlobals<T>::Generate(InitsManager* im, std::vector<VectorValPtr>& gvec, int offset, ValElemVec& init_vals) const
	{
	auto n = init_vals.size();
	auto i = 0U;
	auto t = init_vals[i++];

	auto vt = cast_intrusive<VectorType>(im->Types(t));
	auto vv = make_intrusive<VectorVal>(vt);

	while ( i < n )
		vv->Append(im->ConstVals(init_vals[i++]));

	gvec[offset] = vv;
	}

template <class T>
void CPP_IndexedGlobals<T>::Generate(InitsManager* im, std::vector<RecordValPtr>& gvec, int offset, ValElemVec& init_vals) const
	{
	auto n = init_vals.size();
	auto i = 0U;
	auto t = init_vals[i++];

	auto rt = cast_intrusive<RecordType>(im->Types(t));
	auto rv = make_intrusive<RecordVal>(rt);

	while ( i < n )
		{
		auto v = init_vals[i];
		if ( v >= 0 )
			rv->Assign(i - 1, im->ConstVals(v));
		++i;
		}

	gvec[offset] = rv;
	}

template <class T>
void CPP_IndexedGlobals<T>::Generate(InitsManager* im, std::vector<TableValPtr>& gvec, int offset, ValElemVec& init_vals) const
	{
	auto n = init_vals.size();
	auto i = 0U;
	auto t = init_vals[i++];

	auto tt = cast_intrusive<TableType>(im->Types(t));
	auto tv = make_intrusive<TableVal>(tt);

	while ( i < n )
		{
		auto index = im->ConstVals(init_vals[i++]);
		auto v = init_vals[i++];
		auto value = v >= 0 ? im->ConstVals(v) : nullptr;
		tv->Assign(index, value);
		}

	gvec[offset] = tv;
	}

template <class T>
void CPP_IndexedGlobals<T>::Generate(InitsManager* im, std::vector<FileValPtr>& gvec, int offset, ValElemVec& init_vals) const
	{
	auto n = init_vals.size();
	auto i = 0U;
	auto t = init_vals[i++];	// not used

	auto fn = im->Strings(init_vals[i++]);
	auto fv = make_intrusive<FileVal>(make_intrusive<File>(fn, "w"));

	gvec[offset] = fv;
	}

template <class T>
void CPP_IndexedGlobals<T>::Generate(InitsManager* im, std::vector<FuncValPtr>& gvec, int offset, ValElemVec& init_vals) const
	{
	auto n = init_vals.size();
	auto i = 0U;
	auto t = init_vals[i++];

	auto fn = im->Strings(init_vals[i++]);

	std::vector<p_hash_type> hashes;

	while ( i < n )
		hashes.push_back(im->Hashes(init_vals[i++]));

	gvec[offset] = lookup_func__CPP(fn, hashes, im->Types(t));
	}

template <class T>
void CPP_IndexedGlobals<T>::Generate(InitsManager* im, std::vector<AttrPtr>& gvec, int offset, ValElemVec& init_vals) const
	{
	auto tag = static_cast<AttrTag>(init_vals[0]);
	auto ae_tag = static_cast<AttrExprType>(init_vals[1]);

	ExprPtr e;
	auto e_arg = init_vals[2];

	switch ( ae_tag )
		{
		case AE_NONE:
			break;

		case AE_CONST:
			e = make_intrusive<ConstExpr>(im->ConstVals(e_arg));
			break;

		case AE_NAME:
			{
			auto name = im->Strings(e_arg);
			auto gl = lookup_ID(name, GLOBAL_MODULE_NAME, false, false, false);
			ASSERT(gl);
			e = make_intrusive<NameExpr>(gl);
			break;
			}

		case AE_RECORD:
			{
			auto t = im->Types(e_arg);
			auto rt = cast_intrusive<RecordType>(t);
			auto empty_vals = make_intrusive<ListExpr>();
			auto construct = make_intrusive<RecordConstructorExpr>(empty_vals);
			e = make_intrusive<RecordCoerceExpr>(construct, rt);
			break;
			}

		case AE_CALL:
			e = im->CallExprs(e_arg);
			break;
		}

	gvec[offset] = make_intrusive<Attr>(tag, e);
	}

template <class T>
void CPP_IndexedGlobals<T>::Generate(InitsManager* im, std::vector<AttributesPtr>& gvec, int offset, ValElemVec& init_vals) const
	{
	auto n = init_vals.size();
	auto i = 0U;

	std::vector<AttrPtr> a_list;
	while ( i < n )
		a_list.emplace_back(im->Attrs(init_vals[i++]));

	gvec[offset] = make_intrusive<Attributes>(a_list, nullptr, false, false);
	}


void CPP_TypeGlobals::PreInit(InitsManager* im)
	{
	auto& offsets_vec = im->Indices(offsets_set);
	for ( auto cohort = 0U; cohort < offsets_vec.size(); ++cohort )
		{
		auto& co = inits[cohort];
		auto& cohort_offsets = im->Indices(offsets_vec[cohort]);
		for ( auto i = 0U; i < co.size(); ++i )
			PreInit(im, cohort_offsets[i], co[i]);
		}
	}

void CPP_TypeGlobals::PreInit(InitsManager* im, int offset, ValElemVec& init_vals)
	{
	auto tag = static_cast<TypeTag>(init_vals[0]);

	if ( tag == TYPE_LIST )
		global_vec[offset] = make_intrusive<TypeList>();

	else if ( tag == TYPE_RECORD )
		{
		auto name = im->Strings(init_vals[1]);
		if ( name[0] )
			global_vec[offset] = get_record_type__CPP(name);
		else
			global_vec[offset] = get_record_type__CPP(nullptr);
		}
	}

void CPP_TypeGlobals::Generate(InitsManager* im, vector<TypePtr>& gvec, int offset, ValElemVec& init_vals) const
	{
	auto tag = static_cast<TypeTag>(init_vals[0]);
	TypePtr t;
	switch ( tag )
		{
		case TYPE_ADDR:
		case TYPE_ANY:
		case TYPE_BOOL:
		case TYPE_COUNT:
		case TYPE_DOUBLE:
		case TYPE_ERROR:
		case TYPE_INT:
		case TYPE_INTERVAL:
		case TYPE_PATTERN:
		case TYPE_PORT:
		case TYPE_STRING:
		case TYPE_TIME:
		case TYPE_TIMER:
		case TYPE_VOID:
		case TYPE_SUBNET:
		case TYPE_FILE:
			t = base_type(tag);
			break;

		case TYPE_ENUM:
			t = BuildEnumType(im, init_vals);
			break;

		case TYPE_OPAQUE:
			t = BuildOpaqueType(im, init_vals);
			break;

		case TYPE_TYPE:
			t = BuildTypeType(im, init_vals);
			break;

		case TYPE_VECTOR:
			t = BuildVectorType(im, init_vals);
			break;

		case TYPE_LIST:
			t = BuildTypeList(im, init_vals, offset);
			break;

		case TYPE_TABLE:
			t = BuildTableType(im, init_vals);
			break;

		case TYPE_FUNC:
			t = BuildFuncType(im, init_vals);
			break;

		case TYPE_RECORD:
			t = BuildRecordType(im, init_vals, offset);
			break;

		default:
			ASSERT(0);
		}

	gvec[offset] = t;
	}

TypePtr CPP_TypeGlobals::BuildEnumType(InitsManager* im, ValElemVec& init_vals) const
	{
	auto name = im->Strings(init_vals[1]);
	auto et = get_enum_type__CPP(name);

	if ( et->Names().empty() )
		{
		auto n = init_vals.size();
		auto i = 2U;

		while ( i < n )
			{
			auto e_name = im->Strings(init_vals[i++]);
			auto e_val = init_vals[i++];
			et->AddNameInternal(e_name, e_val);
			}
		}

	return et;
	}

TypePtr CPP_TypeGlobals::BuildOpaqueType(InitsManager* im, ValElemVec& init_vals) const
	{
	auto name = im->Strings(init_vals[1]);
	return make_intrusive<OpaqueType>(name);
	}

TypePtr CPP_TypeGlobals::BuildTypeType(InitsManager* im, ValElemVec& init_vals) const
	{
	auto& t = im->Types(init_vals[1]);
	return make_intrusive<TypeType>(t);
	}

TypePtr CPP_TypeGlobals::BuildVectorType(InitsManager* im, ValElemVec& init_vals) const
	{
	auto& t = im->Types(init_vals[1]);
	return make_intrusive<VectorType>(t);
	}

TypePtr CPP_TypeGlobals::BuildTypeList(InitsManager* im, ValElemVec& init_vals, int offset) const
	{
	const auto& tl = cast_intrusive<TypeList>(global_vec[offset]);

	auto n = init_vals.size();
	auto i = 1U;

	while ( i < n )
		tl->Append(im->Types(init_vals[i++]));

	return tl;
	}

TypePtr CPP_TypeGlobals::BuildTableType(InitsManager* im, ValElemVec& init_vals) const
	{
	auto index = cast_intrusive<TypeList>(im->Types(init_vals[1]));
	auto yield_i = init_vals[2];
	auto yield = yield_i >= 0 ? im->Types(yield_i) : nullptr;

	return make_intrusive<TableType>(index, yield);
	}

TypePtr CPP_TypeGlobals::BuildFuncType(InitsManager* im, ValElemVec& init_vals) const
	{
	auto p = cast_intrusive<RecordType>(im->Types(init_vals[1]));
	auto yield_i = init_vals[2];
	auto flavor = static_cast<FunctionFlavor>(init_vals[3]);

	TypePtr y;

	if ( yield_i >= 0 )
		y = im->Types(yield_i);

	else if ( flavor == FUNC_FLAVOR_FUNCTION || flavor == FUNC_FLAVOR_HOOK )
		y = base_type(TYPE_VOID);

	return make_intrusive<FuncType>(p, y, flavor);
	}

TypePtr CPP_TypeGlobals::BuildRecordType(InitsManager* im, ValElemVec& init_vals, int offset) const
	{
	auto r = cast_intrusive<RecordType>(global_vec[offset]);
	ASSERT(r);

	if ( r->NumFields() == 0 )
		{
		type_decl_list tl;

		auto n = init_vals.size();
		auto i = 2U;

		while ( i < n )
			{
			auto s = im->Strings(init_vals[i++]);
			auto id = util::copy_string(s);
			auto type = im->Types(init_vals[i++]);
			auto attrs_i = init_vals[i++];

			AttributesPtr attrs;
			if ( attrs_i >= 0 )
				attrs = im->Attributes(attrs_i);

			tl.append(new TypeDecl(id, type, attrs));
			}

		r->AddFieldsDirectly(tl);
		}

	return r;
	}


int CPP_FieldMapping::ComputeOffset(InitsManager* im) const
	{
	auto r = im->Types(rec)->AsRecordType();
	auto fm_offset = r->FieldOffset(field_name.c_str());

	if ( fm_offset < 0 )
		{
                // field does not exist, create it
                fm_offset = r->NumFields();

		auto id = util::copy_string(field_name.c_str());
		auto type = im->Types(field_type);

		AttributesPtr attrs;
		if ( field_attrs >= 0 )
			attrs = im->Attributes(field_attrs);

		type_decl_list tl;
		tl.append(new TypeDecl(id, type, attrs));

		r->AddFieldsDirectly(tl);
		}

	return fm_offset;
	}


int CPP_EnumMapping::ComputeOffset(InitsManager* im) const
	{
	auto e = im->Types(e_type)->AsEnumType();

	auto em_offset = e->Lookup(e_name);
	if ( em_offset < 0 )
		{
		em_offset = e->Names().size();
		if ( e->Lookup(em_offset) )
			reporter->InternalError("enum inconsistency while initializing compiled scripts");
		e->AddNameInternal(e_name, em_offset);
		}

	return em_offset;
	}


void CPP_GlobalInit::Generate(InitsManager* im, std::vector<void*>& /* global_vec */, int /* offset */) const
	{
	global = lookup_global__CPP(name, im->Types(type), exported);

	if ( ! global->HasVal() && val >= 0 )
		{
		global->SetVal(im->ConstVals(val));
		if ( attrs >= 0 )
			global->SetAttrs(im->Attributes(attrs));
		}
	}


void generate_indices_set(int* inits, std::vector<std::vector<int>>& indices_set)
	{
	// First figure out how many groups of indices there are, so we
	// can pre-allocate the outer vector.
	auto i_ptr = inits;
	int num_inits = 0;
	while ( *i_ptr >= 0 )
		{
		++num_inits;
		int n = *i_ptr;
		i_ptr += n + 1;
		}

	indices_set.reserve(num_inits);

	i_ptr = inits;
	while ( *i_ptr >= 0 )
		{
		int n = *i_ptr;
		++i_ptr;
		std::vector<int> indices;
		indices.reserve(n);
		for ( int i = 0; i < n; ++i )
			indices.push_back(i_ptr[i]);
		i_ptr += n;

		indices_set.emplace_back(move(indices));
		}
	}


// Instantiate the templates we'll need.

template class CPP_IndexedGlobals<EnumValPtr>;
template class CPP_IndexedGlobals<StringValPtr>;
template class CPP_IndexedGlobals<PatternValPtr>;
template class CPP_IndexedGlobals<ListValPtr>;
template class CPP_IndexedGlobals<VectorValPtr>;
template class CPP_IndexedGlobals<RecordValPtr>;
template class CPP_IndexedGlobals<TableValPtr>;
template class CPP_IndexedGlobals<FileValPtr>;
template class CPP_IndexedGlobals<FuncValPtr>;
template class CPP_IndexedGlobals<AttrPtr>;
template class CPP_IndexedGlobals<AttributesPtr>;
template class CPP_IndexedGlobals<TypePtr>;


	} // zeek::detail
