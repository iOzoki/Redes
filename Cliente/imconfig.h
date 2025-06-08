//-----------------------------------------------------------------------------
// Dear ImGui 1.88
// (config file)
//-----------------------------------------------------------------------------
#pragma once

//---- Define assertion handler. Defaults to calling assert().
//#define IM_ASSERT(_EXPR)  assert(_EXPR)

//---- Define attributes of all API symbols declarations, e.g. for DLL under Windows
//#define IMGUI_API __declspec( dllexport )
//#define IMGUI_API __declspec( dllimport )

//---- Don't define obsolete functions/enums names. Consider enabling from time to time after updating to avoid using soon-to-be obsolete function/names.
#define IMGUI_DISABLE_OBSOLETE_FUNCTIONS

//---- Don't include TCHAR regularly in imgui_impl_win32.h to avoid dragging dependencies on <tchar.h> throughout every file.
#define IMGUI_IMPL_WIN32_DISABLE_TCHAR_METHODS

//---- We need this defined for the backends to be able to use GetStyle()
#define IMGUI_DEFINE_MATH_OPERATORS

