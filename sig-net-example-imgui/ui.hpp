//==============================================================================
// sig-net-example-imgui - UI Layer
//==============================================================================
//
// All ImGui rendering: styling, status colors/labels, and the transmit/receive
// dashboard panels. Depends on the App layer (sig-net.hpp) and ImGui.
//
//==============================================================================

#ifndef SIG_NET_EXAMPLE_UI_HPP
#define SIG_NET_EXAMPLE_UI_HPP

#include "app.hpp"

#include "imgui.h"

#include <SDL.h>

#include <cstdint>
#include <string>

namespace UI
{

//------------------------------------------------------------------------------

// ImGui colour helper.
ImVec4 ColorFromBytes(int r, int g, int b, int a = 255);

// Apply the dark dashboard theme to the current ImGui context.
void ApplyCustomStyle();

//------------------------------------------------------------------------------

// Status colour/label helpers used across panels.
ImVec4 PassphraseStatusColor(int status);
const char *PassphraseStatusLabel(int status);
ImVec4 VerificationColor(bool attempted, bool verified);
const char *VerificationLabel(bool attempted, bool verified);
ImVec4 ReceiverStatusColor(const App::AppState &state);
const char *ReceiverStatusLabel(const App::AppState &state);

//------------------------------------------------------------------------------

// Full-frame backdrop drawn behind the dockspace.
void DrawAppBackdrop();

// Card / metric-tile primitives.
bool BeginCard(const char *id, const char *title, const char *subtitle, float height = 0.0f, bool show_header = true);
void EndCard();
void InputLabel(const char *label);
void DrawMetricTile(const char *id, const char *label, const std::string &value, const ImVec4 &accent);

// Layout helpers for polish.
void DrawSectionDivider();
void DrawStatusPill(const char *label, const ImVec4 &color);
void BeginMonospace();
void EndMonospace();

// Push a coloured tint for a DMX channel based on its slot index (0=R, 1=G, 2=B).
ImVec4 DmxChannelTint(int channel);

//------------------------------------------------------------------------------

// Top-level panel renderers. now_ticks comes from SDL_GetTicks() in main.
void RenderHeaderBand(App::AppState &state);
void RenderTransmitTopRegion(App::AppState &state, float top_height, Uint32 now_ticks);
void RenderTransmitBottomRegion(App::AppState &state, float bottom_height);
void RenderReceiveTopRegion(App::AppState &state, float top_height);
void RenderReceiveBottomRegion(App::AppState &state, float bottom_height);

} // namespace UI

#endif // SIG_NET_EXAMPLE_UI_HPP