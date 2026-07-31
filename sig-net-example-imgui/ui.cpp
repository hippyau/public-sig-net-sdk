//==============================================================================
// sig-net-example-imgui - UI Layer
//==============================================================================
//
// All ImGui rendering: styling, status colours/labels, and the transmit/receive
// dashboard panels.
//
//==============================================================================

#include "ui.hpp"
#include "app.hpp"
#include "backends/imgui_impl_opengl3.h"
#include "backends/imgui_impl_sdl2.h"

#include <SDL.h>

#include <algorithm>
#include <string>

namespace UI
{

// Defined early so anonymous-namespace helpers can call it.
ImVec4 ColorFromBytes(int r, int g, int b, int a) { return ImVec4(r / 255.0f, g / 255.0f, b / 255.0f, a / 255.0f); }

namespace
{

constexpr int kVisibleDmxChannels = 24;

// Push tighter item spacing for monospace-aligned content (hex dumps).
void PushMonospace() { ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4.0f, 2.0f)); }
void PopMonospace() { ImGui::PopStyleVar(); }

// Thin horizontal separator with subtle colour.
void SectionDivider()
{
	ImGui::Dummy(ImVec2(0.0f, 3.0f));
	ImGui::PushStyleColor(ImGuiCol_Separator, ColorFromBytes(42, 53, 72, 120));
	ImGui::Separator();
	ImGui::PopStyleColor();
	ImGui::Dummy(ImVec2(0.0f, 3.0f));
}

// Small coloured pill (rounded badge) with a label.
void StatusPill(const char *label, const ImVec4 &color)
{
	ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(color.x, color.y, color.z, 0.22f));
	ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(color.x, color.y, color.z, 0.32f));
	ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(color.x, color.y, color.z, 0.42f));
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.0f, 2.0f));
	ImGui::SmallButton(label);
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor(3);
}

// Colour-tint a DMX channel slider based on its RGB slot position.
ImVec4 ChannelTint(int channel)
{
	const int slot = channel % 3;
	if (slot == 0) return ColorFromBytes(220, 90, 90, 180);
	if (slot == 1) return ColorFromBytes(90, 200, 120, 180);
	return ColorFromBytes(90, 140, 230, 180);
}

void RenderDmxSliders(App::AppState &state, float slider_region_height)
{
	ImGui::TextColored(ColorFromBytes(130, 146, 168), "Direct per-channel transmission in manual mode.");
	ImGui::SliderInt("Offset", &state.dmx_scroll_position, 0, 512 - kVisibleDmxChannels);
	ImGui::SameLine();
	if (ImGui::Button("Zero All"))
		{
			std::fill(state.dmx_buffer.begin(), state.dmx_buffer.end(), 0);
			if (state.dmx_mode == App::AppState::Manual) App::SendLevelPacket(state, "zero all");
		}
	ImGui::SameLine();
	if (ImGui::Button("Full All"))
		{
			std::fill(state.dmx_buffer.begin(), state.dmx_buffer.end(), 255);
			if (state.dmx_mode == App::AppState::Manual) App::SendLevelPacket(state, "full all");
		}

	if (ImGui::BeginChild("dmx-sliders", ImVec2(0.0f, slider_region_height - 64.0f), true))
		{
			bool changed = false;
			const float start_x = ImGui::GetCursorPosX();
			const float available_width = ImGui::GetContentRegionAvail().x;
			const float slider_width = 24.0f;
			const float slot_spacing = ImGui::GetStyle().ItemSpacing.x;
			const float total_width = (kVisibleDmxChannels * slider_width) + ((kVisibleDmxChannels - 1) * slot_spacing);
			if (available_width > total_width) ImGui::SetCursorPosX(start_x + (available_width - total_width) * 0.42f);
			for (int i = 0; i < kVisibleDmxChannels; ++i)
				{
					const int channel = state.dmx_scroll_position + i;
					int value = state.dmx_buffer[channel];
					ImGui::PushID(channel);
					if (i > 0) ImGui::SameLine();
					ImGui::BeginGroup();
					const ImVec4 tint = ChannelTint(channel);
					ImGui::TextColored(tint, "%d", channel + 1);
					ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(tint.x * 0.25f, tint.y * 0.25f, tint.z * 0.25f, 1.0f));
					ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(tint.x * 0.35f, tint.y * 0.35f, tint.z * 0.35f, 1.0f));
					ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(tint.x * 0.45f, tint.y * 0.45f, tint.z * 0.45f, 1.0f));
					ImGui::PushStyleColor(ImGuiCol_SliderGrab, tint);
					ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, ImVec4(tint.x * 1.2f, tint.y * 1.2f, tint.z * 1.2f, 1.0f));
					if (ImGui::VSliderInt("##value", ImVec2(slider_width, 240.0f), &value, 255, 0, ""))
						{
							state.dmx_buffer[channel] = static_cast<uint8_t>(value);
							changed = true;
						}
					ImGui::PopStyleColor(5);
					ImGui::TextColored(tint, "%03d", state.dmx_buffer[channel]);
					ImGui::EndGroup();
					ImGui::PopID();
				}
			if (changed && state.dmx_mode == App::AppState::Manual) App::SendLevelPacket(state, "manual slider");
		}
	ImGui::EndChild();
}

void RenderSelectedNodeDetails(App::AppState &state, Uint32 now_ticks)
{
	if (state.selected_discovered_node < 0 || state.selected_discovered_node >= static_cast<int>(state.discovered_nodes.size()))
		{
			ImGui::TextColored(ColorFromBytes(145, 161, 182), "No discovered node selected yet.");
			ImGui::TextWrapped("Join the node announce multicast group and wait for traffic or send an announce from this app.");
			return;
		}

	const App::DiscoveredNode &node = state.discovered_nodes[state.selected_discovered_node];
	if (ImGui::BeginTable("selected-node-grid", 2, ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthFixed, 124.0f);
			ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);

			const auto draw_row = [&](const char *label, const std::string &value)
				{
					ImGui::TableNextRow();
					ImGui::TableNextColumn();
					ImGui::TextColored(ColorFromBytes(145, 161, 182), "%s", label);
					ImGui::TableNextColumn();
					ImGui::TextWrapped("%s", value.c_str());
				};

			const auto draw_pill_row = [&](const char *label, const char *pill_label, const ImVec4 &color)
				{
					ImGui::TableNextRow();
					ImGui::TableNextColumn();
					ImGui::TextColored(ColorFromBytes(145, 161, 182), "%s", label);
					ImGui::TableNextColumn();
					StatusPill(pill_label, color);
				};

			draw_row("TUID", node.tuid_hex);
			draw_row("Source", App::FormatString("%s:%u", node.source_ip.c_str(), SigNet::SIGNET_UDP_PORT));
			draw_row("Roles", App::RoleCapabilityLabel(node.role_capability_bits));
			draw_row("Firmware", node.firmware_version_string.empty() ? App::FormatString("%u", node.firmware_version_id) : App::FormatString("%u  %s", node.firmware_version_id, node.firmware_version_string.c_str()));
			draw_row("Protocol", App::FormatString("v%u", node.protocol_version));
			draw_row("Mfg / Variant", App::FormatString("0x%04X / %04X", node.manufacturer_code, node.product_variant_id));
			draw_row("Change Count", std::to_string(node.change_count));
			draw_row("Announces", std::to_string(node.announce_count));
			draw_row("Last Seen", App::FormatAgeLabel(node.last_seen_tick, now_ticks));
			draw_pill_row("HMAC", VerificationLabel(node.verify_attempted, node.hmac_verified), VerificationColor(node.verify_attempted, node.hmac_verified));
			draw_row("URI", node.uri);

			ImGui::EndTable();
		}
}

void RenderDiscoveredNodesTable(App::AppState &state, float height, Uint32 now_ticks)
{
	if (state.discovered_nodes.empty())
		{
			ImGui::TextColored(ColorFromBytes(145, 161, 182), "No announce traffic captured yet.");
			ImGui::TextWrapped("Enable the receiver, stay on the node multicast group, or send an announce from this app to populate the list.");
			return;
		}

	const ImGuiTableFlags table_flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp;

	if (ImGui::BeginTable("discovered-nodes", 7, table_flags, ImVec2(0.0f, height)))
		{
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableSetupColumn("TUID", ImGuiTableColumnFlags_WidthFixed, 126.0f);
			ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 120.0f);
			ImGui::TableSetupColumn("Roles", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("Firmware", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 74.0f);
			ImGui::TableSetupColumn("HMAC", ImGuiTableColumnFlags_WidthFixed, 86.0f);
			ImGui::TableSetupColumn("Age", ImGuiTableColumnFlags_WidthFixed, 72.0f);
			ImGui::TableHeadersRow();

			for (size_t i = 0; i < state.discovered_nodes.size(); ++i)
				{
					const App::DiscoveredNode &node = state.discovered_nodes[i];
					const bool selected = static_cast<int>(i) == state.selected_discovered_node;
					ImGui::TableNextRow();

					ImGui::TableNextColumn();
					if (ImGui::Selectable(node.tuid_hex.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns)) state.selected_discovered_node = static_cast<int>(i);

					ImGui::TableNextColumn();
					ImGui::TextUnformatted(node.source_ip.c_str());

					ImGui::TableNextColumn();
					ImGui::TextWrapped("%s", App::RoleCapabilityLabel(node.role_capability_bits).c_str());

					ImGui::TableNextColumn();
					if (node.firmware_version_string.empty())
						ImGui::Text("%u", node.firmware_version_id);
					else
						ImGui::TextWrapped("%s", node.firmware_version_string.c_str());

					ImGui::TableNextColumn();
					ImGui::Text("v%u", node.protocol_version);

					ImGui::TableNextColumn();
					StatusPill(VerificationLabel(node.verify_attempted, node.hmac_verified), VerificationColor(node.verify_attempted, node.hmac_verified));

					ImGui::TableNextColumn();
					ImGui::TextUnformatted(App::FormatAgeLabel(node.last_seen_tick, now_ticks).c_str());
				}

			ImGui::EndTable();
		}
}

} // namespace

//==============================================================================
// Colour + style
//==============================================================================

void ApplyCustomStyle()
{
	ImGuiStyle &style = ImGui::GetStyle();
	style.WindowPadding = ImVec2(12.0f, 12.0f);
	style.FramePadding = ImVec2(9.0f, 7.0f);
	style.CellPadding = ImVec2(8.0f, 8.0f);
	style.ItemSpacing = ImVec2(8.0f, 8.0f);
	style.ItemInnerSpacing = ImVec2(6.0f, 5.0f);
	style.WindowRounding = 18.0f;
	style.ChildRounding = 16.0f;
	style.FrameRounding = 10.0f;
	style.PopupRounding = 12.0f;
	style.ScrollbarRounding = 12.0f;
	style.GrabRounding = 10.0f;
	style.TabRounding = 14.0f;
	style.WindowBorderSize = 0.0f;
	style.PopupBorderSize = 0.0f;
	style.FrameBorderSize = 0.0f;
	style.ChildBorderSize = 1.0f;
	style.IndentSpacing = 16.0f;

	ImVec4 *colors = style.Colors;
	colors[ImGuiCol_Text] = ColorFromBytes(241, 244, 248);
	colors[ImGuiCol_TextDisabled] = ColorFromBytes(134, 149, 168);
	colors[ImGuiCol_WindowBg] = ColorFromBytes(11, 16, 25);
	colors[ImGuiCol_ChildBg] = ColorFromBytes(18, 24, 36, 232);
	colors[ImGuiCol_PopupBg] = ColorFromBytes(18, 24, 36, 245);
	colors[ImGuiCol_Border] = ColorFromBytes(42, 53, 72, 170);
	colors[ImGuiCol_FrameBg] = ColorFromBytes(24, 32, 46);
	colors[ImGuiCol_FrameBgHovered] = ColorFromBytes(33, 45, 66);
	colors[ImGuiCol_FrameBgActive] = ColorFromBytes(43, 58, 82);
	colors[ImGuiCol_TitleBg] = ColorFromBytes(13, 18, 28);
	colors[ImGuiCol_TitleBgActive] = ColorFromBytes(13, 18, 28);
	colors[ImGuiCol_MenuBarBg] = ColorFromBytes(17, 23, 34);
	colors[ImGuiCol_ScrollbarBg] = ColorFromBytes(15, 21, 31);
	colors[ImGuiCol_ScrollbarGrab] = ColorFromBytes(69, 88, 116);
	colors[ImGuiCol_ScrollbarGrabHovered] = ColorFromBytes(90, 112, 144);
	colors[ImGuiCol_ScrollbarGrabActive] = ColorFromBytes(116, 142, 178);
	colors[ImGuiCol_CheckMark] = ColorFromBytes(255, 191, 92);
	colors[ImGuiCol_SliderGrab] = ColorFromBytes(82, 184, 214);
	colors[ImGuiCol_SliderGrabActive] = ColorFromBytes(124, 214, 239);
	colors[ImGuiCol_Button] = ColorFromBytes(35, 50, 71);
	colors[ImGuiCol_ButtonHovered] = ColorFromBytes(50, 70, 98);
	colors[ImGuiCol_ButtonActive] = ColorFromBytes(68, 94, 129);
	colors[ImGuiCol_Header] = ColorFromBytes(34, 49, 70);
	colors[ImGuiCol_HeaderHovered] = ColorFromBytes(48, 68, 96);
	colors[ImGuiCol_HeaderActive] = ColorFromBytes(61, 86, 121);
	colors[ImGuiCol_Separator] = ColorFromBytes(47, 59, 80);
	colors[ImGuiCol_ResizeGrip] = ColorFromBytes(82, 184, 214, 100);
	colors[ImGuiCol_ResizeGripHovered] = ColorFromBytes(82, 184, 214, 180);
	colors[ImGuiCol_ResizeGripActive] = ColorFromBytes(82, 184, 214, 230);
	colors[ImGuiCol_Tab] = ColorFromBytes(24, 33, 48);
	colors[ImGuiCol_TabHovered] = ColorFromBytes(46, 63, 88);
	colors[ImGuiCol_TabActive] = ColorFromBytes(51, 73, 104);
	colors[ImGuiCol_TableHeaderBg] = ColorFromBytes(20, 28, 40);
	colors[ImGuiCol_TableBorderStrong] = ColorFromBytes(44, 56, 77);
	colors[ImGuiCol_TableBorderLight] = ColorFromBytes(31, 40, 56);
}

//==============================================================================
// Status colour/label helpers
//==============================================================================

ImVec4 PassphraseStatusColor(int status)
{
	if (status == SigNet::SIGNET_PASSPHRASE_VALID) return ColorFromBytes(90, 201, 131);
	if (status == SigNet::SIGNET_PASSPHRASE_TOO_SHORT || status == SigNet::SIGNET_PASSPHRASE_TOO_LONG) return ColorFromBytes(255, 191, 92);
	return ColorFromBytes(247, 108, 94);
}

const char *PassphraseStatusLabel(int status)
{
	if (status == SigNet::SIGNET_PASSPHRASE_VALID) return "Ready";
	if (status == SigNet::SIGNET_PASSPHRASE_TOO_SHORT) return "Too Short";
	if (status == SigNet::SIGNET_PASSPHRASE_TOO_LONG) return "Too Long";
	if (status == SigNet::SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES) return "Needs More Classes";
	if (status == SigNet::SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL) return "Repeated Chars";
	if (status == SigNet::SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL) return "Sequential Pattern";
	return "Check Passphrase";
}

ImVec4 VerificationColor(bool attempted, bool verified)
{
	if (!attempted) return ColorFromBytes(255, 191, 92);
	return verified ? ColorFromBytes(90, 201, 131) : ColorFromBytes(247, 108, 94);
}

const char *VerificationLabel(bool attempted, bool verified)
{
	if (!attempted) return "Unavailable";
	return verified ? "Valid" : "Mismatch";
}

ImVec4 ReceiverStatusColor(const App::AppState &state)
{
	if (!state.receiver_enabled) return ColorFromBytes(145, 161, 182);
	if (state.receiver_active) return ColorFromBytes(90, 201, 131);
	if (!state.receiver_last_error.empty()) return ColorFromBytes(247, 108, 94);
	return ColorFromBytes(255, 191, 92);
}

const char *ReceiverStatusLabel(const App::AppState &state)
{
	if (!state.receiver_enabled) return "Off";
	if (state.receiver_active) return "Listening";
	if (!state.receiver_last_error.empty()) return "Fault";
	return "Idle";
}

//==============================================================================
// Backdrop + card primitives
//==============================================================================

void DrawAppBackdrop()
{
	ImGuiViewport *viewport = ImGui::GetMainViewport();
	ImDrawList *draw_list = ImGui::GetBackgroundDrawList();
	const ImVec2 min = viewport->Pos;
	const ImVec2 max = ImVec2(viewport->Pos.x + viewport->Size.x, viewport->Pos.y + viewport->Size.y);
	draw_list->AddRectFilledMultiColor(min, max, ImGui::GetColorU32(ColorFromBytes(8, 12, 20)), ImGui::GetColorU32(ColorFromBytes(10, 18, 29)), ImGui::GetColorU32(ColorFromBytes(12, 20, 31)),
					   ImGui::GetColorU32(ColorFromBytes(7, 10, 16)));
}

bool BeginCard(const char *id, const char *title, const char *subtitle, float height, bool show_header)
{
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ColorFromBytes(19, 25, 38, 236));
	ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 16.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
	const bool open = ImGui::BeginChild(id, ImVec2(0.0f, height), true, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImDrawList *draw_list = ImGui::GetWindowDrawList();
	const ImVec2 min = ImGui::GetWindowPos();
	const ImVec2 max = ImVec2(min.x + ImGui::GetWindowSize().x, min.y + ImGui::GetWindowSize().y);
	draw_list->AddRectFilled(min, ImVec2(max.x, min.y + 3.0f), ImGui::GetColorU32(ColorFromBytes(255, 183, 80, 220)), 16.0f, ImDrawFlags_RoundCornersTop);
	if (show_header && title && title[0])
		{
			ImGui::TextColored(ColorFromBytes(241, 244, 248), "%s", title);
			if (subtitle && subtitle[0]) ImGui::TextColored(ColorFromBytes(135, 151, 176), "%s", subtitle);
			ImGui::Spacing();
		}
	return open;
}

void InputLabel(const char *label) { ImGui::TextColored(ColorFromBytes(145, 161, 182), "%s", label); }

void EndCard()
{
	ImGui::EndChild();
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor();
}

void DrawMetricTile(const char *id, const char *label, const std::string &value, const ImVec4 &accent)
{
	ImGui::PushID(id);
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ColorFromBytes(14, 19, 29, 235));
	ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 16.0f);
	ImGui::BeginChild("metric", ImVec2(0.0f, 76.0f), true);

	ImDrawList *draw_list = ImGui::GetWindowDrawList();
	const ImVec2 min = ImGui::GetWindowPos();
	const ImVec2 max = ImVec2(min.x + ImGui::GetWindowSize().x, min.y + ImGui::GetWindowSize().y);
	draw_list->AddRectFilled(ImVec2(min.x, max.y - 4.0f), max, ImGui::GetColorU32(accent), 12.0f, ImDrawFlags_RoundCornersBottom);

	ImGui::TextColored(ColorFromBytes(130, 146, 168), "%s", label);
	ImGui::SetWindowFontScale(1.25f);
	ImGui::TextColored(accent, "%s", value.c_str());
	ImGui::SetWindowFontScale(1.0f);

	ImGui::EndChild();
	ImGui::PopStyleVar();
	ImGui::PopStyleColor();
	ImGui::PopID();
}

//==============================================================================
// Layout helpers for polish
//==============================================================================

void DrawSectionDivider() { SectionDivider(); }
void DrawStatusPill(const char *label, const ImVec4 &color) { StatusPill(label, color); }
void BeginMonospace() { PushMonospace(); }
void EndMonospace() { PopMonospace(); }
ImVec4 DmxChannelTint(int channel) { return ChannelTint(channel); }

//==============================================================================
// Top-level panels
//==============================================================================

void RenderHeaderBand(App::AppState &state)
{
	const std::string multicast_preview = App::CurrentMulticastPreview(state);

	ImGui::PushStyleColor(ImGuiCol_ChildBg, ColorFromBytes(14, 20, 31, 238));
	ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 18.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
	ImGui::BeginChild("header-band", ImVec2(0.0f, 70.0f), true, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

	ImDrawList *draw_list = ImGui::GetWindowDrawList();
	const ImVec2 min = ImGui::GetWindowPos();
	const ImVec2 max = ImVec2(min.x + ImGui::GetWindowSize().x, min.y + ImGui::GetWindowSize().y);
	draw_list->AddRectFilledMultiColor(min, max, ImGui::GetColorU32(ColorFromBytes(22, 32, 49, 215)), ImGui::GetColorU32(ColorFromBytes(17, 26, 40, 200)), ImGui::GetColorU32(ColorFromBytes(11, 18, 28, 180)),
					   ImGui::GetColorU32(ColorFromBytes(15, 22, 35, 215)));

	ImGui::BeginGroup();
	ImGui::TextColored(ColorFromBytes(255, 196, 102), "Sig-Net - Cross-platform sender + receiver console");
	ImGui::Dummy(ImVec2(0.0f, 2.0f));
	if (ImGui::RadioButton("Transmit", state.view_mode == App::AppState::ViewTransmit)) state.view_mode = App::AppState::ViewTransmit;
	ImGui::SameLine();
	if (ImGui::RadioButton("Receive", state.view_mode == App::AppState::ViewReceive)) state.view_mode = App::AppState::ViewReceive;
	ImGui::SameLine(0.0f, 16.0f);
	ImGui::TextColored(ColorFromBytes(145, 161, 182), "DMX");
	ImGui::SameLine();
	ImGui::TextColored(ColorFromBytes(90, 201, 131), "%s", App::DmxModeLabel(state));
	ImGui::SameLine(0.0f, 16.0f);
	ImGui::TextColored(ColorFromBytes(145, 161, 182), "RX");
	ImGui::SameLine();
	StatusPill(ReceiverStatusLabel(state), ReceiverStatusColor(state));
	ImGui::SameLine(0.0f, 16.0f);
	ImGui::TextColored(ColorFromBytes(145, 161, 182), "NIC");
	ImGui::SameLine();
	ImGui::TextColored(ColorFromBytes(82, 184, 214), "%s", state.source_ip);
	ImGui::SameLine(0.0f, 16.0f);
	ImGui::TextColored(ColorFromBytes(145, 161, 182), "Mcast");
	ImGui::SameLine();
	ImGui::TextColored(ColorFromBytes(255, 191, 92), "%s", multicast_preview.c_str());
	ImGui::EndGroup();

	ImGui::SameLine(ImGui::GetWindowWidth() - 520.0f);
	ImGui::BeginGroup();
	if (state.view_mode == App::AppState::ViewTransmit)
		{
			ImGui::PushStyleColor(ImGuiCol_Button, ColorFromBytes(68, 130, 178));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ColorFromBytes(82, 155, 207));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive, ColorFromBytes(56, 112, 155));
			if (ImGui::Button("Send Level", ImVec2(118.0f, 30.0f))) App::SendLevelPacket(state, "header action");
			ImGui::PopStyleColor(3);
			ImGui::SameLine();
			if (ImGui::Button("Announce", ImVec2(118.0f, 30.0f))) App::SendAnnouncePacket(state);
			ImGui::SameLine();
			if (ImGui::Button("Self-Test", ImVec2(118.0f, 30.0f))) App::RunSelfTest(state);
			ImGui::SameLine();
			if (ImGui::Button("Refresh NICs", ImVec2(118.0f, 30.0f)))
				{
					App::UpdateInterfaceSelection(state);
					App::LogMessage(state, "Refreshed interface list.");
				}
		}
	else
		{
			ImGui::PushStyleColor(ImGuiCol_Button, state.receiver_enabled ? ColorFromBytes(90, 201, 131) : ColorFromBytes(68, 130, 178));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, state.receiver_enabled ? ColorFromBytes(113, 217, 150) : ColorFromBytes(82, 155, 207));
			ImGui::PushStyleColor(ImGuiCol_ButtonActive, state.receiver_enabled ? ColorFromBytes(68, 173, 112) : ColorFromBytes(56, 112, 155));
			if (ImGui::Button(state.receiver_enabled ? "Stop Listen" : "Start Listen", ImVec2(118.0f, 30.0f)))
				{
					state.receiver_enabled = !state.receiver_enabled;
					App::LogReceiveMessage(state, state.receiver_enabled ? "Receiver enabled." : "Receiver disabled.");
				}
			ImGui::PopStyleColor(3);
			ImGui::SameLine();
			if (ImGui::Button("Clear Nodes", ImVec2(118.0f, 30.0f)))
				{
					state.discovered_nodes.clear();
					state.selected_discovered_node = -1;
					App::LogReceiveMessage(state, "Cleared discovered node list.");
				}
			ImGui::SameLine();
			if (ImGui::Button("Clear Rx Log", ImVec2(118.0f, 30.0f))) state.receive_log_lines.clear();
			ImGui::SameLine();
			if (ImGui::Button("Refresh NICs", ImVec2(118.0f, 30.0f)))
				{
					App::UpdateInterfaceSelection(state);
					App::LogReceiveMessage(state, "Refreshed interface list.");
				}
		}
	ImGui::EndGroup();

	ImGui::EndChild();
	ImGui::PopStyleVar(2);
	ImGui::PopStyleColor();
}

void RenderTransmitTopRegion(App::AppState &state, float top_height, Uint32 now_ticks)
{
	if (ImGui::BeginChild("top-region", ImVec2(0.0f, top_height), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse))
		{
			if (ImGui::BeginTable("main-layout", 2, ImGuiTableFlags_SizingStretchProp))
				{
					ImGui::TableSetupColumn("Controls", ImGuiTableColumnFlags_WidthFixed, 460.0f);
					ImGui::TableSetupColumn("Workspace", ImGuiTableColumnFlags_WidthStretch);

					ImGui::TableNextColumn();
					const float control_row_height = std::max(150.0f, top_height - 12.0f);
					if (BeginCard("control-card", "Transmit Controls", "Key setup, device, announce, and transport.", control_row_height))
						{
							if (ImGui::BeginTabBar("control-tabs", ImGuiTabBarFlags_FittingPolicyResizeDown))
								{
									if (ImGui::BeginTabItem("Key Setup"))
										{
											InputLabel("Passphrase");
											ImGui::SetNextItemWidth(-90.0f);
											if (ImGui::InputText("##passphrase", state.passphrase, sizeof(state.passphrase))) App::RefreshPassphraseReport(state);
											ImGui::SameLine();
											StatusPill(PassphraseStatusLabel(state.passphrase_status), PassphraseStatusColor(state.passphrase_status));
											if (ImGui::BeginChild("passphrase-report", ImVec2(0.0f, 40.0f), false))
												ImGui::TextWrapped("%s", state.passphrase_report[0] ? state.passphrase_report : "");
											ImGui::EndChild();
											if (ImGui::Button("Derive", ImVec2(-60.0f, 0.0f))) App::DeriveK0FromPassphrase(state);
											ImGui::SameLine();
											if (ImGui::Button("Rnd##pass", ImVec2(52.0f, 0.0f))) App::GenerateRandomPassphrase(state);
											SectionDivider();
											InputLabel("K0 Hex");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputText("##k0hex", state.k0_hex, sizeof(state.k0_hex));
											if (ImGui::Button("Passphrase to K0", ImVec2(-60.0f, 0.0f))) App::ApplyK0Hex(state);
											ImGui::SameLine();
											if (ImGui::Button("Rnd##k0", ImVec2(52.0f, 0.0f))) App::GenerateRandomK0(state);
											SectionDivider();
											InputLabel("Sender Key");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputText("##senderkey", state.sender_key_hex, sizeof(state.sender_key_hex), ImGuiInputTextFlags_ReadOnly);
											InputLabel("Citizen Key");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputText("##citizenkey", state.citizen_key_hex, sizeof(state.citizen_key_hex), ImGuiInputTextFlags_ReadOnly);
											ImGui::EndTabItem();
										}

									if (ImGui::BeginTabItem("Device + Network"))
										{
											const std::string multicast_preview = App::CurrentMulticastPreview(state);
											InputLabel("TUID");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputText("##tuid", state.tuid_hex, sizeof(state.tuid_hex));
											InputLabel("Endpoint");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputInt("##endpoint", &state.endpoint);
											InputLabel("Universe");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputInt("##universe", &state.universe);
											SectionDivider();
											InputLabel("Source Interface");
											if (ImGui::BeginCombo("Source Interface", state.interfaces.empty() ? "127.0.0.1" : state.interfaces[state.selected_interface_index].label.c_str()))
												{
													for (size_t i = 0; i < state.interfaces.size(); ++i)
														{
															const bool selected = static_cast<int>(i) == state.selected_interface_index;
															if (ImGui::Selectable(state.interfaces[i].label.c_str(), selected))
																{
																	state.selected_interface_index = static_cast<int>(i);
																	App::CopyString(state.source_ip, sizeof(state.source_ip), state.interfaces[i].ip);
																}
															if (selected) ImGui::SetItemDefaultFocus();
														}
													ImGui::EndCombo();
												}
											InputLabel("Source IP");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputText("##sourceip", state.source_ip, sizeof(state.source_ip));
											ImGui::TextColored(ColorFromBytes(130, 146, 168), "Current Multicast");
											ImGui::SameLine();
											ImGui::TextColored(ColorFromBytes(255, 191, 92), "%s", multicast_preview.c_str());
											ImGui::EndTabItem();
										}

									if (ImGui::BeginTabItem("Announce Packet"))
										{
											InputLabel("Version Number");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputInt("##versionnum", &state.announce_version_num);
											InputLabel("Version String");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputText("##versionstring", state.announce_version_string, sizeof(state.announce_version_string));
											InputLabel("Manufacturer Code");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputText("##mfgcode", state.announce_mfg_code, sizeof(state.announce_mfg_code));
											InputLabel("Product Variant");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputText("##productvariant", state.announce_product_variant, sizeof(state.announce_product_variant));
											if (ImGui::Button("Send Announce", ImVec2(-1.0f, 0.0f))) App::SendAnnouncePacket(state);
											ImGui::EndTabItem();
										}

									if (ImGui::BeginTabItem("Transmit"))
										{
											const int mode = state.dmx_mode == App::AppState::Manual ? 0 : 1;
											if (ImGui::RadioButton("Manual", mode == 0))
												{
													state.dmx_mode = App::AppState::Manual;
													App::LogMessage(state, "DMX mode set to Manual.");
												}
											ImGui::SameLine();
											if (ImGui::RadioButton("Dynamic RGB", mode == 1))
												{
													state.dmx_mode = App::AppState::Dynamic;
													state.last_dynamic_tick = now_ticks;
													App::LogMessage(state, "DMX mode set to Dynamic RGB.");
												}
											SectionDivider();
											ImGui::Checkbox("Keep Alive", &state.keep_alive_enabled);
											ImGui::SameLine();
											if (ImGui::Checkbox("Bad Frames", &state.insert_bad_frames)) state.good_frames_since_bad = 0;
											InputLabel("Bad Frame Every");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputInt("##badframeevery", &state.bad_frame_interval);
											if (ImGui::Button("Send Level Packet", ImVec2(-1.0f, 0.0f))) App::SendLevelPacket(state, "manual button");
											SectionDivider();
											ImGui::TextColored(ColorFromBytes(145, 161, 182), "RGB Pattern");
											ImGui::SameLine();
											ImGui::PushStyleColor(ImGuiCol_FrameBg, ColorFromBytes(state.rgb_r, state.rgb_g, state.rgb_b));
											ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
											ImGui::Dummy(ImVec2(20.0f, 14.0f));
											ImGui::PopStyleVar();
											ImGui::PopStyleColor();
											ImGui::SameLine();
											ImGui::TextColored(ColorFromBytes(state.rgb_r, state.rgb_g, state.rgb_b), "%u  %u  %u", state.rgb_r, state.rgb_g, state.rgb_b);
											ImGui::EndTabItem();
										}

									ImGui::EndTabBar();
								}
						}
					EndCard();

					ImGui::TableNextColumn();
					const float status_height = 104.0f;
					const float dmx_height = std::max(170.0f, top_height - status_height - 12.0f);
					if (BeginCard("status-card", "", "", status_height, false))
						{
							if (ImGui::BeginTable("status-metrics", 4, ImGuiTableFlags_SizingStretchSame))
								{
									ImGui::TableNextColumn();
									DrawMetricTile("sends", "Packets", std::to_string(state.send_count), ColorFromBytes(90, 201, 131));
									ImGui::TableNextColumn();
									DrawMetricTile("errors", "Errors", std::to_string(state.error_count), ColorFromBytes(247, 108, 94));
									ImGui::TableNextColumn();
									DrawMetricTile("session", "Session / Seq", App::FormatString("%u / %u", state.session_id, state.sequence_num), ColorFromBytes(82, 184, 214));
									ImGui::TableNextColumn();
									DrawMetricTile("bytes", "Last Size", std::to_string(state.last_packet_size), ColorFromBytes(255, 191, 92));
									ImGui::EndTable();
								}
						}
					EndCard();

					ImGui::Dummy(ImVec2(0.0f, 8.0f));
					if (BeginCard("dmx-card", "DMX Surface", "", dmx_height - 24.0f)) RenderDmxSliders(state, dmx_height - 64.0f);
					EndCard();

					ImGui::EndTable();
				}
		}
	ImGui::EndChild();
}

void RenderTransmitBottomRegion(App::AppState &state, float bottom_height)
{
	if (ImGui::BeginTable("inspect-layout", 2, ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("Packet", ImGuiTableColumnFlags_WidthStretch, 0.52f);
			ImGui::TableSetupColumn("Log", ImGuiTableColumnFlags_WidthStretch, 0.48f);

			ImGui::TableNextColumn();
			if (BeginCard("packet-card", "Packet Preview", "Hex dump of the most recently transmitted CoAP payload.", bottom_height))
				{
					if (ImGui::BeginChild("packet-preview", ImVec2(0.0f, bottom_height - 58.0f), false))
						{
							PushMonospace();
							ImGui::TextUnformatted(state.last_preview.hex_dump.empty() ? "No packets sent yet." : state.last_preview.hex_dump.c_str());
							PopMonospace();
						}
					ImGui::EndChild();
				}
			EndCard();

			ImGui::TableNextColumn();
			if (BeginCard("log-card", "Event Log", "Operational timeline, validation output, and transport errors.", bottom_height))
				{
					ImGui::Checkbox("Auto-scroll log", &state.auto_scroll_log);
					if (ImGui::BeginChild("event-log", ImVec2(0.0f, bottom_height - 82.0f), false))
						{
							for (const std::string &line : state.log_lines)
								{
									if (line.find("ERROR") != std::string::npos)
										ImGui::TextColored(ColorFromBytes(247, 108, 94), "%s", line.c_str());
									else if (line.find("Self-test") != std::string::npos || line.find("passed") != std::string::npos)
										ImGui::TextColored(ColorFromBytes(90, 201, 131), "%s", line.c_str());
									else
										ImGui::TextUnformatted(line.c_str());
								}
							if (state.auto_scroll_log && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);
						}
					ImGui::EndChild();
				}
			EndCard();

			ImGui::EndTable();
		}
}

void RenderReceiveTopRegion(App::AppState &state, float top_height)
{
	const Uint32 now_ticks = SDL_GetTicks();
	if (ImGui::BeginChild("top-region", ImVec2(0.0f, top_height), false, ImGuiWindowFlags_NoScrollbar))
		{
			if (ImGui::BeginTable("receive-layout", 2, ImGuiTableFlags_SizingStretchProp))
				{
					ImGui::TableSetupColumn("Controls", ImGuiTableColumnFlags_WidthFixed, 460.0f);
					ImGui::TableSetupColumn("Discovery", ImGuiTableColumnFlags_WidthStretch);

					ImGui::TableNextColumn();
					const float control_height = std::max(150.0f, top_height - 12.0f);

					if (BeginCard("receive-control-card", "Receive Controls", "Monitor, security, and selected node.", control_height))
						{
							if (ImGui::BeginTabBar("receive-tabs", ImGuiTabBarFlags_FittingPolicyResizeDown))
								{
									if (ImGui::BeginTabItem("Receive Monitor"))
										{
											ImGui::Checkbox("Enable Receiver", &state.receiver_enabled);
											ImGui::SameLine();
											ImGui::Checkbox("Node Announces", &state.receiver_listen_announces);
											ImGui::SameLine();
											ImGui::Checkbox("Universe Traffic", &state.receiver_listen_universe);
											InputLabel("Universe");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputInt("##receiveuniverse", &state.universe);
											InputLabel("Source Interface");
											if (ImGui::BeginCombo("Receive Interface", state.interfaces.empty() ? "127.0.0.1" : state.interfaces[state.selected_interface_index].label.c_str()))
												{
													for (size_t i = 0; i < state.interfaces.size(); ++i)
														{
															const bool selected = static_cast<int>(i) == state.selected_interface_index;
															if (ImGui::Selectable(state.interfaces[i].label.c_str(), selected))
																{
																	state.selected_interface_index = static_cast<int>(i);
																	App::CopyString(state.source_ip, sizeof(state.source_ip), state.interfaces[i].ip);
																}
															if (selected) ImGui::SetItemDefaultFocus();
														}
													ImGui::EndCombo();
												}
											ImGui::TextColored(ColorFromBytes(145, 161, 182), "Status");
											ImGui::SameLine();
											StatusPill(ReceiverStatusLabel(state), ReceiverStatusColor(state));
											ImGui::SameLine(0.0f, 12.0f);
											ImGui::TextColored(ColorFromBytes(145, 161, 182), "Node Group");
											ImGui::SameLine();
											ImGui::TextUnformatted(SigNet::MULTICAST_NODE_SEND_IP);
											ImGui::TextColored(ColorFromBytes(145, 161, 182), "Universe Group");
											ImGui::SameLine();
											ImGui::TextUnformatted(App::CurrentMulticastPreview(state).c_str());
											if (!state.receiver_last_error.empty()) ImGui::TextWrapped("%s", state.receiver_last_error.c_str());
											ImGui::EndTabItem();
										}

									if (ImGui::BeginTabItem("Security + Identity"))
										{
											InputLabel("TUID");
											ImGui::SetNextItemWidth(-1.0f);
											ImGui::InputText("##receivetuid", state.tuid_hex, sizeof(state.tuid_hex));
											ImGui::TextColored(ColorFromBytes(145, 161, 182), "Keys");
											ImGui::SameLine();
											StatusPill(state.keys_valid ? "Ready" : "Unavailable", state.keys_valid ? ColorFromBytes(90, 201, 131) : ColorFromBytes(255, 191, 92));
											ImGui::Dummy(ImVec2(0.0f, 4.0f));
											ImGui::TextWrapped("Citizenship key verifies /node announces.");
											ImGui::TextWrapped("Sender key verifies /level payloads on the selected universe.");
											ImGui::EndTabItem();
										}

									if (ImGui::BeginTabItem("Selected Node"))
										{
											RenderSelectedNodeDetails(state, now_ticks);
											ImGui::EndTabItem();
										}

									if (ImGui::BeginTabItem("Node Simulator"))
										{
											if (ImGui::BeginChild("##nodesim-scroll-rx", ImVec2(0.0f, -32.0f), true))
												{
													ImGui::Checkbox("Enable Simulator", &state.node_simulator_enabled);
													ImGui::SliderInt("Query Level", &state.node_simulator_query_level, 0, SigNet::QUERY_FULL);
													ImGui::SliderInt("Proactive (ms)", reinterpret_cast<int*>(&state.node_simulator_proactive_interval_ms), 0, 60000);
													ImGui::Checkbox("Respond to Polls", &state.node_simulator_respond_to_polls);
													ImGui::Checkbox("Respond to Gets", &state.node_simulator_respond_to_gets);
													ImGui::Checkbox("Respond to Sets", &state.node_simulator_respond_to_sets);
													ImGui::Checkbox("Proactive Responses", &state.node_simulator_proactive_responses);
													ImGui::Separator();
													ImGui::TextDisabled("K0 Configuration");
													ImGui::InputScalar("K0 (hex)", ImGuiDataType_U8, state.k0_key.data(), NULL, NULL, "%02X", ImGuiInputTextFlags_CharsHexadecimal);
													ImGui::InputScalar("TUID (hex)", ImGuiDataType_U8, state.tuid.data(), NULL, NULL, "%02X", ImGuiInputTextFlags_CharsHexadecimal);
													ImGui::Separator();
													ImGui::TextDisabled("Derived Keys");
													ImGui::Text("Global: %.2x%.2x%.2x ... %.2x",
														state.manager_global_key[0], state.manager_global_key[1], state.manager_global_key[2],
														state.manager_global_key[SigNet::DERIVED_KEY_LENGTH - 1]);
													ImGui::Text("Local:  %.2x%.2x%.2x ... %.2x",
														state.manager_local_key[0], state.manager_local_key[1], state.manager_local_key[2],
														state.manager_local_key[SigNet::DERIVED_KEY_LENGTH - 1]);
													ImGui::Separator();
													ImGui::TextDisabled("Simulator Stats");
													ImGui::Text("Polls responded: %u", state.node_stats_poll_responses);
													ImGui::Text("Gets responded: %u", state.node_stats_get_responses);
													ImGui::Text("Sets accepted: %u", state.node_stats_set_responses);
													ImGui::Text("Replays rejected: %u", state.node_stats_replay_rejected);
													ImGui::Text("HMAC failures: %u", state.node_stats_hmac_failures);
													ImGui::Separator();
													ImGui::TextDisabled("Lost Mode");
													ImGui::Checkbox("Activate Lost Mode", &state.node_simulator_lost_mode);
													ImGui::SliderInt("Timeout (ms)", reinterpret_cast<int*>(&state.node_lost_timeout_ms), 0, 60000);
													ImGui::Text("In Lost Mode: %s", state.in_lost_mode ? "YES" : "NO");
												}
											ImGui::EndChild();
											ImGui::EndTabItem();
										}

									ImGui::EndTabBar();
								}
						}
					EndCard();

					ImGui::TableNextColumn();
					const float status_height = 104.0f;
					const float table_height = std::max(170.0f, top_height - status_height - 12.0f);
					if (BeginCard("receive-status-card", "", "", status_height, false))
						{
							if (ImGui::BeginTable("receive-status-metrics", 4, ImGuiTableFlags_SizingStretchSame))
								{
									ImGui::TableNextColumn();
									DrawMetricTile("rx-packets", "Packets", std::to_string(state.received_packet_count), ColorFromBytes(90, 201, 131));
									ImGui::TableNextColumn();
									DrawMetricTile("rx-nodes", "Nodes", std::to_string(state.discovered_nodes.size()), ColorFromBytes(82, 184, 214));
									ImGui::TableNextColumn();
									DrawMetricTile("rx-verified", "Verified", std::to_string(App::CountVerifiedNodes(state)), ColorFromBytes(255, 191, 92));
									ImGui::TableNextColumn();
									DrawMetricTile("rx-kind", "Last Packet", state.last_received_preview.packet_kind.empty() ? "Idle" : state.last_received_preview.packet_kind,
										       ColorFromBytes(247, 108, 94));
									ImGui::EndTable();
								}
						}
					EndCard();

					ImGui::Dummy(ImVec2(0.0f, 8.0f));
					if (BeginCard("discovery-card", "Discovered Nodes", "Announce traffic updates this table in real time.", table_height)) RenderDiscoveredNodesTable(state, table_height - 52.0f, now_ticks);
					EndCard();

					ImGui::EndTable();
				}
		}
	ImGui::EndChild();
}

void RenderReceiveBottomRegion(App::AppState &state, float bottom_height)
{
	if (ImGui::BeginTable("receive-inspect-layout", 2, ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("Packet", ImGuiTableColumnFlags_WidthStretch, 0.55f);
			ImGui::TableSetupColumn("Log", ImGuiTableColumnFlags_WidthStretch, 0.45f);

			ImGui::TableNextColumn();
			if (BeginCard("receive-packet-card", "Receive Packet Preview", "Most recent packet captured by the local receiver.", bottom_height))
				{
					ImGui::TextColored(ColorFromBytes(145, 161, 182), "Source");
					ImGui::SameLine();
					ImGui::TextUnformatted(state.last_received_preview.source_ip.empty() ? "n/a" : state.last_received_preview.source_ip.c_str());
					ImGui::SameLine(0.0f, 12.0f);
					ImGui::TextColored(ColorFromBytes(145, 161, 182), "Kind");
					ImGui::SameLine();
					ImGui::TextUnformatted(state.last_received_preview.packet_kind.empty() ? "Idle" : state.last_received_preview.packet_kind.c_str());
					ImGui::SameLine(0.0f, 12.0f);
					ImGui::TextColored(ColorFromBytes(145, 161, 182), "HMAC");
					ImGui::SameLine();
					StatusPill(VerificationLabel(state.last_received_preview.verify_attempted, state.last_received_preview.hmac_verified),
						   VerificationColor(state.last_received_preview.verify_attempted, state.last_received_preview.hmac_verified));
					if (!state.last_received_preview.uri.empty()) ImGui::TextWrapped("%s", state.last_received_preview.uri.c_str());
					if (ImGui::BeginChild("receive-packet-preview", ImVec2(0.0f, bottom_height - 92.0f), false))
						{
							PushMonospace();
							ImGui::TextUnformatted(state.last_received_preview.hex_dump.empty() ? "No packets received yet." : state.last_received_preview.hex_dump.c_str());
							PopMonospace();
						}
					ImGui::EndChild();
				}
			EndCard();

			ImGui::TableNextColumn();
			if (BeginCard("receive-log-card", "Receive Log", "Discovery events, HMAC failures, and receiver errors.", bottom_height))
				{
					ImGui::Checkbox("Auto-scroll receive log", &state.auto_scroll_receive_log);
					if (ImGui::BeginChild("receive-log", ImVec2(0.0f, bottom_height - 82.0f), false))
						{
							for (const std::string &line : state.receive_log_lines)
								{
									if (line.find("ERROR") != std::string::npos)
										ImGui::TextColored(ColorFromBytes(247, 108, 94), "%s", line.c_str());
									else if (line.find("Discovered") != std::string::npos)
										ImGui::TextColored(ColorFromBytes(82, 184, 214), "%s", line.c_str());
									else if (line.find("HMAC mismatch") != std::string::npos)
										ImGui::TextColored(ColorFromBytes(255, 191, 92), "%s", line.c_str());
									else
										ImGui::TextUnformatted(line.c_str());
								}
							if (state.auto_scroll_receive_log && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);
						}
					ImGui::EndChild();
				}
			EndCard();

			ImGui::EndTable();
		}
}

} // namespace UI