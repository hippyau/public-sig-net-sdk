//==============================================================================
// sig-net-example-imgui - Entry point
//==============================================================================
//
// SDL2/OpenGL3 bootstrap, the ImGui init sequence, and the main loop. All
// application logic lives in sig-net.hpp/cpp, networking in network.hpp/cpp,
// and rendering in ui.hpp/cpp.
//
//==============================================================================

#include "app.hpp"
#include "network.hpp"
#include "ui.hpp"

#include "backends/imgui_impl_opengl3.h"
#include "backends/imgui_impl_sdl2.h"
#include "imgui.h"

#include <SDL.h>
#include <SDL_opengl.h>

#include <cstdio>

namespace
{

constexpr Uint32 kKeepAliveIntervalMs = 900;
constexpr Uint32 kDynamicIntervalMs = 1000 / SigNet::MAX_ACTIVE_RATE_HZ;

} // namespace

int main(int, char **)
{
	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_GAMECONTROLLER) != 0)
		{
			std::fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
			return 1;
		}


#if defined(__APPLE__)
    const char* glsl_version = "#version 150";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
#else
    const char* glsl_version = "#version 130";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#endif
	
	SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
	SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
	SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);



    
	SDL_Window *window = SDL_CreateWindow("Sig-Net Example ImGui", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1560, 960, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
	if (!window)
		{
			std::fprintf(stderr, "SDL_CreateWindow failed: %s\n", SDL_GetError());
			SDL_Quit();
			return 1;
		}

	SDL_GLContext gl_context = SDL_GL_CreateContext(window);
	if (!gl_context)
		{
			std::fprintf(stderr, "SDL_GL_CreateContext failed: %s\n", SDL_GetError());
			SDL_DestroyWindow(window);
			SDL_Quit();
			return 1;
		}

	SDL_GL_MakeCurrent(window, gl_context);
	SDL_GL_SetSwapInterval(1);

	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGuiIO &io = ImGui::GetIO();
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

	UI::ApplyCustomStyle();

	if (!ImGui_ImplSDL2_InitForOpenGL(window, gl_context))
		{
			std::fprintf(stderr, "ImGui_ImplSDL2_InitForOpenGL failed.\n");
			ImGui::DestroyContext();
			SDL_GL_DeleteContext(gl_context);
			SDL_DestroyWindow(window);
			SDL_Quit();
			return 1;
		}

	if (!ImGui_ImplOpenGL3_Init(glsl_version))
		{
			std::fprintf(stderr, "ImGui_ImplOpenGL3_Init failed.\n");
			ImGui_ImplSDL2_Shutdown();
			ImGui::DestroyContext();
			SDL_GL_DeleteContext(gl_context);
			SDL_DestroyWindow(window);
			SDL_Quit();
			return 1;
		}

	App::AppState state;
	App::InitializeState(state);

	bool done = false;
	while (!done)
		{
			SDL_Event event;
			while (SDL_PollEvent(&event))
				{
					ImGui_ImplSDL2_ProcessEvent(&event);
					if (event.type == SDL_QUIT)
						{
							done = true;
						}
					if (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE && event.window.windowID == SDL_GetWindowID(window))
						{
							done = true;
						}
				}

			const Uint32 now_ticks = SDL_GetTicks();
			if (state.dmx_mode == App::AppState::Dynamic && now_ticks - state.last_dynamic_tick >= kDynamicIntervalMs)
				{
					App::UpdateDynamicPattern(state);
					App::SendLevelPacket(state, "dynamic heartbeat");
					state.last_dynamic_tick = now_ticks;
				}
			if (state.keep_alive_enabled && state.keys_valid && now_ticks - state.last_send_tick >= kKeepAliveIntervalMs)
				{
					App::SendLevelPacket(state, "keep alive");
				}
			App::UpdateReceiver(state);

			ImGui_ImplOpenGL3_NewFrame();
			ImGui_ImplSDL2_NewFrame();
			ImGui::NewFrame();

			UI::DrawAppBackdrop();

			ImGuiViewport *viewport = ImGui::GetMainViewport();
			ImGui::SetNextWindowPos(viewport->WorkPos);
			ImGui::SetNextWindowSize(viewport->WorkSize);
			ImGui::Begin("Sig-Net Example ImGui", nullptr,
				     ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

			UI::RenderHeaderBand(state);
			ImGui::Spacing();

			const float layout_gap = 4.0f;
			const ImVec2 remaining = ImGui::GetContentRegionAvail();
			const float bottom_height = std::max(248.0f, remaining.y * 0.34f);
			const float top_height = std::max(300.0f, remaining.y - bottom_height - layout_gap);

			if (state.view_mode == App::AppState::ViewTransmit)
				{
					UI::RenderTransmitTopRegion(state, top_height, now_ticks);
				}
			else
				{
					UI::RenderReceiveTopRegion(state, top_height);
				}

			ImGui::Dummy(ImVec2(0.0f, layout_gap));
			if (state.view_mode == App::AppState::ViewTransmit)
				{
					UI::RenderTransmitBottomRegion(state, bottom_height);
				}
			else
				{
					UI::RenderReceiveBottomRegion(state, bottom_height);
				}

			ImGui::End();

			ImGui::Render();
			int display_w = 0;
			int display_h = 0;
			SDL_GL_GetDrawableSize(window, &display_w, &display_h);
			glViewport(0, 0, display_w, display_h);
			glClearColor(0.04f, 0.05f, 0.08f, 1.0f);
			glClear(GL_COLOR_BUFFER_BIT);
			ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
			SDL_GL_SwapWindow(window);
		}

	state.udp_sender.Shutdown();
	state.udp_receiver.Shutdown();
	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplSDL2_Shutdown();
	ImGui::DestroyContext();
	SDL_GL_DeleteContext(gl_context);
	SDL_DestroyWindow(window);
	SDL_Quit();
	return 0;
}
