/*
 * WPK64_readable.c - forensic, inert C reconstruction of WPK64.exe.
 *
 * Source image SHA-256:
 * 980d667a7abdf54d598cbbdbb51f3ed2f70614c6b1e3950721834e9ae90f5f56
 * Inputs: supplied WPK64.c and independently extracted MSI payload.
 * Original image base: 0x140000000. Original entry: 0x140001710.
 *
 * This is a semantic reconstruction, not recovered original source code.
 * Application control flow is separated from the Visual C++ 2008 CRT.
 * Native window creation, hooks, threads, events, and mutexes are represented
 * by state changes and explanatory messages. No Windows APIs are linked.
 * Nothing captures input, injects a DLL, persists, or communicates.
 *
 * Build: cc -std=c11 -Wall -Wextra -Werror WPK64_readable.c -o wpk64_model
 * Run:   ./wpk64_model --marker
 * Test:  ./wpk64_model --self-test
 *
 * Fidelity notes:
 * - #3763 is a substring gate, not a secret, authentication, or exact argv test.
 * - The mutex uses bInitialOwner=FALSE in the original. Its existence is tested.
 * - The quit event is manual-reset, initially nonsignaled, and named _CON_QUIT_.
 * - The original wait thread calls exit(0) after WaitForSingleObject returns,
 *   irrespective of the wait result. This includes WAIT_FAILED.
 * - The original message loop checks only != 0, not GetMessageW == -1.
 * - The original ShowWindow value is 0 (SW_HIDE).
 * - IMME64.dll contains the hook implementations; this helper imports them.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char INSTANCE_MUTEX[] = "WWWPXX64_ON_";
static const char QUIT_EVENT[] = "_CON_QUIT_";
static const char WINDOW_TITLE[] = "WPK64_W";
static const char ACTIVATION_MARKER[] = "#3763";

enum { MENU_ABOUT = 0x68, MENU_EXIT = 0x69 };

typedef enum {
    MSG_PAINT,
    MSG_COMMAND_ABOUT,
    MSG_COMMAND_EXIT,
    MSG_DESTROY,
    MSG_OTHER
} ModelMessage;

typedef struct {
    bool mutex_creation_succeeds;
    bool instance_already_exists;
    bool event_creation_succeeds;
    bool window_creation_succeeds;
    bool verbose;
} Environment;

typedef struct {
    bool quit_event_created;
    bool quit_waiter_started;
    bool class_registered;
    bool window_created;
    bool window_hidden;
    bool hook_requested;
    bool hook_cleared;
    bool message_loop_entered;
    bool quit_posted;
    bool process_exit_requested;
    unsigned exit_code;
} Wpk64State;

static void note(const Environment *env, const char *operation)
{
    if (env->verbose) printf("MODEL: %s\n", operation);
}

/* Original FUN_140001000: quit-event wait thread. No real wait occurs here. */
static void quit_waiter_returned(Wpk64State *state, const Environment *env,
                                bool wait_failed)
{
    (void)wait_failed; /* The original does not test the wait return value. */
    note(env, "quit waiter returned; original unconditionally calls exit(0)");
    state->process_exit_requested = true;
    state->exit_code = 0;
}

/* Original FUN_1400011a0: register WNDCLASSEXW, resources 0x6b/0x6c/0x6d. */
static void register_window_class(Wpk64State *state, const Environment *env)
{
    state->class_registered = true;
    note(env, "register class: style=3; callback=0x1400012e0; menu=0x6d");
}

/* Original FUN_140001240: CreateWindowExW, hook import, then SW_HIDE. */
static bool create_hidden_window(Wpk64State *state, const Environment *env)
{
    note(env, "request overlapped window titled WPK64_W (creation stub)");
    if (!env->window_creation_succeeds) return false;
    state->window_created = true;
    state->hook_requested = true;
    note(env, "IMME64!setLBDownHook64(window) represented by an inert flag");
    state->window_hidden = true;
    return true;
}

/* Original FUN_1400012e0. WM_DESTROY=2; WM_PAINT=15; WM_COMMAND=273. */
static void window_message(Wpk64State *state, const Environment *env,
                           ModelMessage message)
{
    switch (message) {
    case MSG_DESTROY:
        state->hook_cleared = true;
        state->hook_requested = false;
        state->quit_posted = true;
        note(env, "IMME64!clearLBDownHook64 stub; PostQuitMessage(0) modeled");
        break;
    case MSG_PAINT:
        note(env, "BeginPaint/EndPaint pair; no visible content");
        break;
    case MSG_COMMAND_ABOUT:
        note(env, "low word 0x68: original consumes command without a dialog");
        break;
    case MSG_COMMAND_EXIT:
        note(env, "low word 0x69: original calls DestroyWindow");
        window_message(state, env, MSG_DESTROY);
        break;
    case MSG_OTHER:
        note(env, "unhandled message: original delegates to DefWindowProcW");
        break;
    }
}

/* Original FUN_140001020, called by the Unicode GUI CRT startup. */
static unsigned reconstructed_winmain(Wpk64State *state, const Environment *env,
                                      const char *command_line_tail)
{
    note(env, INSTANCE_MUTEX);
    if (env->mutex_creation_succeeds && env->instance_already_exists) {
        state->process_exit_requested = true;
        note(env, "existing mutex / ERROR_ALREADY_EXISTS=183: ExitProcess(0)");
        return 0;
    }

    state->quit_event_created = env->event_creation_succeeds;
    state->quit_waiter_started = true;
    note(env, "create manual-reset _CON_QUIT_ event and quit-wait thread");

    if (strstr(command_line_tail, ACTIVATION_MARKER) == NULL) {
        note(env, "marker absent: return before creating a window or hooks");
        return 0;
    }

    note(env, "LoadStringW resource 0x67: title; 0x6d: class name");
    register_window_class(state, env);
    if (!create_hidden_window(state, env)) return 0;

    state->message_loop_entered = true;
    note(env, "LoadAcceleratorsW(0x6d); Translate/Dispatch message loop");
    /* Bounded, analyst-supplied model. The original waits on a GUI queue. */
    return 0;
}

static int self_test(void)
{
    Environment e = { true, false, true, true, false };
    Wpk64State s = {0};
    reconstructed_winmain(&s, &e, "");
    assert(s.quit_waiter_started && !s.window_created && !s.hook_requested);

    s = (Wpk64State){0};
    reconstructed_winmain(&s, &e, "prefix#3763suffix");
    assert(s.window_hidden && s.hook_requested && s.message_loop_entered);
    window_message(&s, &e, MSG_COMMAND_ABOUT);
    assert(!s.quit_posted);
    window_message(&s, &e, MSG_COMMAND_EXIT);
    assert(s.hook_cleared && s.quit_posted);

    s = (Wpk64State){0}; e.instance_already_exists = true;
    reconstructed_winmain(&s, &e, "#3763");
    assert(s.process_exit_requested && !s.quit_waiter_started);

    s = (Wpk64State){0}; e.mutex_creation_succeeds = false;
    reconstructed_winmain(&s, &e, "#3763");
    assert(s.window_created); /* Original does not fail closed on null mutex. */
    quit_waiter_returned(&s, &e, true);
    assert(s.process_exit_requested && s.exit_code == 0);

    puts("WPK64 semantic checks passed; no native operations were performed.");
    return 0;
}

int main(int argc, char **argv)
{
    Environment e = { true, false, true, true, true };
    Wpk64State s = {0};
    const char *tail = "";
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--self-test") == 0) return self_test();
        if (strcmp(argv[i], "--marker") == 0) tail = "#3763";
        else if (strcmp(argv[i], "--existing") == 0) e.instance_already_exists = true;
        else if (strcmp(argv[i], "--wait-returned") == 0) {
            reconstructed_winmain(&s, &e, "#3763");
            quit_waiter_returned(&s, &e, false);
            return 0;
        }
    }
    printf("Inert WPK64 model; title=%s; quit event=%s\n", WINDOW_TITLE, QUIT_EVENT);
    return (int)reconstructed_winmain(&s, &e, tail);
}
