/*
 * WPK_readable.c - human-readable forensic reconstruction of iSafe WPK.exe.
 *
 * Original SHA-256:
 * 35e6be911a65cae4fab14f5354c66a8ef5fb19301043d2456804fcb3a59e0ec4
 * Original base=0x00400000; entry=0x007e6a12; business main=0x00833e90.
 * Sources: supplied 280,653-line decompilation, independently extracted PE,
 * subcfg, W0000, MSI tables, Sysmon and Security exports.
 *
 * STATUS: semantic reconstruction of recoverable application behavior.
 * It is neither byte-equivalent source nor a complete C++/MFC reimplementation.
 * Opaque UNK worker bodies are labeled by address, not filled with invented code.
 * CRT, Chilkat, SQLite internals, C++ exception thunks, and library wrappers
 * are intentionally abstracted. Configuration parsing below is real, passive,
 * bounds-checked C; monitoring, delivery, persistence and process launching
 * have only inert descriptions. No platform callbacks can be installed.
 *
 * Build: cc -std=c11 -Wall -Wextra -Werror WPK_readable.c -o wpk_model
 * Test: ./wpk_model --self-test
 * Inspect supplied configuration locally: ./wpk_model --inspect-config PATH
 * The inspector never displays the stored SMTP secret or captured input.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

enum {
    CONFIG_BODY_BYTES = 0x11d8,
    CONFIG_FILE_BYTES = 0x11dc,
    CONFIG_DWORDS = CONFIG_BODY_BYTES / 4,
    INSTANCE_ALREADY_EXISTS = 183,
    MAIN_TIMER_ID = 1,
    MAIN_TIMER_MS = 1000,
    HOTKEY_ID = 0x699,
    DEFAULT_HOTKEY = 0x00070058,
    RAW_INPUT_SINK = 0x100
};

/* File offsets include the four-byte update counter, not just the body. */
enum {
    OFF_MAIL_LABEL = 0x1c,
    OFF_SMTP_SERVER = 0xec,
    OFF_SMTP_ACCOUNT = 0x1bc,
    OFF_SMTP_SECRET = 0x284,
    OFF_HOTKEY = 0x388
};

typedef struct {
    uint32_t update_counter;
    uint32_t words[CONFIG_DWORDS];
    char mail_label[105];
    char smtp_server[105];
    char smtp_account[101];
    size_t smtp_secret_code_units; /* Content is never retained in this view. */
    uint32_t hotkey;
} ConfigView;

typedef struct {
    const char *original_name;
    uintptr_t address;
    const char *interpretation;
    bool body_recovered;
} Worker;

/* UNK entry points are present as pointers in FUN_008328e4. Their role names
 * below remain deliberately conservative where the supplied C has no body. */
static const Worker WORKERS[] = {
    { "worker_00825b10", 0x00825b10, "application worker; body not supplied", false },
    { "worker_00824010", 0x00824010, "application worker; body not supplied", false },
    { "worker_008323d0", 0x008323d0, "application worker; body not supplied", false },
    { "worker_00832360", 0x00832360, "application worker; body not supplied", false },
    { "worker_00832430", 0x00832430, "conditional worker; body not supplied", false },
    { "worker_0082c850", 0x0082c850, "conditional worker; body not supplied", false },
    { "worker_00830340", 0x00830340, "conditional worker; body not supplied", false },
    { "worker_00830320", 0x00830320, "x64-associated worker; body not supplied", false },
    { "worker_0082c060", 0x0082c060, "application worker; body not supplied", false },
    { "worker_008302f0", 0x008302f0, "conditional worker; body not supplied", false }
};

typedef struct {
    bool already_running;
    bool log_folder_available;
    bool bdel_marker_present;
    bool config_present;
    bool config_size_valid;
    bool database_opens;
    bool database_has_wlog;
    bool database_has_rlog;
    bool winsock_startup_succeeds;
    bool hidden_window_succeeds;
    bool native_system_is_64_bit;
    bool kernel_mode_marker_present;
    bool verbose;
} Environment;

typedef struct {
    bool diagnostic_log_open;
    bool paths_prepared;
    bool config_loaded;
    bool database_ready;
    bool window_created;
    bool clipboard_subscription_requested;
    bool mouse_hook_requested;
    bool raw_keyboard_requested;
    bool raw_mouse_requested;
    bool gui_message_loop_entered;
    bool helper_launch_requested;
    bool exit_requested;
    uint32_t timer_interval_ms;
    unsigned opaque_worker_requests;
    char log_directory[260];
    ConfigView configuration;
} WpkState;

static void effect(const Environment *env, const char *description)
{
    if (env->verbose) printf("MODEL: %s\n", description);
}

static uint32_t read_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* The actual struct stores UTF-16 strings. ASCII is enough for endpoint
 * inspection; unsupported non-ASCII code units become '?', without overruns. */
static size_t utf16_field(const unsigned char *file, size_t size,
                          size_t offset, size_t max_units,
                          char *destination, size_t capacity)
{
    size_t units = 0, written = 0;
    if (capacity) destination[0] = '\0';
    if (offset > size) return 0;
    while (units < max_units && size - offset >= 2) {
        uint16_t c = (uint16_t)file[offset] | (uint16_t)file[offset + 1] << 8;
        if (c == 0) break;
        if (destination && written + 1 < capacity)
            destination[written++] = (c >= 32 && c < 127) ? (char)c : '?';
        ++units; offset += 2;
    }
    if (destination && capacity) destination[written] = '\0';
    return units;
}

/* FUN_008429a0 reads a four-byte header, then file-size-minus-four bytes.
 * FUN_008310d0 expects exactly 0x11dc on disk and copies 0x11d8 to globals.
 * Here a read-only parser replaces the original open/read/write wrapper. */
static bool parse_config(const unsigned char *file, size_t size, ConfigView *out)
{
    if (!file || !out || size != CONFIG_FILE_BYTES) return false;
    memset(out, 0, sizeof *out);
    out->update_counter = read_le32(file);
    for (size_t i = 0; i < CONFIG_DWORDS; ++i)
        out->words[i] = read_le32(file + 4 + i * 4);
    utf16_field(file, size, OFF_MAIL_LABEL, 104,
                out->mail_label, sizeof out->mail_label);
    utf16_field(file, size, OFF_SMTP_SERVER, 104,
                out->smtp_server, sizeof out->smtp_server);
    utf16_field(file, size, OFF_SMTP_ACCOUNT, 100,
                out->smtp_account, sizeof out->smtp_account);
    out->smtp_secret_code_units = utf16_field(file, size, OFF_SMTP_SECRET,
                                             100, NULL, 0);
    out->hotkey = read_le32(file + OFF_HOTKEY);
    return true;
}

/* FUN_008388b0: copy the confirmed numeric defaults without inventing names
 * for flags whose semantics are unresolved. Original default access strings
 * are intentionally omitted because this model has no authentication UI. */
static void numeric_config_defaults(ConfigView *config)
{
    static const unsigned enabled[] = {
        0, 1, 2, 3, 4, 0xd2, 0xd3, 0xd4, 0xd7, 0xdc, 0xde, 0xe0,
        0x104, 0x105, 0x106, 0x107, 0x108, 0x109, 0x10a, 0x10b,
        0x10c, 0x10d, 0x10f, 0x110, 0x114, 0x115, 0x116, 0x117,
        0x15a, 0x467, 0x469, 0x46a, 0x46b, 0x46c, 0x46d, 0x46e,
        0x46f, 0x470, 0x471, 0x472, 0x473, 0x474, 0x475
    };
    memset(config, 0, sizeof *config);
    for (size_t i = 0; i < sizeof enabled / sizeof enabled[0]; ++i)
        config->words[enabled[i]] = 1;
    config->words[0xe1] = DEFAULT_HOTKEY;
    config->words[0xe2] = 20;
    config->words[0xe3] = 500;
    config->words[0xe4] = 40;
    config->words[0xe5] = 100;
    config->hotkey = DEFAULT_HOTKEY;
}

/* FUN_00823950 / FUN_00823c70: diagnostic stream and serialized append.
 * Original basename: ixsaflog.dat; named mutex: _MUTEXT-LOG-FIE_. */
static void diagnostic_open(WpkState *s, const Environment *env)
{
    s->diagnostic_log_open = true;
    effect(env, "diagnostic ixsaflog.dat / _MUTEXT-LOG-FIE_ represented in memory");
}

static void diagnostic_close(WpkState *s, const Environment *env)
{
    s->diagnostic_log_open = false;
    effect(env, "close diagnostic handle (model state only)");
}

/* FUN_008310d0: path preparation, W0000/2/3 and subcfg bootstrap.
 * OS-specific %APPDATA% fallback selection is not fully typed in supplied C.
 * The chosen synthetic path below models the modern %PUBLIC% branch. */
static bool prepare_storage(WpkState *s, const Environment *env)
{
    if (!env->log_folder_available) return false;
    snprintf(s->log_directory, sizeof s->log_directory,
             "%%PUBLIC%%\\L001\\");
    effect(env, "select L001 storage; original requests hidden/system attributes");
    if (env->bdel_marker_present) {
        s->exit_requested = true;
        effect(env, "bdel marker present: original calls ExitProcess(0)");
        return false;
    }
    if (!env->config_present || !env->config_size_valid) {
        numeric_config_defaults(&s->configuration);
        effect(env, "missing/invalid subcfg: original writes a replacement default body");
    } else {
        effect(env, "read subcfg body after four-byte counter; no delivery attempted");
    }
    effect(env, "original checks W0000; extracts CONFIG resource 0x83 if absent");
    effect(env, "original checks/initializes W0002 (0x34) and W0003 (0x80)");
    effect(env, "original touches ftpokay.txt and tests optional kern.bin mode marker");
    s->paths_prepared = true;
    s->config_loaded = true;
    return true;
}

/* FUN_00830380 and FUN_00830c9e: per-user data migration/copy logic.
 * Exact user-selection rules remain partly affected by decompiler stack errors.
 * Confirmed filenames, transaction boundaries and parameterized SQL are kept. */
static void migration_plan(const Environment *env)
{
    effect(env, "migration candidates: subcfg, W0002, W0003 and W0000");
    effect(env, "SQLite migration uses begin/commit transaction boundaries");
    effect(env, "bind values into wLog insertion; no database mutation in this model");
}

/* FUN_00832500 / FUN_008325b5: open DB and verify required table names. */
static bool prepare_database(WpkState *s, const Environment *env)
{
    if (!env->database_opens) return false;
    if (!env->database_has_wlog || !env->database_has_rlog) {
        effect(env, "original has an invalid-format recovery/backup path");
        effect(env, "recovery details remain abstract; model refuses to invent a DB");
        return false;
    }
    s->database_ready = true;
    migration_plan(env);
    return true;
}

/* FUN_00841e00: named event/mutex/mapping transport.
 * This only describes the object-name derivation. It never creates an object.
 * The original explicitly sets a NULL DACL in its SECURITY_DESCRIPTOR. */
static void ipc_plan(const Environment *env, const char *channel, unsigned capacity)
{
    if (!env->verbose) return;
    printf("MODEL: IPC channel %s, capacity=%u\n", channel, capacity);
    printf("MODEL: Global\\EVENT_%s; Global\\MUTEX_%s\n", channel, channel);
    printf("MODEL: Local/Global\\FILEMAPPING_%s; original NULL DACL\n", channel);
}

static void opaque_worker(WpkState *s, const Environment *env, size_t index)
{
    if (index >= sizeof WORKERS / sizeof WORKERS[0]) return;
    ++s->opaque_worker_requests;
    if (env->verbose)
        printf("MODEL: request %s at 0x%08" PRIxPTR " (%s)\n",
               WORKERS[index].original_name, WORKERS[index].address,
               WORKERS[index].interpretation);
}

/* FUN_008328e4: recoverable event registration and orchestration. */
static void monitoring_plan(WpkState *s, const Environment *env)
{
    uint32_t hotkey = s->configuration.hotkey;
    if (hotkey == 0) hotkey = DEFAULT_HOTKEY;
    effect(env, "GDI+ startup and SetClipboardViewer requests are inert");
    s->clipboard_subscription_requested = true;
    if (env->verbose)
        printf("MODEL: hotkey id=0x%x, modifiers=0x%x, vk=0x%x\n",
               HOTKEY_ID, hotkey >> 16, hotkey & 0xffff);
    s->mouse_hook_requested = true;
    effect(env, "IMME!setLBDownHook(window) and WTS session notifications abstracted");
    s->raw_keyboard_requested = true;
    s->raw_mouse_requested = true;
    effect(env, "raw input: page=1 usage=6 and page=1 usage=2, flags=0x100");

    for (size_t i = 0; i < 4; ++i) opaque_worker(s, env, i);
    effect(env, "manual-reset quit event _CON_QUIT_ represented by state only");
    if (!env->kernel_mode_marker_present) {
        opaque_worker(s, env, 4);
        opaque_worker(s, env, 5);
    }
    ipc_plan(env, "MMXEUSAUL_", 0x400);
    if (!env->kernel_mode_marker_present) {
        opaque_worker(s, env, 6);
        effect(env, "SetWinEventHook callback pointer 0x008289b0 is opaque here");
    }
    if (env->native_system_is_64_bit) {
        ipc_plan(env, "MMXIME64_", 0x400);
        opaque_worker(s, env, 7);
        s->helper_launch_requested = true;
        effect(env, "original constructs wpk64.exe #3763; launch is disabled");
    }
    ipc_plan(env, "MMXIME32_", 0x800);
    opaque_worker(s, env, 8);
    s->timer_interval_ms = MAIN_TIMER_MS;
    effect(env, "SetTimer(window,1,1000,NULL) represented by timer interval only");
    if (!env->kernel_mode_marker_present) opaque_worker(s, env, 9);
}

/* Confirmed recorder lifecycle from FUN_00836f60/00836c00/00836860/00837490.
 * The original has sixteen 0x20-byte WAVEHDR allocations and data buffers,
 * prepares/adds each buffer, starts wave input, and writes a RIFF/WAVE stream.
 * No samples, files, device handles, or callback threads exist in this model. */
static void recorder_plan(const Environment *env)
{
    effect(env, "audio capability: 16 buffers; waveInOpen/PrepareHeader/AddBuffer");
    effect(env, "audio capability: RIFF WAVE / fmt / data; sdYYYY-MM-DD_HH-MM-SS.wav");
    effect(env, "audio stop path: waveInStop, waveInClose, header finalization/free");
}

/* Transport evidence combines concrete configuration and application strings.
 * SMTP/FTP/IMAP/Drive branches are capabilities, not proven exfiltration here.
 * Generic Chilkat strings are not treated as actor endpoints or C2 addresses. */
static void delivery_plan(const Environment *env, const ConfigView *config)
{
    effect(env, "delivery capability: application labels Email, IMAP Push, Drive, FTP");
    if (env->verbose && config->smtp_server[0])
        printf("MODEL: configured SMTP host=%s; secret=%s\n",
               config->smtp_server,
               config->smtp_secret_code_units ? "[PRESENT, REDACTED]" : "[EMPTY]");
    effect(env, "network delivery, archive construction and authentication are disabled");
}

/* FUN_00833e90: application main, after CRT initialization. */
static unsigned reconstructed_main(WpkState *s, const Environment *env)
{
    diagnostic_open(s, env);
    effect(env, "single-instance mutex _MPKON_TX_2 (not actually opened)");
    if (env->already_running) { s->exit_requested = true; return 0; }
    if (!prepare_storage(s, env)) { diagnostic_close(s, env); return 0; }
    effect(env, "check IMME64.dll / WPK64.exe presence on native x64 systems");
    effect(env, "registered message UWM_LLLBDN_MSG-44E531B1_14D3_11d5_A025_006067718D04");
    effect(env, "WSAStartup(0x0202) represented by an environment outcome");
    if (!env->winsock_startup_succeeds) { diagnostic_close(s, env); return 0; }
    if (!env->hidden_window_succeeds) { diagnostic_close(s, env); return 0; }
    s->window_created = true;
    effect(env, "register class, create window, set title WPK_WIND");
    if (!prepare_database(s, env)) { diagnostic_close(s, env); return 0; }
    monitoring_plan(s, env);
    s->gui_message_loop_entered = true;
    effect(env, "accelerator/message loop represented without a native queue");
    return 0;
}

/* Read-only explicit-file inspection; no discovery of application/system files. */
static int inspect_config(const char *path)
{
    FILE *f = fopen(path, "rb");
    unsigned char file[CONFIG_FILE_BYTES + 1];
    if (!f) { perror("configuration input"); return 1; }
    size_t n = fread(file, 1, sizeof file, f);
    bool io_error = ferror(f) != 0;
    fclose(f);
    ConfigView view;
    if (io_error || !parse_config(file, n, &view)) {
        memset(file, 0, sizeof file);
        fputs("Expected a 4572-byte subcfg file.\n", stderr);
        return 1;
    }
    printf("update_counter=%" PRIu32 "\n", view.update_counter);
    printf("mail_label=%s\nsmtp_server=%s\nsmtp_account=%s\n",
           view.mail_label, view.smtp_server, view.smtp_account);
    printf("smtp_secret=[REDACTED; %zu UTF-16 code units]\n",
           view.smtp_secret_code_units);
    printf("hotkey_modifiers=0x%x\nhotkey_virtual_key=0x%x\n",
           view.hotkey >> 16, view.hotkey & 0xffff);
    memset(file, 0, sizeof file);
    memset(&view, 0, sizeof view);
    return 0;
}

static Environment normal_environment(void)
{
    Environment e = {
        .log_folder_available = true, .config_present = true,
        .config_size_valid = true, .database_opens = true,
        .database_has_wlog = true, .database_has_rlog = true,
        .winsock_startup_succeeds = true, .hidden_window_succeeds = true,
        .native_system_is_64_bit = true, .verbose = false
    };
    return e;
}

static int self_test(void)
{
    ConfigView view;
    unsigned char b[CONFIG_FILE_BYTES] = {0};
    b[0] = 1;
    b[OFF_SMTP_SERVER] = 'm'; b[OFF_SMTP_SERVER + 2] = 'x';
    b[OFF_SMTP_SECRET] = 's';
    assert(!parse_config(b, sizeof b - 1, &view));
    assert(parse_config(b, sizeof b, &view));
    assert(view.update_counter == 1 && strcmp(view.smtp_server, "mx") == 0);
    assert(view.smtp_secret_code_units == 1);
    numeric_config_defaults(&view);
    assert(view.hotkey == DEFAULT_HOTKEY && view.words[0xe3] == 500);

    Environment e = normal_environment(); WpkState s = {0};
    reconstructed_main(&s, &e);
    assert(s.database_ready && s.helper_launch_requested && s.raw_keyboard_requested);
    assert(s.timer_interval_ms == 1000 && s.opaque_worker_requests == 10);

    s = (WpkState){0}; e.already_running = true;
    reconstructed_main(&s, &e);
    assert(s.exit_requested && !s.paths_prepared);

    s = (WpkState){0}; e = normal_environment(); e.bdel_marker_present = true;
    reconstructed_main(&s, &e);
    assert(s.exit_requested && !s.window_created);

    s = (WpkState){0}; e = normal_environment(); e.database_has_rlog = false;
    reconstructed_main(&s, &e);
    assert(!s.gui_message_loop_entered && !s.mouse_hook_requested);

    s = (WpkState){0}; e = normal_environment(); e.native_system_is_64_bit = false;
    reconstructed_main(&s, &e);
    assert(!s.helper_launch_requested);
    recorder_plan(&e); delivery_plan(&e, &view);
    puts("WPK semantic and passive-parser checks passed.");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) return self_test();
    if (argc == 3 && strcmp(argv[1], "--inspect-config") == 0)
        return inspect_config(argv[2]);
    Environment env = normal_environment(); WpkState state = {0};
    env.verbose = true;
    puts("Inert WPK semantic model. No native monitoring or delivery exists.");
    reconstructed_main(&state, &env);
    recorder_plan(&env);
    delivery_plan(&env, &state.configuration);
    return 0;
}
